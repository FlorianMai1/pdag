// Package file provides a file-based audit log publisher.
// Entries are buffered in a channel and flushed by a background goroutine,
// keeping the hot path lock-free.
package file

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/FlorianMai1/pdag/internal/audit"
	"github.com/FlorianMai1/pdag/internal/metrics"
)

// Compile-time interface checks.
var (
	_ audit.Publisher = (*Logger)(nil)
	_ audit.Reserver  = (*Logger)(nil)
)

const defaultBufferSize = 4096

// Logger writes structured JSON audit log entries to a dedicated file.
type Logger struct {
	fileMu sync.Mutex // guards file and enc
	file   *os.File
	enc    *json.Encoder
	path   string
	ch     chan audit.Entry
	sem    chan struct{} // counting semaphore for fail-closed reservations (cap == cap(ch))
	reopen chan struct{}
	stop   chan struct{} // signals flushLoop to drain and exit
	done   chan struct{} // closed when flushLoop has finished

	enqueueTimeout time.Duration // max time Publish/Reserve waits for buffer space (0 = non-blocking)

	pubMu     sync.RWMutex // held for read by Publish/Reserve, held for write by Close
	closed    bool
	closeOnce sync.Once
}

// NewLogger opens (or creates) the audit log file in append mode
// and starts the background flush goroutine.
// bufSize controls the entry channel capacity; if <= 0, defaultBufferSize is used.
// enqueueTimeout bounds how long Publish/Reserve blocks waiting for buffer space
// before dropping (Publish) or failing (Reserve); <= 0 means non-blocking.
func NewLogger(path string, bufSize int, enqueueTimeout time.Duration) (*Logger, error) {
	if bufSize <= 0 {
		bufSize = defaultBufferSize
	}
	l := &Logger{
		path:           path,
		ch:             make(chan audit.Entry, bufSize),
		sem:            make(chan struct{}, bufSize),
		reopen:         make(chan struct{}, 1),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
		enqueueTimeout: enqueueTimeout,
	}
	if err := l.open(); err != nil {
		return nil, err
	}
	go l.flushLoop()
	return l, nil
}

func (l *Logger) open() error {
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open audit log %q: %w", l.path, err)
	}
	l.setFile(f)
	return nil
}

// setFile installs f as the active file and builds a fresh encoder for it.
// Callers must hold fileMu (or be in single-threaded init).
func (l *Logger) setFile(f *os.File) {
	l.file = f
	l.enc = json.NewEncoder(f)
	l.enc.SetEscapeHTML(false)
}

// Publish enqueues an audit entry for async writing (best-effort / fail-open).
// It blocks up to enqueueTimeout waiting for buffer space to absorb transient
// back-pressure; if still full it drops the entry and returns an error. Used in
// the default (non-fail-closed) audit mode.
func (l *Logger) Publish(e audit.Entry) error {
	l.pubMu.RLock()
	defer l.pubMu.RUnlock()

	if l.closed {
		metrics.AuditDroppedTotal.Inc()
		metrics.AuditWriteErrorsTotal.Inc()
		return fmt.Errorf("audit log closed, entry dropped")
	}

	if l.enqueueTimeout <= 0 {
		// Non-blocking fast path.
		select {
		case l.ch <- e:
			return nil
		default:
			return l.dropFull()
		}
	}

	timer := time.NewTimer(l.enqueueTimeout)
	defer timer.Stop()
	select {
	case l.ch <- e:
		return nil
	case <-timer.C:
		return l.dropFull()
	}
}

func (l *Logger) dropFull() error {
	metrics.AuditDroppedTotal.Inc()
	metrics.AuditWriteErrorsTotal.Inc()
	return fmt.Errorf("audit log buffer full, entry dropped")
}

// Reserve acquires one buffer slot for fail-closed audit mode. It blocks up to
// enqueueTimeout (also bounded by ctx) for a free slot. On success the returned
// commit must be called exactly once with the final entry; the slot guarantees
// the entry can be enqueued without blocking. On saturation it returns ok=false
// so the caller can reject the request (503) before the upstream mutation runs.
func (l *Logger) Reserve(ctx context.Context) (func(audit.Entry), bool) {
	l.pubMu.RLock()
	defer l.pubMu.RUnlock()

	if l.closed {
		metrics.AuditDroppedTotal.Inc()
		return nil, false
	}

	acquire := func() bool {
		if l.enqueueTimeout <= 0 {
			select {
			case l.sem <- struct{}{}:
				return true
			default:
				return false
			}
		}
		timer := time.NewTimer(l.enqueueTimeout)
		defer timer.Stop()
		select {
		case l.sem <- struct{}{}:
			return true
		case <-timer.C:
			return false
		case <-ctx.Done():
			return false
		}
	}

	if !acquire() {
		metrics.AuditDroppedTotal.Inc()
		return nil, false
	}

	// Holding a permit guarantees a free channel slot (cap(sem) == cap(ch) and
	// flushLoop releases a permit only after draining an entry), so the commit
	// send never blocks.
	return func(e audit.Entry) {
		l.ch <- e
	}, true
}

// flushLoop drains the entry channel and writes to disk.
func (l *Logger) flushLoop() {
	defer close(l.done)
	for {
		select {
		case e := <-l.ch:
			l.writeAndRelease(e)
		case <-l.reopen:
			// Open the new file FIRST and only swap on success. If the open
			// fails (e.g. logrotate has not recreated the directory, disk
			// full), we keep writing to the previous file rather than nulling
			// the encoder — otherwise a single failed rotation would cause a
			// permanent, silent audit blackout until the next successful SIGHUP.
			l.fileMu.Lock()
			f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				slog.Error("reopen audit log failed, keeping previous file", "path", l.path, "error", err)
				metrics.AuditReopenFailuresTotal.Inc()
			} else {
				if l.file != nil {
					l.file.Close()
				}
				l.setFile(f)
			}
			l.fileMu.Unlock()
		case <-l.stop:
			// Drain remaining entries after stop signal.
			for {
				select {
				case e := <-l.ch:
					l.writeAndRelease(e)
				default:
					return
				}
			}
		}
	}
}

// writeAndRelease writes an entry and then releases one reservation permit (if
// the entry came through Reserve). The non-blocking receive is a no-op in
// default mode where no permits are ever held.
func (l *Logger) writeAndRelease(e audit.Entry) {
	l.writeEntry(e)
	select {
	case <-l.sem:
	default:
	}
	// Sample the queue depth from the single flushLoop goroutine, where len(ch)
	// is uncontended and meaningful (Publish callers race each other otherwise).
	metrics.AuditQueueDepth.Set(float64(len(l.ch)))
}

func (l *Logger) writeEntry(e audit.Entry) {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	if l.enc == nil {
		metrics.AuditWriteErrorsTotal.Inc()
		return
	}
	if err := l.enc.Encode(e); err != nil {
		slog.Error("audit log write failed", "request_id", e.RequestID, "error", err)
		metrics.AuditWriteErrorsTotal.Inc()
	}
}

// Reopen signals the background goroutine to close and reopen the file.
// Used on SIGHUP for log rotation.
func (l *Logger) Reopen() error {
	select {
	case l.reopen <- struct{}{}:
	default:
		// Already pending.
	}
	return nil
}

// Close stops accepting new entries, drains remaining buffered entries,
// and closes the file. Safe to call concurrently with Publish and idempotent.
func (l *Logger) Close() error {
	var err error
	l.closeOnce.Do(func() {
		// Prevent new Publish calls from sending on the channel.
		l.pubMu.Lock()
		l.closed = true
		l.pubMu.Unlock()

		// Signal flushLoop to drain and exit.
		close(l.stop)
		<-l.done

		l.fileMu.Lock()
		defer l.fileMu.Unlock()
		if l.file != nil {
			err = l.file.Close()
		}
	})
	return err
}
