// Package file provides a file-based audit log publisher.
// Entries are buffered in a channel and flushed by a background goroutine,
// keeping the hot path lock-free.
package file

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/mai/pdag/internal/audit"
	"github.com/mai/pdag/internal/metrics"
)

// Compile-time interface check.
var _ audit.Publisher = (*Logger)(nil)

const defaultBufferSize = 4096

// Logger writes structured JSON audit log entries to a dedicated file.
type Logger struct {
	fileMu sync.Mutex // guards file and enc
	file   *os.File
	enc    *json.Encoder
	path   string
	ch     chan audit.Entry
	reopen chan struct{}
	stop   chan struct{} // signals flushLoop to drain and exit
	done   chan struct{} // closed when flushLoop has finished

	pubMu    sync.RWMutex // held for read by Publish, held for write by Close
	closed   bool
	closeOnce sync.Once
}

// NewLogger opens (or creates) the audit log file in append mode
// and starts the background flush goroutine.
func NewLogger(path string) (*Logger, error) {
	l := &Logger{
		path:   path,
		ch:     make(chan audit.Entry, defaultBufferSize),
		reopen: make(chan struct{}, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
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
	l.file = f
	l.enc = json.NewEncoder(f)
	l.enc.SetEscapeHTML(false)
	return nil
}

// Publish enqueues an audit entry for async writing.
// Returns an error if the buffer is full (back-pressure) or the logger is closed.
func (l *Logger) Publish(e audit.Entry) error {
	l.pubMu.RLock()
	defer l.pubMu.RUnlock()

	if l.closed {
		metrics.AuditDroppedTotal.Inc()
		metrics.AuditWriteErrorsTotal.Inc()
		return fmt.Errorf("audit log closed, entry dropped")
	}
	metrics.AuditQueueDepth.Set(float64(len(l.ch)))
	select {
	case l.ch <- e:
		return nil
	default:
		metrics.AuditDroppedTotal.Inc()
		metrics.AuditWriteErrorsTotal.Inc()
		return fmt.Errorf("audit log buffer full, entry dropped")
	}
}

// flushLoop drains the entry channel and writes to disk.
func (l *Logger) flushLoop() {
	defer close(l.done)
	for {
		select {
		case e := <-l.ch:
			l.writeEntry(e)
		case <-l.reopen:
			l.fileMu.Lock()
			if l.file != nil {
				l.file.Close()
			}
			if err := l.open(); err != nil {
				slog.Error("reopen audit log failed", "error", err)
			}
			l.fileMu.Unlock()
		case <-l.stop:
			// Drain remaining entries after stop signal.
			for {
				select {
				case e := <-l.ch:
					l.writeEntry(e)
				default:
					return
				}
			}
		}
	}
}

func (l *Logger) writeEntry(e audit.Entry) {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
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
