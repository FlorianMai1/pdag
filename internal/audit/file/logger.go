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
	mu     sync.Mutex
	file   *os.File
	enc    *json.Encoder
	path   string
	ch     chan audit.Entry
	reopen chan struct{}
	done   chan struct{}
}

// NewLogger opens (or creates) the audit log file in append mode
// and starts the background flush goroutine.
func NewLogger(path string) (*Logger, error) {
	l := &Logger{
		path:   path,
		ch:     make(chan audit.Entry, defaultBufferSize),
		reopen: make(chan struct{}, 1),
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
// Returns an error only if the buffer is full (back-pressure).
func (l *Logger) Publish(e audit.Entry) error {
	select {
	case l.ch <- e:
		return nil
	default:
		metrics.AuditWriteErrorsTotal.Inc()
		return fmt.Errorf("audit log buffer full, entry dropped")
	}
}

// flushLoop drains the entry channel and writes to disk.
func (l *Logger) flushLoop() {
	defer close(l.done)
	for {
		select {
		case e, ok := <-l.ch:
			if !ok {
				return
			}
			l.mu.Lock()
			if err := l.enc.Encode(e); err != nil {
				slog.Error("audit log write failed", "request_id", e.RequestID, "error", err)
				metrics.AuditWriteErrorsTotal.Inc()
			}
			l.mu.Unlock()
		case <-l.reopen:
			l.mu.Lock()
			if l.file != nil {
				l.file.Close()
			}
			if err := l.open(); err != nil {
				slog.Error("reopen audit log failed", "error", err)
			}
			l.mu.Unlock()
		}
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

// Close drains remaining entries and closes the file.
func (l *Logger) Close() error {
	close(l.ch)
	<-l.done // wait for flush to finish
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
