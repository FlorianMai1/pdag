package file

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mai/pdag/internal/audit"
)

func TestLoggerWritesJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}

	entry := audit.Entry{
		Timestamp:  time.Now().UTC(),
		RequestID:  "req-1",
		Principal:  "alice",
		Method:     "GET",
		Path:       "/api/v1/servers",
		StatusCode: 200,
		LatencyMs:  5,
	}

	if err := l.Publish(entry); err != nil {
		t.Fatal(err)
	}

	// Close drains the buffer before closing the file.
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var got audit.Entry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid JSON: %s", err)
	}

	if got.RequestID != "req-1" {
		t.Errorf("request_id = %q, want %q", got.RequestID, "req-1")
	}
	if got.Principal != "alice" {
		t.Errorf("principal = %q, want %q", got.Principal, "alice")
	}
}

func TestLoggerReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}

	l.Publish(audit.Entry{RequestID: "before"})

	// Give the async flush a moment, then reopen.
	time.Sleep(50 * time.Millisecond)

	// Simulate logrotate: rename the file.
	rotated := path + ".1"
	os.Rename(path, rotated)

	// Reopen should create a new file.
	if err := l.Reopen(); err != nil {
		t.Fatal(err)
	}

	// Give reopen a moment to process.
	time.Sleep(50 * time.Millisecond)

	l.Publish(audit.Entry{RequestID: "after"})

	// Close drains the buffer.
	l.Close()

	// New file should only have "after".
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read new file: %v", err)
	}
	var got audit.Entry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid JSON in new file: %v", err)
	}
	if got.RequestID != "after" {
		t.Errorf("after reopen, request_id = %q, want %q", got.RequestID, "after")
	}

	// Rotated file should have "before".
	data, err = os.ReadFile(rotated)
	if err != nil {
		t.Fatalf("read rotated file: %v", err)
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid JSON in rotated file: %v", err)
	}
	if got.RequestID != "before" {
		t.Errorf("rotated file request_id = %q, want %q", got.RequestID, "before")
	}
}

func TestLoggerBufferFull(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}

	// Close the file to force write errors in the flush goroutine.
	l.fileMu.Lock()
	l.file.Close()
	l.file = nil
	l.fileMu.Unlock()

	// Flood the channel.
	var dropped int
	for range defaultBufferSize + 100 {
		if err := l.Publish(audit.Entry{RequestID: "flood"}); err != nil {
			dropped++
		}
	}

	// Re-open so Close doesn't panic.
	l.fileMu.Lock()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	l.file = f
	l.enc = json.NewEncoder(f)
	l.fileMu.Unlock()

	// We can't assert exact drop count (depends on goroutine scheduling),
	// but the test should not panic or deadlock.
	t.Logf("dropped %d entries out of %d", dropped, defaultBufferSize+100)
}

func TestLoggerConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}

	const writers = 10
	const entriesPerWriter = 100

	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range entriesPerWriter {
				l.Publish(audit.Entry{
					RequestID: "concurrent",
					Method:    "GET",
					Path:      "/test",
				})
			}
		}(i)
	}
	wg.Wait()
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	expected := writers * entriesPerWriter
	if len(lines) != expected {
		t.Errorf("got %d lines, want %d", len(lines), expected)
	}

	// Each line should be valid JSON.
	for i, line := range lines {
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Errorf("line %d is invalid JSON: %s", i, err)
		}
	}
}

func TestLoggerCloseFlushes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}

	for range 50 {
		l.Publish(audit.Entry{RequestID: "flush-test"})
	}

	// Close should drain all entries.
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 50 {
		t.Errorf("got %d lines, want 50", len(lines))
	}
}
