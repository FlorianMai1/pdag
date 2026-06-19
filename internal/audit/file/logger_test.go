package file

import (
	"context"
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

	l, err := NewLogger(path, 0, 0)
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

	l, err := NewLogger(path, 0, 0)
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

	l, err := NewLogger(path, 0, 0)
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

// TestLoggerReserveCommit verifies the fail-closed happy path: a reserved entry
// is committed and written to the file.
func TestLoggerReserveCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := NewLogger(path, 4, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	commit, ok := l.Reserve(context.Background())
	if !ok {
		t.Fatal("Reserve should succeed when capacity is available")
	}
	commit(audit.Entry{RequestID: "reserved-1"})
	time.Sleep(50 * time.Millisecond)
	l.Close()

	got := readRequestIDs(t, path)
	if len(got) != 1 || got[0] != "reserved-1" {
		t.Errorf("got %v, want [reserved-1]", got)
	}
}

// TestLoggerReserveSaturated verifies that Reserve fails (ok=false) within the
// enqueue timeout when all buffer slots are held by uncommitted reservations —
// this is what drives the fail-closed 503.
func TestLoggerReserveSaturated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	const bufSize = 3
	l, err := NewLogger(path, bufSize, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Acquire every permit without committing, exhausting capacity.
	for i := range bufSize {
		if _, ok := l.Reserve(context.Background()); !ok {
			t.Fatalf("Reserve %d should succeed while capacity remains", i)
		}
	}

	start := time.Now()
	_, ok := l.Reserve(context.Background())
	elapsed := time.Since(start)

	if ok {
		t.Error("Reserve should fail when all slots are held")
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("Reserve returned after %v, expected it to block ~50ms (bounded) before failing", elapsed)
	}
}

func TestLoggerConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := NewLogger(path, 0, 0)
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

// TestLoggerReopenFailure verifies that a failed reopen (e.g. logrotate has not
// recreated the file/dir) does NOT cause a silent audit blackout: the logger
// keeps writing to the previously-open file, and a later successful reopen
// recovers cleanly. This guards the open-new-then-swap behavior.
func TestLoggerReopenFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test relies on file permissions to force a reopen failure; root bypasses them")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := NewLogger(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Write an entry so we know the logger works.
	l.Publish(audit.Entry{RequestID: "before-fail"})
	time.Sleep(50 * time.Millisecond)

	// Make the file read-only so OpenFile(O_WRONLY) fails on reopen, while the
	// already-open file descriptor inside the logger stays writable.
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}

	if err := l.Reopen(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	// Entries published during the failed-reopen window must NOT be lost — they
	// are written through the retained (old) file descriptor to the same file.
	l.Publish(audit.Entry{RequestID: "during-fail"})
	time.Sleep(50 * time.Millisecond)

	// Restore permissions and reopen again — should recover and keep appending.
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := l.Reopen(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	l.Publish(audit.Entry{RequestID: "recovered"})
	l.Close()

	got := readRequestIDs(t, path)
	want := []string{"before-fail", "during-fail", "recovered"}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %v, want %d %v (no blackout: nothing may be lost)", len(got), got, len(want), want)
	}
	for i, id := range want {
		if got[i] != id {
			t.Errorf("entry %d = %q, want %q", i, got[i], id)
		}
	}
}

// readRequestIDs reads a JSON-lines audit file and returns the RequestID of each entry.
func readRequestIDs(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	var ids []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		ids = append(ids, e.RequestID)
	}
	return ids
}

func TestLoggerCloseFlushes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l, err := NewLogger(path, 0, 0)
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
