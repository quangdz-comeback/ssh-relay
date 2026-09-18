package policy

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherReloadKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	// Start with no file: flags-only operation.
	w, err := StartWatcher(path, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("StartWatcher without file: %v", err)
	}
	if got := w.Current().OverlayDefault(base()); got != base() {
		t.Fatalf("empty watcher changed base: %+v", got)
	}

	good := []byte(`{"default": {"max_sessions_per_ip": 9}}`)
	if err := os.WriteFile(path, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.ReloadNow(); err != nil {
		t.Fatalf("ReloadNow good: %v", err)
	}
	if got := w.Current().OverlayDefault(base()).MaxSessionsPerIP; got != 9 {
		t.Fatalf("max_sessions_per_ip = %d, want 9", got)
	}

	// Bad reload: error reported, last good policy kept.
	if err := os.WriteFile(path, []byte(`{"default": {"max_sessions_per_ip": 0}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.ReloadNow(); err == nil {
		t.Fatalf("ReloadNow bad file should error")
	}
	if got := w.Current().OverlayDefault(base()).MaxSessionsPerIP; got != 9 {
		t.Fatalf("last good policy lost: got %d, want 9", got)
	}

	// A subsequent good reload recovers.
	if err := os.WriteFile(path, []byte(`{"default": {"max_sessions_per_ip": 4}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := w.ReloadNow(); err == nil && w.Current().OverlayDefault(base()).MaxSessionsPerIP == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery reload did not take effect")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Invalid startup file is fatal for the caller (fail-closed).
	if _, err := StartWatcher(path2(t, `{"nope":1}`), slog.New(slog.NewTextHandler(os.Stderr, nil))); err == nil {
		t.Fatalf("invalid startup file must fail")
	}
}

func path2(t *testing.T, content string) string {
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
