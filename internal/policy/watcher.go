package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// Watcher holds the current PolicySet and hot-reloads it when the file
// changes (mtime/size poll + explicit ReloadNow for SIGHUP). A reload that
// fails validation keeps the last good set (ARCHITECTURE §6.3).
type Watcher struct {
	path string
	log  *slog.Logger

	current atomic.Pointer[PolicySet]
	ident   atomic.Value // string: sha256 of last good file (size+mtime is racy)
}

// EmptySet returns a valid set with no overrides (used when no file exists).
func EmptySet() *PolicySet {
	s, err := Parse([]byte("{}"))
	if err != nil {
		panic(err) // unreachable
	}
	return s
}

// Load initial loads the file if present and starts the poll loop.
// A missing file is fine (flags-only operation); an invalid file is fatal for
// startup — the caller decides by checking the returned error.
func StartWatcher(path string, log *slog.Logger) (*Watcher, error) {
	w := &Watcher{path: path, log: log}
	var initial *PolicySet
	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		initial = EmptySet()
		w.ident.Store("")
	case err != nil:
		return nil, err
	default:
		initial, err = Parse(data)
		if err != nil {
			return nil, err
		}
		w.ident.Store(fileIdentity(data))
	}
	w.current.Store(initial)

	go w.loop()
	return w, nil
}

// Current returns the latest good PolicySet.
func (w *Watcher) Current() *PolicySet { return w.current.Load() }

// ReloadNow forces a reload (SIGHUP path). It reports the validation error of
// a bad file while keeping the last good set in place.
func (w *Watcher) ReloadNow() error {
	data, err := os.ReadFile(w.path)
	if os.IsNotExist(err) {
		w.current.Store(EmptySet())
		w.ident.Store("")
		return nil
	}
	if err != nil {
		return err
	}
	id := fileIdentity(data)
	if id == w.ident.Load() {
		return nil // unchanged
	}
	set, err := Parse(data)
	if err != nil {
		w.log.Error("policy.json reload rejected, keeping last good policy", "path", w.path, "err", err)
		return err
	}
	w.ident.Store(id)
	w.current.Store(set)
	w.log.Info("policy.json reloaded", "path", w.path, "custom_policies", len(set.Custom))
	return nil
}

func (w *Watcher) loop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		if _, err := os.Stat(w.path); err != nil {
			continue // missing or unreadable: keep current
		}
		_ = w.ReloadNow()
	}
}

func fileIdentity(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
