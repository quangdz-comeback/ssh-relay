package throttle

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestUnlimitedPassthrough(t *testing.T) {
	l := New(0)
	if l != nil {
		t.Fatalf("New(0) must return nil (unlimited)")
	}
	var buf bytes.Buffer
	w := l.Writer(context.Background(), &buf)
	if _, err := io.Copy(w, bytes.NewReader(make([]byte, 1024))); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 1024 {
		t.Fatalf("wrote %d", buf.Len())
	}
}

func TestLimitThrottles(t *testing.T) {
	// 512 KiB/s with burst = 512 KiB: writing 1 MiB must spend ~0.5s+ in
	// WaitN after the burst is consumed. Loose bounds keep CI stable.
	l := New(512 * 1024)
	start := time.Now()
	n, err := io.Copy(io.Discard, l.Reader(context.Background(), bytes.NewReader(make([]byte, 1024*1024))))
	elapsed := time.Since(start)
	if err != nil || n != 1024*1024 {
		t.Fatalf("copy: n=%d err=%v", n, err)
	}
	if elapsed < 700*time.Millisecond {
		t.Fatalf("throttle did not engage: elapsed %v", elapsed)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("throttle too slow: elapsed %v", elapsed)
	}
}

func TestContextCancelsWait(t *testing.T) {
	l := New(64) // tiny limit: WaitN will be slow, so the cancel must rescue
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	type endless struct{}
	go func() { // keep the runtime happy; the reader below blocks in WaitN
		_ = endless{}
	}()
	start := time.Now()
	_, err := io.Copy(io.Discard, l.Reader(ctx, neverEnds{}))
	if err == nil {
		t.Fatalf("expected error after cancel")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("cancel did not unblock the reader in time")
	}
	_ = cancel
}

type neverEnds struct{}

func (neverEnds) Read(p []byte) (int, error) { return len(p), nil }
