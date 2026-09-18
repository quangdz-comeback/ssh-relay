// Package throttle provides per-connection, per-direction token-bucket
// Readers/Writers (bwlimit semantics: bytes per second, 0 = unlimited,
// burst = max(limit, 64 KiB) — ARCHITECTURE §7.3).
package throttle

import (
	"context"
	"io"

	"golang.org/x/time/rate"
)

const minBurst = 64 * 1024

// Limiter wraps a rate.Limiter; nil *Limiter means unlimited.
type Limiter struct {
	rl *rate.Limiter
}

// New builds a limiter for bytesPerSec; unlimited when <= 0.
func New(bytesPerSec int64) *Limiter {
	if bytesPerSec <= 0 {
		return nil
	}
	burst := int(bytesPerSec)
	if burst < minBurst {
		burst = minBurst
	}
	return &Limiter{rl: rate.NewLimiter(rate.Limit(bytesPerSec), burst)}
}

// Reader wraps r so reads consume tokens before data moves.
func (l *Limiter) Reader(ctx context.Context, r io.Reader) io.Reader {
	if l == nil {
		return r
	}
	return &throttledReader{ctx: ctx, r: r, l: l}
}

// Writer wraps w so writes consume tokens before data moves.
func (l *Limiter) Writer(ctx context.Context, w io.Writer) io.Writer {
	if l == nil {
		return w
	}
	return &throttledWriter{ctx: ctx, w: w, l: l}
}

type throttledReader struct {
	ctx context.Context
	r   io.Reader
	l   *Limiter
}

func (t *throttledReader) Read(p []byte) (int, error) {
	if len(p) > 1<<20 {
		p = p[:1<<20] // never wait for more than 1 MiB of tokens per chunk
	}
	if err := t.l.rl.WaitN(t.ctx, len(p)); err != nil {
		return 0, err
	}
	return t.r.Read(p)
}

type throttledWriter struct {
	ctx context.Context
	w   io.Writer
	l   *Limiter
}

func (t *throttledWriter) Write(p []byte) (int, error) {
	for total := 0; total < len(p); {
		chunk := len(p) - total
		if chunk > 1<<20 {
			chunk = 1 << 20
		}
		if err := t.l.rl.WaitN(t.ctx, chunk); err != nil {
			return total, err
		}
		n, err := t.w.Write(p[total : total+chunk])
		total += n
		if err != nil {
			return total, err
		}
	}
	return len(p), nil
}
