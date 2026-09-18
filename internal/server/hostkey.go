package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// LoadOrCreateHostKey returns the relay's Ed25519 host key, generating and
// persisting it on first boot (the only durable state, ARCHITECTURE §8).
func LoadOrCreateHostKey(dataDir string, log *slog.Logger) (ssh.Signer, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, "host_ed25519")
	if data, err := os.ReadFile(path); err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse host key %s: %w", path, err)
		}
		log.Info("loaded host key", "path", path, "fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))
		return signer, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read host key %s: %w", path, err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "relay host key")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("write host key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(pem.EncodeToMemory(block))
	if err != nil {
		return nil, fmt.Errorf("re-parse generated host key: %w", err)
	}
	log.Info("generated new host key", "path", path, "fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))
	return signer, nil
}
