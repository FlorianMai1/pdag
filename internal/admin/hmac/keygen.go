// Package hmac provides HMAC-SHA256-based key generation for PDAG's admin API.
package hmac

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/FlorianMai1/pdag/internal/admin"
)

// Compile-time interface check.
var _ admin.KeyGenerator = Generator{}

// Generator implements admin.KeyGenerator using HMAC-SHA256.
// The HMAC secret is injected at construction and used for all Hash calls.
type Generator struct {
	hmacKeyID  string
	hmacSecret string
}

// NewGenerator creates a Generator with the given HMAC key ID and secret.
func NewGenerator(hmacKeyID, hmacSecret string) Generator {
	return Generator{hmacKeyID: hmacKeyID, hmacSecret: hmacSecret}
}

// GenerateKeyID returns a key ID with prefix "k_" followed by 16 random hex chars.
func (Generator) GenerateKeyID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate key ID: %w", err)
	}
	return "k_" + hex.EncodeToString(b), nil
}

// GenerateSecret returns a secret with prefix "pdg_" followed by 64 random hex chars (32 bytes entropy).
func (Generator) GenerateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return "pdg_" + hex.EncodeToString(b), nil
}

// Hash computes HMAC-SHA256(secret, plaintext) and returns the hex-encoded result.
func (g Generator) Hash(plaintext string) string {
	mac := hmac.New(sha256.New, []byte(g.hmacSecret))
	mac.Write([]byte(plaintext))
	return hex.EncodeToString(mac.Sum(nil))
}

// HmacKeyID returns the ID of the HMAC secret used for hashing.
func (g Generator) HmacKeyID() string {
	return g.hmacKeyID
}
