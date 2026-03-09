package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/mai/pdag/internal/authn"
	"github.com/mai/pdag/internal/store"
)

type HmacService struct {
	secretMap map[string]string
}

// NewHmacService creates an authentication service from a map of HMAC key ID → secret.
func NewHmacService(secrets map[string]string) *HmacService {
	return &HmacService{
		secretMap: secrets,
	}
}

// Authenticate verifies the provided secret against the stored hash using
// the HMAC secret identified by the key record's HmacKeyID.
func (h *HmacService) Authenticate(secret string, rec *store.KeyRecord) error {
	hmacSecret, ok := h.secretMap[rec.HmacKeyID]
	if !ok {
		return fmt.Errorf("hmac secret %q not found", rec.HmacKeyID)
	}
	match, err := h.verify(secret, rec.KeyHash, hmacSecret)
	if err != nil {
		return fmt.Errorf("verify key hash: %w", err)
	}
	if !match {
		return authn.ErrInvalidCredentials
	}
	return nil
}

// verify uses constant-time comparison to prevent timing attacks.
func (h *HmacService) verify(providedApiKey string, storedHash string, hmacSecret string) (bool, error) {
	expected, err := hex.DecodeString(storedHash)
	if err != nil {
		return false, fmt.Errorf("decode stored hash: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write([]byte(providedApiKey))
	return hmac.Equal(mac.Sum(nil), expected), nil
}
