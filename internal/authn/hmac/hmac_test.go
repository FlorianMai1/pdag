package hmac

import (
	"errors"
	"testing"

	adminhmac "github.com/mai/pdag/internal/admin/hmac"
	"github.com/mai/pdag/internal/authn"
	"github.com/mai/pdag/internal/store"
)

func TestAuthenticate(t *testing.T) {
	svc := &HmacService{
		secretMap: map[string]string{"v1": "my-hmac-secret"},
	}

	plaintext := "pdg_abc123"
	hash := adminhmac.NewGenerator("v1", "my-hmac-secret").Hash(plaintext)

	rec := &store.KeyRecord{
		KeyHash:   hash,
		HmacKeyID: "v1",
	}

	if err := svc.Authenticate(plaintext, rec); err != nil {
		t.Errorf("Authenticate returned error for correct key: %v", err)
	}

	if err := svc.Authenticate("wrong-key", rec); !errors.Is(err, authn.ErrInvalidCredentials) {
		t.Errorf("Authenticate with wrong key: got %v, want ErrInvalidCredentials", err)
	}
}

func TestAuthenticateMissingHmacSecret(t *testing.T) {
	svc := &HmacService{
		secretMap: map[string]string{"v1": "my-hmac-secret"},
	}

	rec := &store.KeyRecord{
		KeyHash:   "abcd",
		HmacKeyID: "v99",
	}

	err := svc.Authenticate("anything", rec)
	if err == nil {
		t.Error("Authenticate should return error for missing HMAC secret")
	}
	if errors.Is(err, authn.ErrInvalidCredentials) {
		t.Error("missing HMAC secret should not be ErrInvalidCredentials")
	}
}

func TestAuthenticateInvalidHex(t *testing.T) {
	svc := &HmacService{
		secretMap: map[string]string{"v1": "secret"},
	}

	rec := &store.KeyRecord{
		KeyHash:   "not-hex!!",
		HmacKeyID: "v1",
	}

	err := svc.Authenticate("plain", rec)
	if err == nil {
		t.Fatal("Authenticate with invalid hex hash should return error")
	}
	if errors.Is(err, authn.ErrInvalidCredentials) {
		t.Error("corrupt hash should be internal error, not ErrInvalidCredentials")
	}
}

func TestAuthenticateWrongLengthHash(t *testing.T) {
	svc := &HmacService{
		secretMap: map[string]string{"v1": "secret"},
	}
	// Valid hex but not a 32-byte SHA-256 digest.
	rec := &store.KeyRecord{
		KeyHash:   "abcd",
		HmacKeyID: "v1",
	}

	err := svc.Authenticate("plain", rec)
	if !errors.Is(err, authn.ErrInvalidCredentials) {
		t.Errorf("short stored hash should be ErrInvalidCredentials, got %v", err)
	}
}
