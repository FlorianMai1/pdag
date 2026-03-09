package authn

import (
	"errors"

	"github.com/mai/pdag/internal/store"
)

// ErrInvalidCredentials is returned when the provided API key does not match.
var ErrInvalidCredentials = errors.New("invalid credentials")

// Service authenticates an API key against a stored key record.
type Service interface {
	// Authenticate verifies that the provided secret matches the stored hash
	// for the given key record. Returns ErrInvalidCredentials on mismatch,
	// or another error for internal failures (e.g. missing HMAC secret).
	Authenticate(secret string, rec *store.KeyRecord) error
}
