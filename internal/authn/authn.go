package authn

import (
	"errors"

	"github.com/FlorianMai1/pdag/internal/store"
)

// ErrInvalidCredentials is returned when the provided API key does not match.
var ErrInvalidCredentials = errors.New("invalid credentials")

// Service authenticates an API key against a stored key record.
type Service interface {
	// Authenticate verifies that the provided secret matches the stored hash
	// for the given key record. Returns ErrInvalidCredentials on mismatch,
	// or another error for internal failures (e.g. missing HMAC secret).
	Authenticate(secret string, rec *store.KeyRecord) error

	// DummyVerify performs the same constant-work verification as Authenticate
	// but against a fixed decoy, discarding the result. It is called on the
	// unknown-key path so latency does not reveal whether a key ID exists.
	DummyVerify(secret string)
}
