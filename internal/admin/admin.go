// Package admin provides the HTTP admin API for key management.
// It runs on its own dedicated port, protected by a static bearer token.
package admin

// KeyGenerator provides key ID generation, secret generation, and hashing.
// The HMAC secret used for hashing is injected at construction time.
type KeyGenerator interface {
	GenerateKeyID() (string, error)
	GenerateSecret() (string, error)
	Hash(plaintext string) string
	HmacKeyID() string
}
