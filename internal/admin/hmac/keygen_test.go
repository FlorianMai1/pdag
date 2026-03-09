package hmac

import (
	"strings"
	"testing"
)

var keygen = NewGenerator("v1", "test-secret")

func TestGenerateKeyID(t *testing.T) {
	id, err := keygen.GenerateKeyID()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "k_") {
		t.Errorf("key ID %q should start with k_", id)
	}
	// k_ + 16 hex chars = 18
	if len(id) != 18 {
		t.Errorf("key ID length = %d, want 18", len(id))
	}
}

func TestGenerateSecret(t *testing.T) {
	s, err := keygen.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "pdg_") {
		t.Errorf("secret %q should start with pdg_", s)
	}
	// pdg_ + 64 hex chars = 68
	if len(s) != 68 {
		t.Errorf("secret length = %d, want 68", len(s))
	}
}

func TestGenerateUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, _ := keygen.GenerateSecret()
		if seen[s] {
			t.Fatalf("duplicate secret generated: %s", s)
		}
		seen[s] = true
	}
}

func TestHashDeterministic(t *testing.T) {
	h1 := keygen.Hash("p")
	h2 := keygen.Hash("p")
	if h1 != h2 {
		t.Errorf("Hash is not deterministic: %q != %q", h1, h2)
	}
}

func TestHmacKeyID(t *testing.T) {
	if keygen.HmacKeyID() != "v1" {
		t.Errorf("HmacKeyID = %q, want v1", keygen.HmacKeyID())
	}
}
