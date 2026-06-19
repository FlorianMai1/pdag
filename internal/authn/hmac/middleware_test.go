package hmac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	adminhmac "github.com/FlorianMai1/pdag/internal/admin/hmac"
	"github.com/FlorianMai1/pdag/internal/clientip"
	"github.com/FlorianMai1/pdag/internal/middleware"
	"github.com/FlorianMai1/pdag/internal/store"
	"github.com/FlorianMai1/pdag/internal/store/memory"
)

func setupTest(t *testing.T) (*memory.Store, *HmacService) {
	t.Helper()

	hmac := &HmacService{
		secretMap: map[string]string{"v1": "test-hmac-secret"},
	}

	s := memory.NewStore()
	secret := "pdg_testsecret"
	hash := adminhmac.NewGenerator("v1", "test-hmac-secret").Hash(secret)

	s.Create(context.Background(), &store.KeyRecord{
		ID:        "k_valid",
		KeyHash:   hash,
		HmacKeyID: "v1",
		Principal: "alice",
		Roles:     []string{"admin"},
		Enabled:   true,
	})

	disabledHash := adminhmac.NewGenerator("v1", "test-hmac-secret").Hash("pdg_disabled")
	s.Create(context.Background(), &store.KeyRecord{
		ID:        "k_disabled",
		KeyHash:   disabledHash,
		HmacKeyID: "v1",
		Principal: "bob",
		Roles:     []string{"read_zones"},
		Enabled:   false,
	})

	expired := time.Now().Add(-1 * time.Hour)
	expiredHash := adminhmac.NewGenerator("v1", "test-hmac-secret").Hash("pdg_expired")
	s.Create(context.Background(), &store.KeyRecord{
		ID:        "k_expired",
		KeyHash:   expiredHash,
		HmacKeyID: "v1",
		Principal: "charlie",
		Roles:     []string{"read_zones"},
		Enabled:   true,
		ExpiresAt: &expired,
	})

	return s, hmac
}

func TestAuthnMiddleware(t *testing.T) {
	s, cfg := setupTest(t)

	tests := []struct {
		name          string
		apiKey        string
		wantStatus    int
		wantPrincipal string
	}{
		{
			name:       "missing header",
			apiKey:     "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "malformed - no colon",
			apiKey:     "justanid",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "malformed - empty id",
			apiKey:     ":secret",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "malformed - empty secret",
			apiKey:     "k_valid:",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unknown key ID",
			apiKey:     "k_unknown:pdg_testsecret",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong secret",
			apiKey:     "k_valid:pdg_wrongsecret",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "disabled key",
			apiKey:     "k_disabled:pdg_disabled",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "expired key",
			apiKey:     "k_expired:pdg_expired",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:          "valid key",
			apiKey:        "k_valid:pdg_testsecret",
			wantStatus:    http.StatusOK,
			wantPrincipal: "alice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPrincipal string
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPrincipal = middleware.GetPrincipal(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			resolver, _ := clientip.New(nil)
			handler := middleware.RequestID(Middleware(s, cfg, resolver)(inner))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.apiKey != "" {
				req.Header.Set("X-API-Key", tt.apiKey)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantPrincipal != "" && gotPrincipal != tt.wantPrincipal {
				t.Errorf("principal = %q, want %q", gotPrincipal, tt.wantPrincipal)
			}
		})
	}
}

// TestAuthnMiddlewareNoStateOracle verifies that unknown, disabled, expired, and
// bad-secret keys all return an IDENTICAL response (same status AND body), so an
// unauthenticated caller cannot distinguish key states (oracle hardening, #4).
func TestAuthnMiddlewareNoStateOracle(t *testing.T) {
	s, cfg := setupTest(t)
	resolver, _ := clientip.New(nil)
	handler := middleware.RequestID(Middleware(s, cfg, resolver)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))

	// Disabled/expired keys are probed WITHOUT the correct secret — pre-fix these
	// leaked "key disabled"/"key expired"; now they must look like any bad guess.
	apiKeys := []string{
		"k_unknown:pdg_whatever",
		"k_valid:pdg_wrongsecret",
		"k_disabled:pdg_wrongsecret",
		"k_expired:pdg_wrongsecret",
	}

	var bodies []string
	for _, ak := range apiKeys {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", ak)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", ak, rec.Code)
		}
		bodies = append(bodies, rec.Body.String())
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("response body differs between key states (oracle leak): %q vs %q", bodies[0], bodies[i])
		}
	}
}

// TestAuthnMiddlewareAllowlist verifies that the per-key allowed_cidrs check
// uses the trusted-proxy-aware client IP: behind a trusted proxy the real
// client (from X-Forwarded-For) is matched, while a spoofed XFF from an
// untrusted peer is ignored.
func TestAuthnMiddlewareAllowlist(t *testing.T) {
	s, cfg := setupTest(t)

	// A key restricted to clients in 203.0.113.0/24.
	hash := adminhmac.NewGenerator("v1", "test-hmac-secret").Hash("pdg_cidrsecret")
	s.Create(context.Background(), &store.KeyRecord{
		ID:           "k_cidr",
		KeyHash:      hash,
		HmacKeyID:    "v1",
		Principal:    "dave",
		Roles:        []string{"admin"},
		Enabled:      true,
		AllowedCIDRs: []string{"203.0.113.0/24"},
	})

	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		xff        string
		wantStatus int
	}{
		{
			name:       "direct client in allowlist",
			remoteAddr: "203.0.113.7:5555",
			wantStatus: http.StatusOK,
		},
		{
			name:       "direct client not in allowlist",
			remoteAddr: "198.51.100.9:5555",
			wantStatus: http.StatusUnauthorized, // uniform 401 (oracle hardening)
		},
		{
			name:       "trusted proxy forwards allowed client",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:5555",
			xff:        "203.0.113.7",
			wantStatus: http.StatusOK,
		},
		{
			name:       "trusted proxy forwards disallowed client",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:5555",
			xff:        "198.51.100.9",
			wantStatus: http.StatusUnauthorized, // uniform 401 (oracle hardening)
		},
		{
			name:       "untrusted peer cannot spoof XFF",
			trusted:    nil, // no trusted proxies → XFF ignored, peer used
			remoteAddr: "198.51.100.9:5555",
			xff:        "203.0.113.7",           // spoofed
			wantStatus: http.StatusUnauthorized, // uniform 401 (oracle hardening)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			resolver, err := clientip.New(tt.trusted)
			if err != nil {
				t.Fatal(err)
			}
			handler := middleware.RequestID(Middleware(s, cfg, resolver)(inner))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-API-Key", "k_cidr:pdg_cidrsecret")
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}
