package hmac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	adminhmac "github.com/mai/pdag/internal/admin/hmac"
	"github.com/mai/pdag/internal/middleware"
	"github.com/mai/pdag/internal/store"
	"github.com/mai/pdag/internal/store/memory"
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

			handler := middleware.RequestID(Middleware(s, cfg)(inner))
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
