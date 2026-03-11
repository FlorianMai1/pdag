package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mai/pdag/internal/ratelimit"
	"github.com/mai/pdag/internal/ratelimit/token"
	"github.com/mai/pdag/internal/store"
)

const adminMaxBodyBytes = 64 * 1024 // 64 KiB

// NewServer returns an http.Server for the admin API on the given address.
func NewServer(addr string, mgr store.KeyManager, keygen KeyGenerator, adminToken string) *http.Server {
	rl := token.New(token.Config{Rate: 10, Burst: 50})
	handler := withRateLimit(rl, maxBodyBytes(adminMaxBodyBytes, Handler(mgr, keygen, adminToken)))
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// Handler returns an http.Handler for the admin API routes.
func Handler(mgr store.KeyManager, keygen KeyGenerator, adminToken string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /admin/keys", withAuth(adminToken, createKey(mgr, keygen)))
	mux.HandleFunc("GET /admin/keys/{id}", withAuth(adminToken, getKey(mgr)))
	mux.HandleFunc("GET /admin/keys", withAuth(adminToken, listKeys(mgr)))
	mux.HandleFunc("DELETE /admin/keys/expired", withAuth(adminToken, purgeExpired(mgr)))
	mux.HandleFunc("DELETE /admin/keys/{id}", withAuth(adminToken, deleteKey(mgr)))
	mux.HandleFunc("PATCH /admin/keys/{id}/disable", withAuth(adminToken, setEnabled(mgr, false)))
	mux.HandleFunc("PATCH /admin/keys/{id}/enable", withAuth(adminToken, setEnabled(mgr, true)))
	mux.HandleFunc("PUT /admin/keys/{id}/roles", withAuth(adminToken, updateRoles(mgr)))
	mux.HandleFunc("PATCH /admin/keys/{id}/expiry", withAuth(adminToken, setExpiry(mgr)))

	return mux
}

func maxBodyBytes(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}

func withRateLimit(rl ratelimit.RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		if !rl.Allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withAuth(token string, next http.HandlerFunc) http.HandlerFunc {
	// Precompute the HMAC of the expected token so we only hash once at init.
	tokenKey := []byte(token)
	tokenMAC := hmacHash([]byte(token), tokenKey)

	return func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			http.Error(w, "admin API not configured", http.StatusServiceUnavailable)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		got := strings.TrimPrefix(auth, "Bearer ")
		gotMAC := hmacHash([]byte(got), tokenKey)
		if subtle.ConstantTimeCompare(gotMAC, tokenMAC) != 1 {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func hmacHash(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func getKey(mgr store.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		rec, err := mgr.GetByID(r.Context(), id)
		if err != nil {
			slog.Error("get key", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if rec == nil {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keyResponse{
			ID:        rec.ID,
			Principal: rec.Principal,
			Roles:     rec.Roles,
			Enabled:   rec.Enabled,
			ExpiresAt: rec.ExpiresAt,
			CreatedAt: rec.CreatedAt,
		})
	}
}

func purgeExpired(mgr store.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n, err := mgr.DeleteExpired(r.Context(), time.Now())
		if err != nil {
			slog.Error("purge expired keys", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := mgr.AuditKeyEvent(r.Context(), "", "purge_expired", "admin_api", nil, map[string]any{
			"deleted": n,
		}); err != nil {
			slog.Error("audit purge expired", "error", err)
		}
		slog.Info("purged expired keys", "count", n)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{"deleted": n})
	}
}

type createKeyRequest struct {
	Principal string   `json:"principal"`
	Roles     []string `json:"roles"`
	ExpiresAt *string  `json:"expires_at,omitempty"` // RFC3339
}

type createKeyResponse struct {
	ID        string   `json:"id"`
	Secret    string   `json:"secret"`
	Principal string   `json:"principal"`
	Roles     []string `json:"roles"`
}

func createKey(mgr store.KeyManager, keygen KeyGenerator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Principal == "" {
			http.Error(w, "principal is required", http.StatusBadRequest)
			return
		}

		keyID, err := keygen.GenerateKeyID()
		if err != nil {
			slog.Error("generate key ID", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		secret, err := keygen.GenerateSecret()
		if err != nil {
			slog.Error("generate secret", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		hash := keygen.Hash(secret)

		rec := &store.KeyRecord{
			ID:        keyID,
			KeyHash:   hash,
			HmacKeyID: keygen.HmacKeyID(),
			Principal: req.Principal,
			Roles:     req.Roles,
			Enabled:   true,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}

		if req.ExpiresAt != nil {
			t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				http.Error(w, "invalid expires_at format (use RFC3339)", http.StatusBadRequest)
				return
			}
			rec.ExpiresAt = &t
		}

		if err := mgr.Create(r.Context(), rec); err != nil {
			slog.Error("create key", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := mgr.AuditKeyEvent(r.Context(), keyID, "create", "admin_api", nil, map[string]any{
			"principal": req.Principal,
			"roles":     req.Roles,
		}); err != nil {
			slog.Error("audit key create", "error", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(createKeyResponse{
			ID:        keyID,
			Secret:    secret,
			Principal: req.Principal,
			Roles:     req.Roles,
		})
	}
}

type keyResponse struct {
	ID        string     `json:"id"`
	Principal string     `json:"principal"`
	Roles     []string   `json:"roles"`
	Enabled   bool       `json:"enabled"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

const (
	defaultLimit = 100
	maxLimit     = 1000
)

func listKeys(mgr store.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := defaultLimit
		offset := 0

		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		if limit > maxLimit {
			limit = maxLimit
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}

		principal := r.URL.Query().Get("principal")
		role := r.URL.Query().Get("role")

		keys, err := mgr.ListFiltered(r.Context(), limit, offset, principal, role)
		if err != nil {
			slog.Error("list keys", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if keys == nil {
			keys = []*store.KeyRecord{}
		}

		resp := make([]keyResponse, len(keys))
		for i, k := range keys {
			resp[i] = keyResponse{
				ID:        k.ID,
				Principal: k.Principal,
				Roles:     k.Roles,
				Enabled:   k.Enabled,
				ExpiresAt: k.ExpiresAt,
				CreatedAt: k.CreatedAt,
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func deleteKey(mgr store.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := mgr.Delete(r.Context(), id); err != nil {
			slog.Error("delete key", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := mgr.AuditKeyEvent(r.Context(), id, "delete", "admin_api", nil, nil); err != nil {
			slog.Error("audit key delete", "error", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func setEnabled(mgr store.KeyManager, enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := mgr.SetEnabled(r.Context(), id, enabled); err != nil {
			slog.Error("set enabled", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		action := "disable"
		if enabled {
			action = "enable"
		}
		if err := mgr.AuditKeyEvent(r.Context(), id, action, "admin_api", nil, map[string]any{
			"enabled": enabled,
		}); err != nil {
			slog.Error("audit key "+action, "error", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type setExpiryRequest struct {
	ExpiresAt *string `json:"expires_at"` // RFC3339 or null to clear
}

func setExpiry(mgr store.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		var req setExpiryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		var expiresAt *time.Time
		if req.ExpiresAt != nil {
			t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				http.Error(w, "invalid expires_at format (use RFC3339)", http.StatusBadRequest)
				return
			}
			expiresAt = &t
		}

		if err := mgr.SetExpiresAt(r.Context(), id, expiresAt); err != nil {
			slog.Error("set expiry", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := mgr.AuditKeyEvent(r.Context(), id, "update_expiry", "admin_api", nil, map[string]any{
			"expires_at": expiresAt,
		}); err != nil {
			slog.Error("audit key update_expiry", "error", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type updateRolesRequest struct {
	Roles []string `json:"roles"`
}

func updateRoles(mgr store.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		var req updateRolesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		if err := mgr.SetRoles(r.Context(), id, req.Roles); err != nil {
			slog.Error("set roles", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := mgr.AuditKeyEvent(r.Context(), id, "update_roles", "admin_api", nil, map[string]any{
			"roles": req.Roles,
		}); err != nil {
			slog.Error("audit key update_roles", "error", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
