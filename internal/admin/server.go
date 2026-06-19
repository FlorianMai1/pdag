package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/FlorianMai1/pdag/internal/metrics"
	"github.com/FlorianMai1/pdag/internal/ratelimit"
	"github.com/FlorianMai1/pdag/internal/ratelimit/token"
	"github.com/FlorianMai1/pdag/internal/store"
)

const adminMaxBodyBytes = 64 * 1024 // 64 KiB
const maxPrincipalLen = 256
const maxRoles = 64
const maxRoleLen = 128
const maxAllowedCIDRs = 256

// strictDecode decodes a single JSON object from the request body, rejecting
// unknown fields and trailing data so typo'd fields and malformed bodies fail
// loudly rather than being silently ignored.
func strictDecode(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("unexpected trailing data after JSON object")
	}
	return nil
}

// validateRoles trims and validates a requested role set: rejects empty/blank
// roles, caps the count and per-role length, and (when known is non-empty) warns
// about roles with no matching authz plugin to catch typos. Returns the trimmed
// roles on success.
func validateRoles(roles []string, known map[string]bool) ([]string, error) {
	if len(roles) == 0 {
		return nil, fmt.Errorf("at least one role is required")
	}
	if len(roles) > maxRoles {
		return nil, fmt.Errorf("too many roles (max %d)", maxRoles)
	}
	cleaned := make([]string, 0, len(roles))
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if role == "" {
			return nil, fmt.Errorf("roles must not be empty or blank")
		}
		if len(role) > maxRoleLen {
			return nil, fmt.Errorf("role exceeds maximum length of %d", maxRoleLen)
		}
		if len(known) > 0 && !known[role] {
			slog.Warn("key assigned a role with no matching authz plugin", "role", role)
		}
		cleaned = append(cleaned, role)
	}
	return cleaned, nil
}

// auditMutation records the audit event for a mutation that has ALREADY been
// applied to the store. On audit-write failure the mutation cannot be cleanly
// rolled back, so it flags the split-brain via a reconciliation log line and the
// audit_inconsistency_total metric and reports 500 to the caller. Returns false
// if auditing failed (caller should return immediately).
func auditMutation(w http.ResponseWriter, r *http.Request, mgr store.KeyManager, keyID, action string, oldValues, newValues any) bool {
	if err := mgr.AuditKeyEvent(r.Context(), keyID, action, "admin_api", oldValues, newValues); err != nil {
		metrics.AuditInconsistencyTotal.Inc()
		slog.Error("audit inconsistency: mutation applied but not audited",
			"action", action, "key_id", keyID, "error", err)
		http.Error(w, "audit logging failed", http.StatusInternalServerError)
		return false
	}
	return true
}

// NewServer returns an http.Server for the admin API on the given address.
// knownRoles is the set of roles backed by a configured authz plugin; it is used
// only to warn (not reject) when a key is assigned an unrecognized role.
func NewServer(addr string, mgr store.KeyManager, keygen KeyGenerator, adminToken string, knownRoles map[string]bool) *http.Server {
	rl := token.New(token.Config{Rate: 10, Burst: 50})
	handler := withRateLimit(rl, maxBodyBytes(adminMaxBodyBytes, Handler(mgr, keygen, adminToken, knownRoles)))
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
func Handler(mgr store.KeyManager, keygen KeyGenerator, adminToken string, knownRoles map[string]bool) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /admin/keys", withAuth(adminToken, createKey(mgr, keygen, knownRoles)))
	mux.HandleFunc("GET /admin/keys/{id}", withAuth(adminToken, getKey(mgr)))
	mux.HandleFunc("GET /admin/keys", withAuth(adminToken, listKeys(mgr)))
	mux.HandleFunc("DELETE /admin/keys/expired", withAuth(adminToken, purgeExpired(mgr)))
	mux.HandleFunc("DELETE /admin/keys/{id}", withAuth(adminToken, deleteKey(mgr)))
	mux.HandleFunc("PATCH /admin/keys/{id}/disable", withAuth(adminToken, setEnabled(mgr, false)))
	mux.HandleFunc("PATCH /admin/keys/{id}/enable", withAuth(adminToken, setEnabled(mgr, true)))
	mux.HandleFunc("PUT /admin/keys/{id}/roles", withAuth(adminToken, updateRoles(mgr, knownRoles)))
	mux.HandleFunc("POST /admin/keys/{id}/rotate", withAuth(adminToken, rotateKey(mgr, keygen)))
	mux.HandleFunc("PUT /admin/keys/{id}/allowed-cidrs", withAuth(adminToken, updateAllowedCIDRs(mgr)))
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
		// Error is unrecoverable: headers are already sent.
		_ = json.NewEncoder(w).Encode(keyResponse{
			ID:           rec.ID,
			Principal:    rec.Principal,
			Roles:        rec.Roles,
			AllowedCIDRs: rec.AllowedCIDRs,
			Enabled:      rec.Enabled,
			ExpiresAt:    rec.ExpiresAt,
			CreatedAt:    rec.CreatedAt,
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
			http.Error(w, "audit logging failed", http.StatusInternalServerError)
			return
		}
		slog.Info("purged expired keys", "count", n)
		w.Header().Set("Content-Type", "application/json")
		// Error is unrecoverable: headers are already sent.
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

func createKey(mgr store.KeyManager, keygen KeyGenerator, knownRoles map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createKeyRequest
		if err := strictDecode(r, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Principal == "" {
			http.Error(w, "principal is required", http.StatusBadRequest)
			return
		}
		if len(req.Principal) > maxPrincipalLen {
			http.Error(w, fmt.Sprintf("principal exceeds maximum length of %d", maxPrincipalLen), http.StatusBadRequest)
			return
		}
		roles, err := validateRoles(req.Roles, knownRoles)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Roles = roles

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
			if !t.After(time.Now()) {
				http.Error(w, "expires_at must be in the future", http.StatusBadRequest)
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
			// The key is live but unaudited and its secret is about to be lost.
			// Compensate by deleting the just-created key so we never leave an
			// unauditable orphan; only if that also fails is it a true split-brain.
			slog.Error("audit key create failed, deleting orphaned key", "key_id", keyID, "error", err)
			if delErr := mgr.Delete(r.Context(), keyID); delErr != nil {
				metrics.AuditInconsistencyTotal.Inc()
				slog.Error("audit inconsistency: could not delete unaudited key after create-audit failure",
					"key_id", keyID, "error", delErr)
			}
			http.Error(w, "audit logging failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		// Error is unrecoverable: headers are already sent.
		_ = json.NewEncoder(w).Encode(createKeyResponse{
			ID:        keyID,
			Secret:    secret,
			Principal: req.Principal,
			Roles:     req.Roles,
		})
	}
}

type keyResponse struct {
	ID           string     `json:"id"`
	Principal    string     `json:"principal"`
	Roles        []string   `json:"roles"`
	AllowedCIDRs []string   `json:"allowed_cidrs,omitempty"`
	Enabled      bool       `json:"enabled"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
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
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
				return
			}
			limit = n
		}
		if limit > maxLimit {
			limit = maxLimit
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				http.Error(w, "offset must be a non-negative integer", http.StatusBadRequest)
				return
			}
			offset = n
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
				ID:           k.ID,
				Principal:    k.Principal,
				Roles:        k.Roles,
				AllowedCIDRs: k.AllowedCIDRs,
				Enabled:      k.Enabled,
				ExpiresAt:    k.ExpiresAt,
				CreatedAt:    k.CreatedAt,
			}
		}

		w.Header().Set("Content-Type", "application/json")
		// Error is unrecoverable: headers are already sent.
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func deleteKey(mgr store.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := mgr.Delete(r.Context(), id); err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				http.Error(w, "key not found", http.StatusNotFound)
				return
			}
			slog.Error("delete key", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !auditMutation(w, r, mgr, id, "delete", nil, nil) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func setEnabled(mgr store.KeyManager, enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := mgr.SetEnabled(r.Context(), id, enabled); err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				http.Error(w, "key not found", http.StatusNotFound)
				return
			}
			slog.Error("set enabled", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		action := "disable"
		if enabled {
			action = "enable"
		}
		if !auditMutation(w, r, mgr, id, action, nil, map[string]any{"enabled": enabled}) {
			return
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
		if err := strictDecode(r, &req); err != nil {
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
			if !t.After(time.Now()) {
				http.Error(w, "expires_at must be in the future", http.StatusBadRequest)
				return
			}
			expiresAt = &t
		}

		if err := mgr.SetExpiresAt(r.Context(), id, expiresAt); err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				http.Error(w, "key not found", http.StatusNotFound)
				return
			}
			slog.Error("set expiry", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !auditMutation(w, r, mgr, id, "update_expiry", nil, map[string]any{"expires_at": expiresAt}) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type rotateKeyResponse struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

func rotateKey(mgr store.KeyManager, keygen KeyGenerator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		rec, err := mgr.GetByID(r.Context(), id)
		if err != nil {
			slog.Error("rotate key lookup", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if rec == nil {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}

		secret, err := keygen.GenerateSecret()
		if err != nil {
			slog.Error("generate secret for rotation", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		hash := keygen.Hash(secret)
		if err := mgr.UpdateHash(r.Context(), id, hash, keygen.HmacKeyID()); err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				http.Error(w, "key not found", http.StatusNotFound)
				return
			}
			slog.Error("rotate key", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Note: on audit failure the hash is already rotated and the new secret
		// is about to be lost — there is no clean rollback (the old hash is
		// gone), so auditMutation flags the inconsistency for reconciliation.
		if !auditMutation(w, r, mgr, id, "rotate",
			map[string]any{"hmac_key_id": rec.HmacKeyID},
			map[string]any{"hmac_key_id": keygen.HmacKeyID()}) {
			return
		}

		w.Header().Set("Content-Type", "application/json")
		// Error is unrecoverable: headers are already sent.
		_ = json.NewEncoder(w).Encode(rotateKeyResponse{
			ID:     id,
			Secret: secret,
		})
	}
}

type updateRolesRequest struct {
	Roles []string `json:"roles"`
}

func updateRoles(mgr store.KeyManager, knownRoles map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		var req updateRolesRequest
		if err := strictDecode(r, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		roles, err := validateRoles(req.Roles, knownRoles)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Roles = roles

		if err := mgr.SetRoles(r.Context(), id, req.Roles); err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				http.Error(w, "key not found", http.StatusNotFound)
				return
			}
			slog.Error("set roles", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !auditMutation(w, r, mgr, id, "update_roles", nil, map[string]any{"roles": req.Roles}) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type updateAllowedCIDRsRequest struct {
	AllowedCIDRs []string `json:"allowed_cidrs"`
}

func updateAllowedCIDRs(mgr store.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		var req updateAllowedCIDRsRequest
		if err := strictDecode(r, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		if len(req.AllowedCIDRs) > maxAllowedCIDRs {
			http.Error(w, fmt.Sprintf("too many allowed_cidrs (max %d)", maxAllowedCIDRs), http.StatusBadRequest)
			return
		}

		// Validate all CIDRs at the boundary.
		for _, cidr := range req.AllowedCIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				http.Error(w, fmt.Sprintf("invalid CIDR %q: %v", cidr, err), http.StatusBadRequest)
				return
			}
		}

		if err := mgr.SetAllowedCIDRs(r.Context(), id, req.AllowedCIDRs); err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				http.Error(w, "key not found", http.StatusNotFound)
				return
			}
			slog.Error("set allowed_cidrs", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !auditMutation(w, r, mgr, id, "update_allowed_cidrs", nil, map[string]any{"allowed_cidrs": req.AllowedCIDRs}) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
