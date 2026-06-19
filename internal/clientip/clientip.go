// Package clientip resolves the real client IP of an HTTP request, optionally
// honoring X-Forwarded-For when the immediate peer is a configured trusted proxy.
//
// PDAG is designed to run behind a reverse proxy (nginx/caddy) for TLS, so
// r.RemoteAddr is the proxy's address rather than the real client. Without
// trusted-proxy handling, per-key IP allowlists (allowed_cidrs) would be
// evaluated against the proxy and become a no-op security control. The resolver
// only trusts X-Forwarded-For when the peer itself is trusted, so a client
// cannot spoof its source IP by setting the header.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Resolver determines the client IP of a request given a set of trusted proxies.
type Resolver struct {
	trusted []*net.IPNet
}

// New builds a Resolver from a list of trusted proxy CIDRs. An empty list means
// no proxies are trusted: ClientIP always returns the immediate peer
// (r.RemoteAddr), ignoring X-Forwarded-For. Invalid CIDRs are rejected.
func New(trustedCIDRs []string) (*Resolver, error) {
	trusted := make([]*net.IPNet, 0, len(trustedCIDRs))
	for _, c := range trustedCIDRs {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies: invalid CIDR %q: %w", c, err)
		}
		trusted = append(trusted, ipNet)
	}
	return &Resolver{trusted: trusted}, nil
}

// ClientIP returns the resolved client IP, or nil if it cannot be parsed.
//
// If no trusted proxies are configured, or the immediate peer is not trusted,
// the peer IP (from r.RemoteAddr) is returned and X-Forwarded-For is ignored.
// If the peer is trusted, the X-Forwarded-For chain is walked right-to-left and
// the first address that is NOT a trusted proxy is returned as the real client;
// if every hop is trusted (or the header is absent/empty), the peer is returned.
func (r *Resolver) ClientIP(req *http.Request) net.IP {
	peer := peerIP(req.RemoteAddr)
	if peer == nil {
		return nil
	}
	if len(r.trusted) == 0 || !r.isTrusted(peer) {
		return peer
	}

	xff := req.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			// A malformed hop breaks the chain of trust; stop and return the
			// last known-good address (the peer) rather than guessing.
			return peer
		}
		if !r.isTrusted(ip) {
			return ip
		}
	}
	// Every hop was a trusted proxy.
	return peer
}

func (r *Resolver) isTrusted(ip net.IP) bool {
	for _, n := range r.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// peerIP extracts the IP from a "host:port" RemoteAddr.
func peerIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// RemoteAddr may occasionally lack a port (e.g. in tests); try raw.
		host = remoteAddr
	}
	return net.ParseIP(host)
}
