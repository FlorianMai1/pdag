// Package httproute normalizes request paths to bounded-cardinality route
// templates, shared by the metrics and tracing middleware so attacker- or
// scanner-controlled paths cannot create unbounded label/span-name series.
package httproute

import "strings"

// OtherPath is the single label value all unrecognized paths fold into.
const OtherPath = "/other"

// knownFixedPaths are non-API endpoints served through the instrumented chain
// (probe chain + metrics) that are safe to keep verbatim.
var knownFixedPaths = map[string]bool{"healthz": true, "readyz": true, "metrics": true}

// zoneTailActions are bounded zone sub-resource verbs kept as literals.
var zoneTailActions = map[string]bool{"export": true, "notify": true, "axfr-retrieve": true, "rectify": true}

// Normalize maps a request path to a bounded-cardinality route template. Known
// PowerDNS templates have their dynamic segments masked (:server_id, :zone_id,
// :cryptokey_id, :kind); every unrecognized path folds into OtherPath.
//
//	/api/v1/servers/:server_id[/zones[/:zone_id[/export|notify|...
//	  |cryptokeys[/:cryptokey_id]|metadata[/:kind]]]]
func Normalize(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")

	// Remove empty trailing parts from trailing slashes.
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}

	if len(parts) == 0 {
		return "/"
	}
	if len(parts) == 1 && knownFixedPaths[parts[0]] {
		return "/" + parts[0]
	}

	// Everything else must be a PowerDNS API path; otherwise fold to /other.
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "servers" {
		return OtherPath
	}
	if len(parts) == 3 {
		return "/api/v1/servers"
	}

	parts[3] = ":server_id"
	if len(parts) == 4 {
		return "/" + strings.Join(parts, "/")
	}

	// Server-level sub-resource at index 4.
	if parts[4] != "zones" {
		// e.g. config, statistics, search-data — bounded literals. Anything
		// deeper than the sub-resource itself is unexpected → fold.
		if len(parts) == 5 {
			return "/" + strings.Join(parts, "/")
		}
		return OtherPath
	}

	if len(parts) == 5 {
		return "/" + strings.Join(parts, "/") // /api/v1/servers/:server_id/zones
	}
	parts[5] = ":zone_id"
	if len(parts) == 6 {
		return "/" + strings.Join(parts, "/") // .../zones/:zone_id
	}

	// Zone sub-resource tail at index 6 (and optional ID at index 7).
	switch tail := parts[6]; {
	case zoneTailActions[tail] && len(parts) == 7:
		return "/" + strings.Join(parts, "/")
	case tail == "cryptokeys":
		if len(parts) == 7 {
			return "/" + strings.Join(parts, "/")
		}
		if len(parts) == 8 {
			parts[7] = ":cryptokey_id"
			return "/" + strings.Join(parts, "/")
		}
		return OtherPath
	case tail == "metadata":
		if len(parts) == 7 {
			return "/" + strings.Join(parts, "/")
		}
		if len(parts) == 8 {
			parts[7] = ":kind"
			return "/" + strings.Join(parts, "/")
		}
		return OtherPath
	default:
		return OtherPath
	}
}
