# github.com/FlorianMai1/pdag
# Requires: golangci-lint v1.64+ (https://golangci-lint.run/usage/install/)

GO       ?= go
GOFLAGS  ?= -trimpath
CGO      ?= 0

BIN_DIR    := bin
PDAG       := $(BIN_DIR)/pdag
PLUGIN_DIR := $(BIN_DIR)/plugins

# ── Version stamping ─────────────────────────────────────────────
# Derived from git; override VERSION on the command line for releases.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

PLUGINS    := admin read_zones zone_notify letsencrypt_dns_challenger api_discovery
PLUGIN_BINS := $(addprefix $(PLUGIN_DIR)/,$(PLUGINS))

# ── Primary targets ──────────────────────────────────────────────

.PHONY: all build plugins test lint fmt vet fix proto vuln check clean help

all: build plugins

build: $(PDAG)

plugins: $(PLUGIN_BINS)

test:
	CGO_ENABLED=1 $(GO) test -race -count=1 ./cmd/... ./internal/... ./sdk/...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	$(GO) vet ./...

fix:
	$(GO) fix ./...

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/authz/authz.proto

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

check: fix fmt vet lint test vuln

clean:
	rm -rf $(BIN_DIR)

# ── Binary rules ─────────────────────────────────────────────────

$(PDAG): $(shell find cmd internal proto sdk -name '*.go')
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $@ ./cmd/pdag

$(PLUGIN_DIR)/%: plugins/%/main.go $(shell find sdk -name '*.go' 2>/dev/null)
	@mkdir -p $(PLUGIN_DIR)
	CGO_ENABLED=$(CGO) $(GO) build $(GOFLAGS) -o $@ ./plugins/$*

# ── Convenience per-plugin targets ───────────────────────────────

.PHONY: $(PLUGINS)
$(PLUGINS): %: $(PLUGIN_DIR)/%

# ── Integration tests (requires Docker) ──────────────────────────

.PHONY: test-integration
test-integration:
	CGO_ENABLED=1 $(GO) test -race -count=1 -timeout 120s ./tests/...

# ── Help ─────────────────────────────────────────────────────────

help:
	@echo "Targets:"
	@echo "  all              Build pdag + all plugins (default)"
	@echo "  build            Build pdag binary"
	@echo "  plugins          Build all plugin binaries"
	@echo "  <plugin-name>    Build a single plugin ($(PLUGINS))"
	@echo "  test             Run unit tests with -race"
	@echo "  test-integration Run integration tests (needs Docker)"
	@echo "  lint             Run golangci-lint"
	@echo "  fmt              Format code with gofmt"
	@echo "  vet              Run go vet"
	@echo "  fix              Run go fix"
	@echo "  proto            Regenerate protobuf Go code"
	@echo "  vuln             Scan dependencies with govulncheck"
	@echo "  check            Run fix + fmt + vet + lint + test + vuln"
	@echo "  clean            Remove bin/"
