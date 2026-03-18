## Interface-at-boundary, implementation-in-subpackage
#### Tags: `packages` `interface` `boundary` `module` 

Every major internal component follows the same structure: the **parent package** defines the interface and any noop/test helpers; **subpackages** provide concrete implementations. The parent never imports its children. 

Implementations never directly depend upon root config, structs only hold the minimal needed information. 

When adding a new component, define the interface in the parent package first, then implement in a subpackage. 

Wiring happens in `cmd/pdag/serve.go`.

## Code Style
#### Tags: `style` `conventions` `logging` `errors`

- `slog` for all logging. No `fmt.Println` or `log.Println`.
- Errors are values — wrap with `%w`, handle explicitly, no panics.
- Handlers as `http.Handler` / `http.HandlerFunc`, composed with middleware chaining.
- Typed context keys (`type contextKey string`) for request-scoped values.
- Minimal dependencies — prefer stdlib. See `go.mod` for the full list.

## Pre-Commit tooling
#### Tags: `pre-commit` `commit` `contributing`

Run `make check` before every commit. It runs fix, fmt, vet, lint, and tests in sequence.

Before committing at least all unit tests should pass.
