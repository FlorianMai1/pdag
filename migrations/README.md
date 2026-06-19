# Migrations

PDAG uses [golang-migrate](https://github.com/golang-migrate/migrate) with
plain `database/sql`. Each migration is a pair of `NNN_name.up.sql` /
`NNN_name.down.sql` files applied in numeric order.

## Apply (automatic)

On startup with a Postgres store configured (`db.dsn` set), PDAG runs all
pending **up** migrations automatically before serving — see
`internal/store/postgres/postgres.go` (`runMigrations`). No manual step is
needed for a normal deploy; the binary ships the `migrations/` directory
alongside it (the Docker image copies it to `/opt/pdag/migrations`).

## Roll back (manual)

PDAG never applies **down** migrations itself. To roll back, run the
`migrate` CLI against the same DSN, e.g. to undo the most recent migration:

```sh
migrate -path ./migrations -database "$PDAG_DSN" down 1
```

Down files are provided for every migration so a release can be reverted, but
rolling back a column/table that newer code depends on will break that code —
roll back the binary first, then the schema.

## Add a migration

Create the next numbered pair (`004_*.up.sql` / `004_*.down.sql`). Keep up and
down symmetric, and prefer additive, backward-compatible changes so a new
schema works with the previously-deployed binary during a rolling deploy.
