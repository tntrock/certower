// Package store persists Certower's state in SQLite or PostgreSQL.
//
// Queries are written once with "?" placeholders and rewritten to "$n" for
// PostgreSQL. Lists and JSON documents are stored as JSON in both dialects.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Dialect is the SQL database flavor.
type Dialect string

const (
	SQLite   Dialect = "sqlite"
	Postgres Dialect = "postgres"
)

var (
	// ErrNotFound means the requested row does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict means a uniqueness constraint was violated.
	ErrConflict = errors.New("already exists")
	// ErrInvalidReference means a foreign key points at nothing.
	ErrInvalidReference = errors.New("invalid reference")
)

//go:embed migrations
var migrations embed.FS

type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Store is a handle to the database, or to one transaction on it.
type Store struct {
	db      *sql.DB
	q       querier
	dialect Dialect
}

// Open connects to a database. dsn is either
//
//	sqlite:<path>            e.g. sqlite:certower.db, sqlite::memory:
//	postgres://user:pass@host/db?sslmode=...
func Open(ctx context.Context, dsn string) (*Store, error) {
	var (
		db      *sql.DB
		dialect Dialect
		err     error
	)
	switch {
	case strings.HasPrefix(dsn, "sqlite:"):
		dialect = SQLite
		path := strings.TrimPrefix(dsn, "sqlite:")
		db, err = sql.Open("sqlite", path+sqlitePragmas(path))
		if err == nil && path == ":memory:" {
			// Each connection to :memory: is a separate database.
			db.SetMaxOpenConns(1)
		}
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		dialect = Postgres
		db, err = sql.Open("pgx", dsn)
	default:
		return nil, fmt.Errorf("store: unsupported dsn %q (want sqlite:<path> or postgres://...)", dsn)
	}
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, q: db, dialect: dialect}, nil
}

func sqlitePragmas(path string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	// _time_format=sqlite stores times as "2006-01-02 15:04:05.999999999-07:00".
	// All times are UTC, so they also compare correctly as text.
	p := sep + "_time_format=sqlite&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	if path != ":memory:" {
		p += "&_pragma=journal_mode(WAL)"
	}
	return p
}

// Dialect reports which database is in use.
func (s *Store) Dialect() Dialect { return s.dialect }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// InTx runs fn in a transaction. The Store passed to fn is bound to it.
func (s *Store) InTx(ctx context.Context, fn func(tx *Store) error) error {
	if _, ok := s.q.(*sql.Tx); ok {
		return fn(s) // already in a transaction
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(&Store{db: s.db, q: tx, dialect: s.dialect}); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Migrate applies pending migrations from migrations/<dialect>.
func (s *Store) Migrate(ctx context.Context) error {
	dir := "migrations/" + string(s.dialect)
	entries, err := fs.ReadDir(migrations, dir)
	if err != nil {
		return err
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL
	)`); err != nil {
		return err
	}
	for _, name := range files {
		var n int
		if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT count(*) FROM schema_migrations WHERE version = ?`), name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := migrations.ReadFile(dir + "/" + name)
		if err != nil {
			return err
		}
		err = s.InTx(ctx, func(tx *Store) error {
			// Both drivers accept multiple statements in one Exec call.
			if _, err := tx.q.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("migration %s: %w", name, err)
			}
			_, err := tx.exec(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, name, now())
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// rebind turns "?" placeholders into "$1", "$2", ... for PostgreSQL.
// Queries in this package never contain a literal "?".
func (s *Store) rebind(query string) string {
	if s.dialect != Postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Store) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	res, err := s.q.ExecContext(ctx, s.rebind(query), args...)
	return res, mapErr(err)
}

func (s *Store) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	rows, err := s.q.QueryContext(ctx, s.rebind(query), args...)
	return rows, mapErr(err)
}

func (s *Store) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return s.q.QueryRowContext(ctx, s.rebind(query), args...)
}

// execOne runs a statement that must affect exactly one row.
func (s *Store) execOne(ctx context.Context, query string, args ...any) error {
	res, err := s.exec(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return fmt.Errorf("%w: %v", ErrConflict, err)
		case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
			return fmt.Errorf("%w: %v", ErrInvalidReference, err)
		}
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505":
			return fmt.Errorf("%w: %v", ErrConflict, err)
		case "23503":
			return fmt.Errorf("%w: %v", ErrInvalidReference, err)
		}
	}
	return err
}

// newID returns a time-ordered UUIDv7 string.
func newID() string {
	return uuid.Must(uuid.NewV7()).String()
}

// now returns the current time truncated to microseconds, the precision
// both databases keep, so values round-trip exactly.
func now() time.Time {
	return time.Now().UTC().Truncate(time.Microsecond)
}

// nullable turns "" into NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// str dereferences a nullable string column.
func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
