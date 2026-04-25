package userkeys

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStore persists user-created API keys in PostgreSQL.
type PostgresStore struct {
	db     *sql.DB
	schema string
}

// NewPostgresStore connects to PostgreSQL and prepares API key tables.
func NewPostgresStore(ctx context.Context, dsn, schema string) (*PostgresStore, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, fmt.Errorf("user api key postgres dsn is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open user api key postgres: %w", err)
	}
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping user api key postgres: %w", err)
	}
	store := &PostgresStore{db: db, schema: strings.TrimSpace(schema)}
	if err = store.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close releases the database connection.
func (s *PostgresStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Create inserts a new API key record and returns the public record plus plaintext key.
func (s *PostgresStore) Create(name, group string, expiresAt time.Time) (PublicRecord, string, error) {
	return s.CreateForOwner("", name, group, expiresAt)
}

// CreateForOwner inserts a new API key record for an optional user owner.
func (s *PostgresStore) CreateForOwner(ownerID, name, group string, expiresAt time.Time) (PublicRecord, string, error) {
	key, err := generateKey()
	if err != nil {
		return PublicRecord{}, "", err
	}
	now := time.Now().UTC()
	record := &Record{
		ID:        newID(key),
		OwnerID:   strings.TrimSpace(ownerID),
		Name:      normalizeName(name),
		KeyHash:   hashKey(key),
		KeyPrefix: prefixForDisplay(key),
		Group:     normalizeGroup(group),
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: expiresAt.UTC(),
	}
	var expires any
	if !record.ExpiresAt.IsZero() {
		expires = record.ExpiresAt
	}
	if _, err = s.db.ExecContext(context.Background(), fmt.Sprintf(`
		INSERT INTO %s (id, owner_id, name, key_hash, key_prefix, pool_group, disabled, created_at, updated_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, false, $7, $8, $9)
	`, s.table("portal_api_keys")), record.ID, record.OwnerID, record.Name, record.KeyHash, record.KeyPrefix, record.Group, record.CreatedAt, record.UpdatedAt, expires); err != nil {
		return PublicRecord{}, "", fmt.Errorf("insert user api key: %w", err)
	}
	return publicRecord(record), key, nil
}

// List returns all records sorted by creation time.
func (s *PostgresStore) List() []PublicRecord {
	return s.list("")
}

// ListByOwner returns all records owned by the given user sorted by creation time.
func (s *PostgresStore) ListByOwner(ownerID string) []PublicRecord {
	return s.list(strings.TrimSpace(ownerID))
}

// Update modifies mutable fields on a record.
func (s *PostgresStore) Update(id string, update UpdateRequest) (PublicRecord, error) {
	return s.update("", id, update, false)
}

// UpdateForOwner modifies a record only when it belongs to the given owner.
func (s *PostgresStore) UpdateForOwner(ownerID, id string, update UpdateRequest) (PublicRecord, error) {
	return s.update(strings.TrimSpace(ownerID), id, update, true)
}

// Delete removes a record by ID.
func (s *PostgresStore) Delete(id string) error {
	return s.delete("", id, false)
}

// DeleteForOwner removes an owned record by ID.
func (s *PostgresStore) DeleteForOwner(ownerID, id string) error {
	return s.delete(strings.TrimSpace(ownerID), id, true)
}

// LookupKey validates a plaintext key and returns its record.
func (s *PostgresStore) LookupKey(key string) (*Record, bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, false
	}
	var record Record
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(context.Background(), fmt.Sprintf(`
		SELECT id, owner_id, name, key_hash, key_prefix, pool_group, disabled, created_at, updated_at, expires_at
		FROM %s
		WHERE key_hash = $1 AND disabled = false AND (expires_at IS NULL OR expires_at > NOW())
	`, s.table("portal_api_keys")), hashKey(key)).Scan(&record.ID, &record.OwnerID, &record.Name, &record.KeyHash, &record.KeyPrefix, &record.Group, &record.Disabled, &record.CreatedAt, &record.UpdatedAt, &expiresAt)
	if err != nil {
		return nil, false
	}
	if expiresAt.Valid {
		record.ExpiresAt = expiresAt.Time
	}
	return &record, true
}

func (s *PostgresStore) list(ownerID string) []PublicRecord {
	query := fmt.Sprintf(`
		SELECT id, owner_id, name, key_prefix, pool_group, disabled, created_at, updated_at, expires_at
		FROM %s
	`, s.table("portal_api_keys"))
	var args []any
	if ownerID != "" {
		query += " WHERE owner_id = $1"
		args = append(args, ownerID)
	}
	query += " ORDER BY created_at ASC, id ASC"
	rows, err := s.db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []PublicRecord
	for rows.Next() {
		var record PublicRecord
		var expiresAt sql.NullTime
		if err = rows.Scan(&record.ID, &record.OwnerID, &record.Name, &record.KeyPrefix, &record.Group, &record.Disabled, &record.CreatedAt, &record.UpdatedAt, &expiresAt); err != nil {
			return out
		}
		if expiresAt.Valid {
			record.ExpiresAt = expiresAt.Time
		}
		out = append(out, record)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (s *PostgresStore) update(ownerID, id string, update UpdateRequest, requireOwner bool) (PublicRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return PublicRecord{}, fmt.Errorf("id is required")
	}
	record, err := s.loadRecord(id, ownerID, requireOwner)
	if err != nil {
		return PublicRecord{}, err
	}
	if update.Name != nil {
		record.Name = normalizeName(*update.Name)
	}
	if update.Group != nil {
		record.Group = normalizeGroup(*update.Group)
	}
	if update.Disabled != nil {
		record.Disabled = *update.Disabled
	}
	if update.ExpiresAt != nil {
		record.ExpiresAt = update.ExpiresAt.UTC()
	}
	record.UpdatedAt = time.Now().UTC()
	var expires any
	if !record.ExpiresAt.IsZero() {
		expires = record.ExpiresAt
	}
	res, err := s.db.ExecContext(context.Background(), fmt.Sprintf(`
		UPDATE %s
		SET name = $1, pool_group = $2, disabled = $3, updated_at = $4, expires_at = $5
		WHERE id = $6
	`, s.table("portal_api_keys")), record.Name, record.Group, record.Disabled, record.UpdatedAt, expires, record.ID)
	if err != nil {
		return PublicRecord{}, fmt.Errorf("update user api key: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return PublicRecord{}, os.ErrNotExist
	}
	return publicRecord(record), nil
}

func (s *PostgresStore) delete(ownerID, id string, requireOwner bool) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("id is required")
	}
	query := fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, s.table("portal_api_keys"))
	args := []any{id}
	if requireOwner {
		query += " AND owner_id = $2"
		args = append(args, ownerID)
	}
	res, err := s.db.ExecContext(context.Background(), query, args...)
	if err != nil {
		return fmt.Errorf("delete user api key: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return os.ErrNotExist
	}
	return nil
}

func (s *PostgresStore) loadRecord(id, ownerID string, requireOwner bool) (*Record, error) {
	query := fmt.Sprintf(`
		SELECT id, owner_id, name, key_hash, key_prefix, pool_group, disabled, created_at, updated_at, expires_at
		FROM %s WHERE id = $1
	`, s.table("portal_api_keys"))
	args := []any{id}
	if requireOwner {
		query += " AND owner_id = $2"
		args = append(args, ownerID)
	}
	var record Record
	var expiresAt sql.NullTime
	err := s.db.QueryRowContext(context.Background(), query, args...).Scan(&record.ID, &record.OwnerID, &record.Name, &record.KeyHash, &record.KeyPrefix, &record.Group, &record.Disabled, &record.CreatedAt, &record.UpdatedAt, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("load user api key: %w", err)
	}
	if expiresAt.Valid {
		record.ExpiresAt = expiresAt.Time
	}
	return &record, nil
}

func (s *PostgresStore) ensureSchema(ctx context.Context) error {
	if s.schema != "" {
		if _, err := s.db.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quoteIdentifier(s.schema))); err != nil {
			return fmt.Errorf("create user api key schema: %w", err)
		}
	}
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			owner_id TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			key_prefix TEXT NOT NULL,
			pool_group TEXT NOT NULL DEFAULT '',
			disabled BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ
		)
	`, s.table("portal_api_keys"))); err != nil {
		return fmt.Errorf("create user api key table: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s (owner_id, created_at ASC)`, s.index("idx_portal_api_keys_owner"), s.table("portal_api_keys"))); err != nil {
		return fmt.Errorf("create user api key owner index: %w", err)
	}
	return nil
}

func (s *PostgresStore) table(name string) string {
	if s.schema == "" {
		return quoteIdentifier(name)
	}
	return quoteIdentifier(s.schema) + "." + quoteIdentifier(name)
}

func (s *PostgresStore) index(name string) string {
	if s.schema == "" {
		return quoteIdentifier(name)
	}
	return quoteIdentifier(s.schema) + "." + quoteIdentifier(name)
}

func quoteIdentifier(identifier string) string {
	parts := strings.Split(identifier, ".")
	for i, part := range parts {
		parts[i] = `"` + strings.ReplaceAll(part, `"`, `""`) + `"`
	}
	return strings.Join(parts, ".")
}
