// Package usage provides usage tracking and logging functionality for the CLI Proxy API server.
// This file implements PostgreSQL-based usage recording for persistent storage.
package usage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	coreusage "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/usage"
	log "github.com/sirupsen/logrus"
)

var (
	globalPostgresPlugin *PostgresUsagePlugin
	pgPluginOnce         sync.Once
)

func InitPostgresUsagePlugin() *PostgresUsagePlugin {
	pgPluginOnce.Do(func() {
		dsn := os.Getenv("USAGE_PG_DSN")
		if dsn == "" {
			dsn = os.Getenv("PGSTORE_DSN")
		}
		if dsn == "" {
			return
		}

		schema := os.Getenv("USAGE_PG_SCHEMA")
		if schema == "" {
			schema = os.Getenv("PGSTORE_SCHEMA")
		}

		plugin, err := NewPostgresUsagePlugin(dsn, schema)
		if err != nil {
			log.Errorf("usage: failed to initialize postgres plugin: %v", err)
			return
		}

		globalPostgresPlugin = plugin
		coreusage.RegisterPlugin(plugin)
		log.Info("usage: postgres plugin initialized, usage records will be saved to database")
	})
	return globalPostgresPlugin
}

func GlobalPostgresUsagePlugin() *PostgresUsagePlugin {
	return globalPostgresPlugin
}

type PostgresUsagePlugin struct {
	db     *sql.DB
	schema string
}

func NewPostgresUsagePlugin(dsn, schema string) (*PostgresUsagePlugin, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, fmt.Errorf("postgres usage plugin: DSN is required")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres usage plugin: open database: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres usage plugin: ping database: %w", err)
	}

	plugin := &PostgresUsagePlugin{
		db:     db,
		schema: strings.TrimSpace(schema),
	}

	if err = plugin.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres usage plugin: ensure schema: %w", err)
	}

	return plugin, nil
}

func (p *PostgresUsagePlugin) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	return p.db.Close()
}

func (p *PostgresUsagePlugin) HandleUsage(ctx context.Context, record coreusage.Record) {
	if p == nil || p.db == nil {
		return
	}

	requestedAt := record.RequestedAt
	if requestedAt.IsZero() {
		requestedAt = time.Now().UTC()
	}

	latencyMs := int64(0)
	if record.Latency > 0 {
		latencyMs = record.Latency.Milliseconds()
	}

	apiKey := record.APIKey
	if apiKey == "" {
		apiKey = "anonymous"
	}

	model := record.Model
	if model == "" {
		model = "unknown"
	}

	provider := record.Provider
	if provider == "" {
		provider = "unknown"
	}

	inputTokens := record.Detail.InputTokens
	outputTokens := record.Detail.OutputTokens
	reasoningTokens := record.Detail.ReasoningTokens
	cachedTokens := record.Detail.CachedTokens
	totalTokens := record.Detail.TotalTokens

	if totalTokens == 0 {
		totalTokens = inputTokens + outputTokens + reasoningTokens
	}
	if totalTokens == 0 {
		totalTokens = inputTokens + outputTokens + reasoningTokens + cachedTokens
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (
			id,
			api_key,
			model,
			provider,
			auth_id,
			auth_index,
			auth_type,
			source,
			requested_at,
			latency_ms,
			failed,
			input_tokens,
			output_tokens,
			reasoning_tokens,
			cached_tokens,
			total_tokens,
			created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW()
		)
	`, p.table("api_usage_logs"))

	id := generateUsageID()

	execCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := p.db.ExecContext(execCtx, query,
		id,
		apiKey,
		model,
		provider,
		record.AuthID,
		record.AuthIndex,
		record.AuthType,
		record.Source,
		requestedAt,
		latencyMs,
		record.Failed,
		inputTokens,
		outputTokens,
		reasoningTokens,
		cachedTokens,
		totalTokens,
	)

	if err != nil {
		log.Errorf("usage: failed to insert record to postgres: %v", err)
	}
}

func (p *PostgresUsagePlugin) ensureSchema(ctx context.Context) error {
	if p.schema != "" {
		query := fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", p.quoteIdentifier(p.schema))
		if _, err := p.db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
	}

	statements := []string{
		fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			api_key TEXT NOT NULL,
			model TEXT NOT NULL,
			provider TEXT NOT NULL,
			auth_id TEXT,
			auth_index TEXT,
			auth_type TEXT,
			source TEXT,
			requested_at TIMESTAMPTZ NOT NULL,
			latency_ms BIGINT NOT NULL DEFAULT 0,
			failed BOOLEAN NOT NULL DEFAULT FALSE,
			input_tokens BIGINT NOT NULL DEFAULT 0,
			output_tokens BIGINT NOT NULL DEFAULT 0,
			reasoning_tokens BIGINT NOT NULL DEFAULT 0,
			cached_tokens BIGINT NOT NULL DEFAULT 0,
			total_tokens BIGINT NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
		`, p.table("api_usage_logs")),

		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s (api_key, requested_at DESC)`,
			p.index("idx_api_usage_api_key_time"), p.table("api_usage_logs")),

		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s (model, requested_at DESC)`,
			p.index("idx_api_usage_model_time"), p.table("api_usage_logs")),

		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s (provider, requested_at DESC)`,
			p.index("idx_api_usage_provider_time"), p.table("api_usage_logs")),

		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s (requested_at DESC)`,
			p.index("idx_api_usage_requested_at"), p.table("api_usage_logs")),
	}

	for _, stmt := range statements {
		if _, err := p.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute statement: %w", err)
		}
	}

	return nil
}

func (p *PostgresUsagePlugin) table(name string) string {
	if p.schema == "" {
		return p.quoteIdentifier(name)
	}
	return p.quoteIdentifier(p.schema) + "." + p.quoteIdentifier(name)
}

func (p *PostgresUsagePlugin) index(name string) string {
	return p.quoteIdentifier(name)
}

func (p *PostgresUsagePlugin) quoteIdentifier(identifier string) string {
	replaced := strings.ReplaceAll(identifier, "\"", "\"\"")
	return "\"" + replaced + "\""
}

func generateUsageID() string {
	now := time.Now().UTC()
	return fmt.Sprintf("usage-%s-%09d",
		now.Format("20060102-150405"),
		now.Nanosecond())
}

type UsageLog struct {
	ID              string    `json:"id"`
	APIKey          string    `json:"api_key,omitempty"`
	APIKeyPrefix    string    `json:"api_key_prefix,omitempty"`
	Model           string    `json:"model"`
	Provider        string    `json:"provider"`
	AuthID          string    `json:"auth_id,omitempty"`
	AuthIndex       string    `json:"auth_index,omitempty"`
	AuthType        string    `json:"auth_type,omitempty"`
	Source          string    `json:"source,omitempty"`
	RequestedAt     time.Time `json:"requested_at"`
	LatencyMs       int64     `json:"latency_ms"`
	Failed          bool      `json:"failed"`
	InputTokens     int64     `json:"input_tokens"`
	OutputTokens    int64     `json:"output_tokens"`
	ReasoningTokens int64     `json:"reasoning_tokens"`
	CachedTokens    int64     `json:"cached_tokens"`
	TotalTokens     int64     `json:"total_tokens"`
	CreatedAt       time.Time `json:"created_at,omitempty"`
}

func (p *PostgresUsagePlugin) ListUsageLogsByKeyPrefixes(ctx context.Context, keyPrefixes []string, limit int) ([]UsageLog, error) {
	if p == nil || p.db == nil {
		return nil, fmt.Errorf("postgres usage plugin not initialized")
	}
	if len(keyPrefixes) == 0 {
		return []UsageLog{}, nil
	}
	limit = clampLimit(limit)

	query := fmt.Sprintf(`
		SELECT id, api_key, model, provider, auth_id, auth_index, auth_type, source, requested_at, latency_ms, failed, input_tokens, output_tokens, reasoning_tokens, cached_tokens, total_tokens, created_at
		FROM %s
		WHERE
	`, p.table("api_usage_logs"))

	conditions := make([]string, 0, len(keyPrefixes))
	args := make([]any, 0, len(keyPrefixes)+1)
	for i, prefix := range keyPrefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			continue
		}
		conditions = append(conditions, fmt.Sprintf("api_key LIKE $%d || '%%'", i+1))
		args = append(args, prefix)
	}
	if len(conditions) == 0 {
		return []UsageLog{}, nil
	}
	query += " " + strings.Join(conditions, " OR ")
	query += fmt.Sprintf(" ORDER BY requested_at DESC LIMIT $%d", len(args)+1)
	args = append(args, limit)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query usage logs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var logs []UsageLog
	for rows.Next() {
		log, scanErr := scanUsageLogRow(rows)
		if scanErr != nil {
			return logs, nil
		}
		logs = append(logs, log)
	}
	return logs, nil
}

func (p *PostgresUsagePlugin) ListUsageLogsAll(ctx context.Context, limit int) ([]UsageLog, error) {
	if p == nil || p.db == nil {
		return nil, fmt.Errorf("postgres usage plugin not initialized")
	}
	limit = clampLimit(limit)

	query := fmt.Sprintf(`
		SELECT id, api_key, model, provider, auth_id, auth_index, auth_type, source, requested_at, latency_ms, failed, input_tokens, output_tokens, reasoning_tokens, cached_tokens, total_tokens, created_at
		FROM %s
		ORDER BY requested_at DESC
		LIMIT $1
	`, p.table("api_usage_logs"))

	rows, err := p.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query all usage logs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var logs []UsageLog
	for rows.Next() {
		log, scanErr := scanUsageLogRow(rows)
		if scanErr != nil {
			return logs, nil
		}
		logs = append(logs, log)
	}
	return logs, nil
}

func scanUsageLogRow(rows *sql.Rows) (UsageLog, error) {
	var log UsageLog
	var apiKey sql.NullString
	var authID, authIndex, authType, source sql.NullString
	var createdAt sql.NullTime
	if err := rows.Scan(
		&log.ID,
		&apiKey,
		&log.Model,
		&log.Provider,
		&authID,
		&authIndex,
		&authType,
		&source,
		&log.RequestedAt,
		&log.LatencyMs,
		&log.Failed,
		&log.InputTokens,
		&log.OutputTokens,
		&log.ReasoningTokens,
		&log.CachedTokens,
		&log.TotalTokens,
		&createdAt,
	); err != nil {
		return log, err
	}
	if apiKey.Valid {
		log.APIKey = apiKey.String
		log.APIKeyPrefix = prefixForDisplay(apiKey.String)
	}
	if authID.Valid {
		log.AuthID = authID.String
	}
	if authIndex.Valid {
		log.AuthIndex = authIndex.String
	}
	if authType.Valid {
		log.AuthType = authType.String
	}
	if source.Valid {
		log.Source = source.String
	}
	if createdAt.Valid {
		log.CreatedAt = createdAt.Time
	}
	return log, nil
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 500 {
		return 500
	}
	return limit
}

func prefixForDisplay(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 14 {
		return key
	}
	return key[:14]
}
