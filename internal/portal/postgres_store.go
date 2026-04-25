package portal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

// PostgresStore persists dashboard users, sessions, codes and orders in PostgreSQL.
type PostgresStore struct {
	db     *sql.DB
	schema string
}

// NewPostgresStore connects to PostgreSQL and prepares portal tables.
func NewPostgresStore(ctx context.Context, dsn, schema string) (*PostgresStore, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, fmt.Errorf("portal postgres dsn is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open portal postgres: %w", err)
	}
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping portal postgres: %w", err)
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

// CreateEmailCode creates a short-lived code for registration or login.
func (s *PostgresStore) CreateEmailCode(email, purpose string) (string, error) {
	email = normalizeEmail(email)
	purpose = normalizePurpose(purpose)
	if email == "" {
		return "", fmt.Errorf("email is required")
	}
	if purpose == "" {
		return "", fmt.Errorf("purpose is required")
	}
	code, err := generateNumericCode()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin email code tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, fmt.Sprintf(`
		UPDATE %s
		SET used_at = NOW()
		WHERE email = $1 AND purpose = $2 AND used_at IS NULL
	`, s.table("portal_email_codes")), email, purpose); err != nil {
		return "", fmt.Errorf("expire previous email codes: %w", err)
	}
	if _, err = tx.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (id, email, purpose, code_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, s.table("portal_email_codes")),
		newID("code", email, purpose, now), email, purpose, hashToken(email+":"+purpose+":"+code), now, now.Add(emailCodeTTL)); err != nil {
		return "", fmt.Errorf("insert email code: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return "", fmt.Errorf("commit email code tx: %w", err)
	}
	return code, nil
}

// VerifyEmailCode validates and consumes an email code.
func (s *PostgresStore) VerifyEmailCode(email, purpose, code string) error {
	email = normalizeEmail(email)
	purpose = normalizePurpose(purpose)
	code = strings.TrimSpace(code)
	if email == "" || purpose == "" || code == "" {
		return fmt.Errorf("verification code is required")
	}
	res, err := s.db.ExecContext(context.Background(), fmt.Sprintf(`
		UPDATE %s
		SET used_at = NOW()
		WHERE id = (
			SELECT id FROM %s
			WHERE email = $1 AND purpose = $2 AND code_hash = $3 AND used_at IS NULL AND expires_at > NOW()
			ORDER BY created_at DESC
			LIMIT 1
		)
	`, s.table("portal_email_codes"), s.table("portal_email_codes")), email, purpose, hashToken(email+":"+purpose+":"+code))
	if err != nil {
		return fmt.Errorf("verify email code: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return os.ErrPermission
	}
	return nil
}

// Register creates a user account and a login session.
func (s *PostgresStore) Register(email, password, name string) (PublicUser, string, error) {
	email = normalizeEmail(email)
	name = normalizeName(name, email)
	if email == "" {
		return PublicUser{}, "", fmt.Errorf("email is required")
	}
	if len(password) < 8 {
		return PublicUser{}, "", fmt.Errorf("password must be at least 8 characters")
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return PublicUser{}, "", fmt.Errorf("hash password: %w", err)
	}
	token, tokenHash, err := newToken()
	if err != nil {
		return PublicUser{}, "", err
	}
	now := time.Now().UTC()
	user := User{ID: newID("user", email, now), Email: email, Name: name, PasswordHash: string(passwordHash), CreatedAt: now, UpdatedAt: now}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PublicUser{}, "", fmt.Errorf("begin register tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (id, email, name, password_hash, balance_cents, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 0, $5, $6)
	`, s.table("portal_users")), user.ID, user.Email, user.Name, user.PasswordHash, user.CreatedAt, user.UpdatedAt); err != nil {
		if isUniqueViolation(err) {
			return PublicUser{}, "", fmt.Errorf("email already registered")
		}
		return PublicUser{}, "", fmt.Errorf("insert user: %w", err)
	}
	if _, err = tx.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (token_hash, user_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4)
	`, s.table("portal_sessions")), tokenHash, user.ID, now, now.Add(sessionTTL)); err != nil {
		return PublicUser{}, "", fmt.Errorf("insert session: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return PublicUser{}, "", fmt.Errorf("commit register tx: %w", err)
	}
	return publicUser(&user), token, nil
}

// Login validates credentials and creates a new session.
func (s *PostgresStore) Login(email, password string) (PublicUser, string, error) {
	email = normalizeEmail(email)
	var user User
	if err := s.db.QueryRowContext(context.Background(), fmt.Sprintf(`
		SELECT id, email, name, password_hash, balance_cents, created_at, updated_at
		FROM %s WHERE email = $1
	`, s.table("portal_users")), email).Scan(&user.ID, &user.Email, &user.Name, &user.PasswordHash, &user.BalanceCents, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PublicUser{}, "", os.ErrPermission
		}
		return PublicUser{}, "", fmt.Errorf("load user: %w", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return PublicUser{}, "", os.ErrPermission
	}
	token, tokenHash, err := newToken()
	if err != nil {
		return PublicUser{}, "", err
	}
	now := time.Now().UTC()
	if _, err = s.db.ExecContext(context.Background(), fmt.Sprintf(`
		INSERT INTO %s (token_hash, user_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4)
	`, s.table("portal_sessions")), tokenHash, user.ID, now, now.Add(sessionTTL)); err != nil {
		return PublicUser{}, "", fmt.Errorf("insert session: %w", err)
	}
	return publicUser(&user), token, nil
}

// Logout removes a session token.
func (s *PostgresStore) Logout(token string) error {
	hash := hashToken(token)
	if hash == "" {
		return nil
	}
	_, err := s.db.ExecContext(context.Background(), fmt.Sprintf(`DELETE FROM %s WHERE token_hash = $1`, s.table("portal_sessions")), hash)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// UserForToken resolves a bearer token to a user.
func (s *PostgresStore) UserForToken(token string) (PublicUser, bool) {
	hash := hashToken(token)
	if hash == "" {
		return PublicUser{}, false
	}
	var user User
	err := s.db.QueryRowContext(context.Background(), fmt.Sprintf(`
		SELECT u.id, u.email, u.name, u.balance_cents, u.created_at, u.updated_at
		FROM %s u
		JOIN %s sess ON sess.user_id = u.id
		WHERE sess.token_hash = $1 AND sess.expires_at > NOW()
	`, s.table("portal_users"), s.table("portal_sessions")), hash).Scan(&user.ID, &user.Email, &user.Name, &user.BalanceCents, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return PublicUser{}, false
	}
	return publicUser(&user), true
}

// CreateOrder creates a pending recharge order for a plan.
func (s *PostgresStore) CreateOrder(userID, planID string) (PublicOrder, error) {
	plan, ok := findPlan(planID)
	if !ok {
		return PublicOrder{}, os.ErrNotExist
	}
	now := time.Now().UTC()
	order := Order{ID: newID("order", userID, plan.ID, now), UserID: userID, PlanID: plan.ID, AmountCents: plan.AmountCents, Status: "pending", CreatedAt: now}
	res, err := s.db.ExecContext(context.Background(), fmt.Sprintf(`
		INSERT INTO %s (id, user_id, plan_id, amount_cents, status, created_at)
		SELECT $1, $2, $3, $4, $5, $6
		WHERE EXISTS (SELECT 1 FROM %s WHERE id = $2)
	`, s.table("portal_orders"), s.table("portal_users")), order.ID, order.UserID, order.PlanID, order.AmountCents, order.Status, order.CreatedAt)
	if err != nil {
		return PublicOrder{}, fmt.Errorf("insert order: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return PublicOrder{}, os.ErrNotExist
	}
	return publicOrder(&order), nil
}

// ListOrders returns a user's orders sorted newest first.
func (s *PostgresStore) ListOrders(userID string) []PublicOrder {
	rows, err := s.db.QueryContext(context.Background(), fmt.Sprintf(`
		SELECT id, plan_id, amount_cents, status, created_at, paid_at
		FROM %s WHERE user_id = $1
		ORDER BY created_at DESC
	`, s.table("portal_orders")), strings.TrimSpace(userID))
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var out []PublicOrder
	for rows.Next() {
		var order Order
		var paidAt sql.NullTime
		if err = rows.Scan(&order.ID, &order.PlanID, &order.AmountCents, &order.Status, &order.CreatedAt, &paidAt); err != nil {
			return out
		}
		if paidAt.Valid {
			order.PaidAt = paidAt.Time
		}
		out = append(out, publicOrder(&order))
	}
	return out
}

// MarkOrderPaid marks an order as paid and credits the user balance.
func (s *PostgresStore) MarkOrderPaid(userID, orderID string) (PublicOrder, PublicUser, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PublicOrder{}, PublicUser{}, fmt.Errorf("begin pay tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var order Order
	var paidAt sql.NullTime
	err = tx.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT id, user_id, plan_id, amount_cents, status, created_at, paid_at
		FROM %s WHERE id = $1 AND user_id = $2
		FOR UPDATE
	`, s.table("portal_orders")), strings.TrimSpace(orderID), strings.TrimSpace(userID)).Scan(&order.ID, &order.UserID, &order.PlanID, &order.AmountCents, &order.Status, &order.CreatedAt, &paidAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PublicOrder{}, PublicUser{}, os.ErrNotExist
		}
		return PublicOrder{}, PublicUser{}, fmt.Errorf("load order: %w", err)
	}
	if paidAt.Valid {
		order.PaidAt = paidAt.Time
	}
	if order.Status != "paid" {
		plan, ok := findPlan(order.PlanID)
		if !ok {
			return PublicOrder{}, PublicUser{}, os.ErrNotExist
		}
		now := time.Now().UTC()
		if _, err = tx.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET status = 'paid', paid_at = $1 WHERE id = $2`, s.table("portal_orders")), now, order.ID); err != nil {
			return PublicOrder{}, PublicUser{}, fmt.Errorf("mark order paid: %w", err)
		}
		if _, err = tx.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET balance_cents = balance_cents + $1, updated_at = $2 WHERE id = $3`, s.table("portal_users")), plan.CreditCents, now, userID); err != nil {
			return PublicOrder{}, PublicUser{}, fmt.Errorf("credit user: %w", err)
		}
		order.Status = "paid"
		order.PaidAt = now
	}
	var user User
	if err = tx.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT id, email, name, balance_cents, created_at, updated_at
		FROM %s WHERE id = $1
	`, s.table("portal_users")), userID).Scan(&user.ID, &user.Email, &user.Name, &user.BalanceCents, &user.CreatedAt, &user.UpdatedAt); err != nil {
		return PublicOrder{}, PublicUser{}, fmt.Errorf("load user: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return PublicOrder{}, PublicUser{}, fmt.Errorf("commit pay tx: %w", err)
	}
	return publicOrder(&order), publicUser(&user), nil
}

func (s *PostgresStore) ensureSchema(ctx context.Context) error {
	if s.schema != "" {
		if _, err := s.db.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quoteIdentifier(s.schema))); err != nil {
			return fmt.Errorf("create portal schema: %w", err)
		}
	}
	statements := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			balance_cents BIGINT NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`, s.table("portal_users")),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			token_hash TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL
		)`, s.table("portal_sessions"), s.table("portal_users")),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			purpose TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ
		)`, s.table("portal_email_codes")),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s (email, purpose, created_at DESC)`, s.index("idx_portal_email_codes_lookup"), s.table("portal_email_codes")),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
			plan_id TEXT NOT NULL,
			amount_cents BIGINT NOT NULL,
			status TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			paid_at TIMESTAMPTZ
		)`, s.table("portal_orders"), s.table("portal_users")),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s (user_id, created_at DESC)`, s.index("idx_portal_orders_user"), s.table("portal_orders")),
	}
	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("ensure portal schema: %w", err)
		}
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
	return quoteIdentifier(name)
}
