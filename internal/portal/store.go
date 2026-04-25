package portal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionTTL = 30 * 24 * time.Hour
const emailCodeTTL = 10 * time.Minute

// DataStore defines the persistence surface for dashboard users and billing data.
type DataStore interface {
	CreateEmailCode(email, purpose string) (string, error)
	VerifyEmailCode(email, purpose, code string) error
	Register(email, password, name string) (PublicUser, string, error)
	Login(email, password string) (PublicUser, string, error)
	Logout(token string) error
	UserForToken(token string) (PublicUser, bool)
	CreateOrder(userID, planID string) (PublicOrder, error)
	ListOrders(userID string) []PublicOrder
	MarkOrderPaid(userID, orderID string) (PublicOrder, PublicUser, error)
}

// User is a registered dashboard account.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	PasswordHash string    `json:"password_hash"`
	BalanceCents int64     `json:"balance_cents"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// PublicUser is safe to return to browser clients.
type PublicUser struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	BalanceCents int64     `json:"balance_cents"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Session authenticates a browser client.
type Session struct {
	TokenHash string    `json:"token_hash"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Order records a recharge order.
type Order struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	PlanID      string    `json:"plan_id"`
	AmountCents int64     `json:"amount_cents"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	PaidAt      time.Time `json:"paid_at,omitempty"`
}

// EmailCode stores a short-lived verification code hash.
type EmailCode struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Purpose   string    `json:"purpose"`
	CodeHash  string    `json:"code_hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
}

// PublicOrder is safe to return to browser clients.
type PublicOrder struct {
	ID          string    `json:"id"`
	PlanID      string    `json:"plan_id"`
	AmountCents int64     `json:"amount_cents"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	PaidAt      time.Time `json:"paid_at,omitempty"`
}

// Plan describes a supported recharge package.
type Plan struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	AmountCents int64  `json:"amount_cents"`
	CreditCents int64  `json:"credit_cents"`
}

// Store persists dashboard users, sessions and recharge orders in a JSON file.
type Store struct {
	mu       sync.RWMutex
	path     string
	users    map[string]*User
	sessions map[string]*Session
	orders   map[string]*Order
	codes    map[string]*EmailCode
}

type diskState struct {
	Users    []*User      `json:"users"`
	Sessions []*Session   `json:"sessions"`
	Orders   []*Order     `json:"orders"`
	Codes    []*EmailCode `json:"codes"`
}

// DefaultPath returns the dashboard store path next to the active config file.
func DefaultPath(configFilePath string) string {
	base := strings.TrimSpace(configFilePath)
	if base == "" {
		base = "."
	}
	dir := filepath.Dir(base)
	if dir == "." || dir == "" {
		if wd, err := os.Getwd(); err == nil {
			dir = wd
		}
	}
	return filepath.Join(dir, "portal_store.json")
}

// DefaultPlans returns the built-in recharge packages.
func DefaultPlans() []Plan {
	return []Plan{
		{ID: "starter", Name: "入门包", AmountCents: 1000, CreditCents: 1000},
		{ID: "standard", Name: "标准包", AmountCents: 5000, CreditCents: 5200},
		{ID: "pro", Name: "专业包", AmountCents: 10000, CreditCents: 10800},
	}
}

// NewStore loads or creates the dashboard store.
func NewStore(path string) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("portal store path is required")
	}
	s := &Store{
		path:     path,
		users:    make(map[string]*User),
		sessions: make(map[string]*Session),
		orders:   make(map[string]*Order),
		codes:    make(map[string]*EmailCode),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// CreateEmailCode creates a short-lived code for registration or login.
func (s *Store) CreateEmailCode(email, purpose string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("portal store is nil")
	}
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
	record := &EmailCode{
		ID:        newID("code", email, purpose, now),
		Email:     email,
		Purpose:   purpose,
		CodeHash:  hashToken(email + ":" + purpose + ":" + code),
		CreatedAt: now,
		ExpiresAt: now.Add(emailCodeTTL),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.codes {
		if existing == nil || existing.Email != email || existing.Purpose != purpose || !existing.UsedAt.IsZero() {
			continue
		}
		delete(s.codes, id)
	}
	s.codes[record.ID] = record
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	return code, nil
}

// VerifyEmailCode validates and consumes an email code.
func (s *Store) VerifyEmailCode(email, purpose, code string) error {
	if s == nil {
		return fmt.Errorf("portal store is nil")
	}
	email = normalizeEmail(email)
	purpose = normalizePurpose(purpose)
	code = strings.TrimSpace(code)
	if email == "" || purpose == "" || code == "" {
		return fmt.Errorf("verification code is required")
	}
	expectedHash := hashToken(email + ":" + purpose + ":" + code)
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.codes {
		if record == nil || record.Email != email || record.Purpose != purpose || !record.UsedAt.IsZero() {
			continue
		}
		if now.After(record.ExpiresAt) {
			continue
		}
		if record.CodeHash != expectedHash {
			continue
		}
		record.UsedAt = now
		if err := s.saveLocked(); err != nil {
			return err
		}
		return nil
	}
	return os.ErrPermission
}

// Register creates a user account and a login session.
func (s *Store) Register(email, password, name string) (PublicUser, string, error) {
	if s == nil {
		return PublicUser{}, "", fmt.Errorf("portal store is nil")
	}
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
	now := time.Now().UTC()
	token, tokenHash, err := newToken()
	if err != nil {
		return PublicUser{}, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.findUserByEmailLocked(email) != nil {
		return PublicUser{}, "", fmt.Errorf("email already registered")
	}
	user := &User{
		ID:           newID("user", email, now),
		Email:        email,
		Name:         name,
		PasswordHash: string(passwordHash),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.users[user.ID] = user
	s.sessions[tokenHash] = &Session{TokenHash: tokenHash, UserID: user.ID, CreatedAt: now, ExpiresAt: now.Add(sessionTTL)}
	if err := s.saveLocked(); err != nil {
		return PublicUser{}, "", err
	}
	return publicUser(user), token, nil
}

// Login validates credentials and creates a new session.
func (s *Store) Login(email, password string) (PublicUser, string, error) {
	if s == nil {
		return PublicUser{}, "", fmt.Errorf("portal store is nil")
	}
	email = normalizeEmail(email)
	token, tokenHash, err := newToken()
	if err != nil {
		return PublicUser{}, "", err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	user := s.findUserByEmailLocked(email)
	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return PublicUser{}, "", os.ErrPermission
	}
	s.sessions[tokenHash] = &Session{TokenHash: tokenHash, UserID: user.ID, CreatedAt: now, ExpiresAt: now.Add(sessionTTL)}
	if err := s.saveLocked(); err != nil {
		return PublicUser{}, "", err
	}
	return publicUser(user), token, nil
}

// Logout removes a session token.
func (s *Store) Logout(token string) error {
	if s == nil {
		return nil
	}
	hash := hashToken(token)
	if hash == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, hash)
	return s.saveLocked()
}

// UserForToken resolves a bearer token to a user.
func (s *Store) UserForToken(token string) (PublicUser, bool) {
	if s == nil {
		return PublicUser{}, false
	}
	hash := hashToken(token)
	if hash == "" {
		return PublicUser{}, false
	}
	now := time.Now().UTC()
	s.mu.RLock()
	session := s.sessions[hash]
	if session == nil || now.After(session.ExpiresAt) {
		s.mu.RUnlock()
		return PublicUser{}, false
	}
	user := s.users[session.UserID]
	s.mu.RUnlock()
	if user == nil {
		return PublicUser{}, false
	}
	return publicUser(user), true
}

// CreateOrder creates a pending recharge order for a plan.
func (s *Store) CreateOrder(userID, planID string) (PublicOrder, error) {
	if s == nil {
		return PublicOrder{}, fmt.Errorf("portal store is nil")
	}
	plan, ok := findPlan(planID)
	if !ok {
		return PublicOrder{}, os.ErrNotExist
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users[userID] == nil {
		return PublicOrder{}, os.ErrNotExist
	}
	order := &Order{
		ID:          newID("order", userID, plan.ID, now),
		UserID:      userID,
		PlanID:      plan.ID,
		AmountCents: plan.AmountCents,
		Status:      "pending",
		CreatedAt:   now,
	}
	s.orders[order.ID] = order
	if err := s.saveLocked(); err != nil {
		return PublicOrder{}, err
	}
	return publicOrder(order), nil
}

// ListOrders returns a user's orders sorted newest first.
func (s *Store) ListOrders(userID string) []PublicOrder {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PublicOrder, 0)
	for _, order := range s.orders {
		if order == nil || order.UserID != userID {
			continue
		}
		out = append(out, publicOrder(order))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// MarkOrderPaid marks an order as paid and credits the user balance.
func (s *Store) MarkOrderPaid(userID, orderID string) (PublicOrder, PublicUser, error) {
	if s == nil {
		return PublicOrder{}, PublicUser{}, fmt.Errorf("portal store is nil")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	order := s.orders[strings.TrimSpace(orderID)]
	user := s.users[userID]
	if order == nil || user == nil || order.UserID != userID {
		return PublicOrder{}, PublicUser{}, os.ErrNotExist
	}
	if order.Status != "paid" {
		plan, ok := findPlan(order.PlanID)
		if !ok {
			return PublicOrder{}, PublicUser{}, os.ErrNotExist
		}
		order.Status = "paid"
		order.PaidAt = now
		user.BalanceCents += plan.CreditCents
		user.UpdatedAt = now
	}
	if err := s.saveLocked(); err != nil {
		return PublicOrder{}, PublicUser{}, err
	}
	return publicOrder(order), publicUser(user), nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read portal store: %w", err)
	}
	var state diskState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parse portal store: %w", err)
	}
	now := time.Now().UTC()
	for _, user := range state.Users {
		if user == nil || strings.TrimSpace(user.ID) == "" || normalizeEmail(user.Email) == "" {
			continue
		}
		user.Email = normalizeEmail(user.Email)
		s.users[user.ID] = user
	}
	for _, session := range state.Sessions {
		if session == nil || strings.TrimSpace(session.TokenHash) == "" || now.After(session.ExpiresAt) {
			continue
		}
		s.sessions[session.TokenHash] = session
	}
	for _, order := range state.Orders {
		if order == nil || strings.TrimSpace(order.ID) == "" {
			continue
		}
		s.orders[order.ID] = order
	}
	for _, code := range state.Codes {
		if code == nil || strings.TrimSpace(code.ID) == "" || now.After(code.ExpiresAt) || !code.UsedAt.IsZero() {
			continue
		}
		code.Email = normalizeEmail(code.Email)
		code.Purpose = normalizePurpose(code.Purpose)
		s.codes[code.ID] = code
	}
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create portal store directory: %w", err)
	}
	state := diskState{
		Users:    make([]*User, 0, len(s.users)),
		Sessions: make([]*Session, 0, len(s.sessions)),
		Orders:   make([]*Order, 0, len(s.orders)),
		Codes:    make([]*EmailCode, 0, len(s.codes)),
	}
	for _, user := range s.users {
		copyUser := *user
		state.Users = append(state.Users, &copyUser)
	}
	for _, session := range s.sessions {
		copySession := *session
		state.Sessions = append(state.Sessions, &copySession)
	}
	for _, order := range s.orders {
		copyOrder := *order
		state.Orders = append(state.Orders, &copyOrder)
	}
	now := time.Now().UTC()
	for _, code := range s.codes {
		if code == nil || now.After(code.ExpiresAt) || !code.UsedAt.IsZero() {
			continue
		}
		copyCode := *code
		state.Codes = append(state.Codes, &copyCode)
	}
	sort.Slice(state.Users, func(i, j int) bool { return state.Users[i].ID < state.Users[j].ID })
	sort.Slice(state.Sessions, func(i, j int) bool { return state.Sessions[i].TokenHash < state.Sessions[j].TokenHash })
	sort.Slice(state.Orders, func(i, j int) bool { return state.Orders[i].ID < state.Orders[j].ID })
	sort.Slice(state.Codes, func(i, j int) bool { return state.Codes[i].ID < state.Codes[j].ID })
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal portal store: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write portal store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace portal store: %w", err)
	}
	return nil
}

func (s *Store) findUserByEmailLocked(email string) *User {
	for _, user := range s.users {
		if user != nil && user.Email == email {
			return user
		}
	}
	return nil
}

func findPlan(planID string) (Plan, bool) {
	planID = strings.TrimSpace(planID)
	for _, plan := range DefaultPlans() {
		if plan.ID == planID {
			return plan, true
		}
	}
	return Plan{}, false
}

func publicUser(user *User) PublicUser {
	if user == nil {
		return PublicUser{}
	}
	return PublicUser{
		ID:           user.ID,
		Email:        user.Email,
		Name:         user.Name,
		BalanceCents: user.BalanceCents,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
}

func publicOrder(order *Order) PublicOrder {
	if order == nil {
		return PublicOrder{}
	}
	return PublicOrder{
		ID:          order.ID,
		PlanID:      order.PlanID,
		AmountCents: order.AmountCents,
		Status:      order.Status,
		CreatedAt:   order.CreatedAt,
		PaidAt:      order.PaidAt,
	}
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func normalizePurpose(purpose string) string {
	purpose = strings.ToLower(strings.TrimSpace(purpose))
	switch purpose {
	case "register", "login":
		return purpose
	default:
		return ""
	}
}

func normalizeName(name, email string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		return name
	}
	if at := strings.Index(email, "@"); at > 0 {
		return email[:at]
	}
	return "User"
}

func newToken() (string, string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", fmt.Errorf("generate session token: %w", err)
	}
	token := "gt_" + base64.RawURLEncoding.EncodeToString(raw[:])
	return token, hashToken(token), nil
}

func generateNumericCode() (string, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate email code: %w", err)
	}
	value := int(raw[0])<<24 | int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if value < 0 {
		value = -value
	}
	return fmt.Sprintf("%06d", value%1000000), nil
}

func hashToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newID(parts ...any) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = fmt.Fprintf(h, "%v:", part)
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err == nil {
		_, _ = h.Write(raw[:])
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}
