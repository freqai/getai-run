package userkeys

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
)

const (
	keyPrefix = "sk-getai-"
)

// KeyStore defines persistence for user-created downstream API keys.
type KeyStore interface {
	Create(name, group string, expiresAt time.Time) (PublicRecord, string, error)
	CreateForOwner(ownerID, name, group string, expiresAt time.Time) (PublicRecord, string, error)
	List() []PublicRecord
	ListByOwner(ownerID string) []PublicRecord
	Update(id string, update UpdateRequest) (PublicRecord, error)
	UpdateForOwner(ownerID, id string, update UpdateRequest) (PublicRecord, error)
	Delete(id string) error
	DeleteForOwner(ownerID, id string) error
	LookupKey(key string) (*Record, bool)
}

// Record describes one user-created downstream API key.
type Record struct {
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id,omitempty"`
	Name      string    `json:"name"`
	KeyHash   string    `json:"key_hash"`
	KeyPrefix string    `json:"key_prefix"`
	Group     string    `json:"group,omitempty"`
	Disabled  bool      `json:"disabled,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// PublicRecord is returned by management APIs without leaking the key hash.
type PublicRecord struct {
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id,omitempty"`
	Name      string    `json:"name"`
	KeyPrefix string    `json:"key_prefix"`
	Group     string    `json:"group,omitempty"`
	Disabled  bool      `json:"disabled,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Store persists user-created downstream API keys in a JSON file.
type Store struct {
	mu      sync.RWMutex
	path    string
	records map[string]*Record
}

// NewStore loads or creates a file-backed key store.
func NewStore(path string) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("user api key store path is required")
	}
	store := &Store{path: path, records: make(map[string]*Record)}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

// DefaultPath returns the default store path next to the active config file.
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
	return filepath.Join(dir, "user_api_keys.json")
}

// Create inserts a new API key record and returns the public record plus plaintext key.
func (s *Store) Create(name, group string, expiresAt time.Time) (PublicRecord, string, error) {
	return s.CreateForOwner("", name, group, expiresAt)
}

// CreateForOwner inserts a new API key record for an optional user owner.
func (s *Store) CreateForOwner(ownerID, name, group string, expiresAt time.Time) (PublicRecord, string, error) {
	if s == nil {
		return PublicRecord{}, "", fmt.Errorf("user api key store is nil")
	}
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
	s.mu.Lock()
	if s.records == nil {
		s.records = make(map[string]*Record)
	}
	s.records[record.ID] = record
	err = s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		return PublicRecord{}, "", err
	}
	return publicRecord(record), key, nil
}

// List returns all records sorted by creation time.
func (s *Store) List() []PublicRecord {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PublicRecord, 0, len(s.records))
	for _, record := range s.records {
		out = append(out, publicRecord(record))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// ListByOwner returns all records owned by the given user sorted by creation time.
func (s *Store) ListByOwner(ownerID string) []PublicRecord {
	if s == nil {
		return nil
	}
	ownerID = strings.TrimSpace(ownerID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PublicRecord, 0)
	for _, record := range s.records {
		if record == nil || strings.TrimSpace(record.OwnerID) != ownerID {
			continue
		}
		out = append(out, publicRecord(record))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// Update modifies mutable fields on a record.
func (s *Store) Update(id string, update UpdateRequest) (PublicRecord, error) {
	if s == nil {
		return PublicRecord{}, fmt.Errorf("user api key store is nil")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return PublicRecord{}, fmt.Errorf("id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.records[id]
	if record == nil {
		return PublicRecord{}, os.ErrNotExist
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
	if err := s.saveLocked(); err != nil {
		return PublicRecord{}, err
	}
	return publicRecord(record), nil
}

// UpdateForOwner modifies a record only when it belongs to the given owner.
func (s *Store) UpdateForOwner(ownerID, id string, update UpdateRequest) (PublicRecord, error) {
	if s == nil {
		return PublicRecord{}, fmt.Errorf("user api key store is nil")
	}
	ownerID = strings.TrimSpace(ownerID)
	id = strings.TrimSpace(id)
	if id == "" {
		return PublicRecord{}, fmt.Errorf("id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.records[id]
	if record == nil || strings.TrimSpace(record.OwnerID) != ownerID {
		return PublicRecord{}, os.ErrNotExist
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
	if err := s.saveLocked(); err != nil {
		return PublicRecord{}, err
	}
	return publicRecord(record), nil
}

// Delete removes a record by ID.
func (s *Store) Delete(id string) error {
	if s == nil {
		return fmt.Errorf("user api key store is nil")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records[id] == nil {
		return os.ErrNotExist
	}
	delete(s.records, id)
	return s.saveLocked()
}

// DeleteForOwner removes an owned record by ID.
func (s *Store) DeleteForOwner(ownerID, id string) error {
	if s == nil {
		return fmt.Errorf("user api key store is nil")
	}
	ownerID = strings.TrimSpace(ownerID)
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.records[id]
	if record == nil || strings.TrimSpace(record.OwnerID) != ownerID {
		return os.ErrNotExist
	}
	delete(s.records, id)
	return s.saveLocked()
}

// LookupKey validates a plaintext key and returns its record.
func (s *Store) LookupKey(key string) (*Record, bool) {
	if s == nil {
		return nil, false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, false
	}
	hashed := hashKey(key)
	now := time.Now().UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range s.records {
		if record == nil || record.Disabled || record.KeyHash != hashed {
			continue
		}
		if !record.ExpiresAt.IsZero() && now.After(record.ExpiresAt) {
			continue
		}
		return cloneRecord(record), true
	}
	return nil, false
}

// UpdateRequest contains optional mutable fields.
type UpdateRequest struct {
	Name      *string    `json:"name"`
	Group     *string    `json:"group"`
	Disabled  *bool      `json:"disabled"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read user api key store: %w", err)
	}
	var records []*Record
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("parse user api key store: %w", err)
	}
	for _, record := range records {
		if record == nil || strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.KeyHash) == "" {
			continue
		}
		record.ID = strings.TrimSpace(record.ID)
		record.Name = normalizeName(record.Name)
		record.Group = normalizeGroup(record.Group)
		s.records[record.ID] = record
	}
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create user api key store directory: %w", err)
	}
	records := make([]*Record, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, cloneRecord(record))
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal user api key store: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write user api key store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace user api key store: %w", err)
	}
	return nil
}

func generateKey() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate api key: %w", err)
	}
	return keyPrefix + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:])
}

func newID(key string) string {
	sum := sha256.Sum256([]byte("id:" + key))
	return hex.EncodeToString(sum[:8])
}

func prefixForDisplay(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 14 {
		return key
	}
	return key[:14]
}

func normalizeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "API Key"
	}
	return name
}

func normalizeGroup(group string) string {
	return strings.TrimSpace(group)
}

func publicRecord(record *Record) PublicRecord {
	if record == nil {
		return PublicRecord{}
	}
	return PublicRecord{
		ID:        record.ID,
		OwnerID:   record.OwnerID,
		Name:      record.Name,
		KeyPrefix: record.KeyPrefix,
		Group:     record.Group,
		Disabled:  record.Disabled,
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt,
		ExpiresAt: record.ExpiresAt,
	}
}

func cloneRecord(record *Record) *Record {
	if record == nil {
		return nil
	}
	copyRecord := *record
	return &copyRecord
}
