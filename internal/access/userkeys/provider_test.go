package userkeys

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestProviderAuthenticatesStoredKeyWithGroup(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	record, key, err := store.Create("test", "claude-paid", zeroTime())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "/v1/models", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)

	result, authErr := NewProvider(store).Authenticate(req.Context(), req)
	if authErr != nil {
		t.Fatalf("Authenticate() authErr = %v", authErr)
	}
	if result.Principal != record.ID {
		t.Fatalf("Principal = %q, want %q", result.Principal, record.ID)
	}
	if got := result.Metadata[MetadataKeyGroup]; got != "claude-paid" {
		t.Fatalf("group metadata = %q, want claude-paid", got)
	}
}

func zeroTime() (z time.Time) { return z }
