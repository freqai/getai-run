package userkeys

import (
	"context"
	"net/http"
	"strings"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
)

const (
	// ProviderType is the access provider identifier for user-created API keys.
	ProviderType = "user-api-key"

	// MetadataKeyID is attached to sdk/access.Result.Metadata after successful auth.
	MetadataKeyID = "user_key_id"
	// MetadataKeyGroup scopes upstream account-pool selection.
	MetadataKeyGroup = "pool_group"
)

// Provider validates user-created API keys from the runtime key store.
type Provider struct {
	store *Store
}

// NewProvider constructs a user API key access provider.
func NewProvider(store *Store) *Provider {
	return &Provider{store: store}
}

func (p *Provider) Identifier() string {
	return ProviderType
}

func (p *Provider) Authenticate(_ context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	if p == nil || p.store == nil {
		return nil, sdkaccess.NewNotHandledError()
	}
	key := extractRequestKey(r)
	if key == "" {
		return nil, sdkaccess.NewNoCredentialsError()
	}
	record, ok := p.store.LookupKey(key)
	if !ok || record == nil {
		return nil, sdkaccess.NewInvalidCredentialError()
	}
	meta := map[string]string{
		MetadataKeyID: record.ID,
	}
	if group := strings.TrimSpace(record.Group); group != "" {
		meta[MetadataKeyGroup] = group
	}
	return &sdkaccess.Result{
		Provider:  p.Identifier(),
		Principal: record.ID,
		Metadata:  meta,
	}, nil
}

func extractRequestKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	candidates := []string{
		extractBearerToken(r.Header.Get("Authorization")),
		r.Header.Get("X-Api-Key"),
		r.Header.Get("X-Goog-Api-Key"),
	}
	if r.URL != nil {
		q := r.URL.Query()
		candidates = append(candidates, q.Get("key"), q.Get("auth_token"))
	}
	for _, candidate := range candidates {
		if key := strings.TrimSpace(candidate); key != "" {
			return key
		}
	}
	return ""
}

func extractBearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return header
	}
	if !strings.EqualFold(parts[0], "bearer") {
		return header
	}
	return strings.TrimSpace(parts[1])
}
