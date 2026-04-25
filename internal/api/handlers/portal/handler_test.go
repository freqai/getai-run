package portal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/access/userkeys"
	portalstore "github.com/router-for-me/CLIProxyAPI/v6/internal/portal"
)

func TestPortalRegisterCreateAPIKeyAndAuthenticate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	userStore, err := portalstore.NewStore(filepath.Join(dir, "portal.json"))
	if err != nil {
		t.Fatalf("portal store: %v", err)
	}
	keyStore, err := userkeys.NewStore(filepath.Join(dir, "keys.json"))
	if err != nil {
		t.Fatalf("key store: %v", err)
	}
	handler := NewHandler(userStore, keyStore, nil)
	router := gin.New()
	group := router.Group("/v0/portal")
	group.POST("/register", handler.Register)
	authed := group.Group("")
	authed.Use(handler.AuthMiddleware())
	authed.POST("/api-keys", handler.CreateAPIKey)

	registerBody := map[string]string{
		"email":    "dev@example.com",
		"password": "password123",
		"name":     "Dev",
	}
	registerResp := performJSON(router, http.MethodPost, "/v0/portal/register", "", registerBody)
	if registerResp.Code != http.StatusCreated {
		t.Fatalf("register status = %d body=%s", registerResp.Code, registerResp.Body.String())
	}
	var registerData struct {
		Token string `json:"token"`
		User  struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(registerResp.Body.Bytes(), &registerData); err != nil {
		t.Fatalf("register json: %v", err)
	}
	if registerData.Token == "" || registerData.User.ID == "" {
		t.Fatalf("missing token or user id: %+v", registerData)
	}

	keyBody := map[string]string{"name": "Test Key", "group": "codex"}
	keyResp := performJSON(router, http.MethodPost, "/v0/portal/api-keys", registerData.Token, keyBody)
	if keyResp.Code != http.StatusCreated {
		t.Fatalf("create key status = %d body=%s", keyResp.Code, keyResp.Body.String())
	}
	var keyData struct {
		Key    string `json:"key"`
		APIKey struct {
			OwnerID string `json:"owner_id"`
			Group   string `json:"group"`
		} `json:"api_key"`
	}
	if err := json.Unmarshal(keyResp.Body.Bytes(), &keyData); err != nil {
		t.Fatalf("key json: %v", err)
	}
	if keyData.APIKey.OwnerID != registerData.User.ID {
		t.Fatalf("owner id = %q, want %q", keyData.APIKey.OwnerID, registerData.User.ID)
	}
	if keyData.APIKey.Group != "codex" {
		t.Fatalf("group = %q, want codex", keyData.APIKey.Group)
	}
	record, ok := keyStore.LookupKey(keyData.Key)
	if !ok {
		t.Fatal("created key did not authenticate")
	}
	if record.OwnerID != registerData.User.ID || record.Group != "codex" {
		t.Fatalf("record = %+v", record)
	}
}

func performJSON(router http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}
