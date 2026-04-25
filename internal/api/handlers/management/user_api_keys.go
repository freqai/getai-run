package management

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/access/userkeys"
)

// SetUserAPIKeyStore wires the user-created API key store into management APIs.
func (h *Handler) SetUserAPIKeyStore(store *userkeys.Store) {
	h.mu.Lock()
	h.userAPIKeyStore = store
	h.mu.Unlock()
}

// GetUserAPIKeys lists user-created API keys without secret material.
func (h *Handler) GetUserAPIKeys(c *gin.Context) {
	store := h.getUserAPIKeyStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user api key store unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_keys": store.List()})
}

// CreateUserAPIKey creates a new user API key. The plaintext key is returned once.
func (h *Handler) CreateUserAPIKey(c *gin.Context) {
	store := h.getUserAPIKeyStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user api key store unavailable"})
		return
	}
	var req struct {
		Name      string     `json:"name"`
		Group     string     `json:"group"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var expiresAt time.Time
	if req.ExpiresAt != nil {
		expiresAt = req.ExpiresAt.UTC()
	}
	record, key, err := store.Create(req.Name, req.Group, expiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"api_key": record, "key": key})
}

// PatchUserAPIKey updates mutable API key fields.
func (h *Handler) PatchUserAPIKey(c *gin.Context) {
	store := h.getUserAPIKeyStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user api key store unavailable"})
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	var req userkeys.UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	record, err := store.Update(id, req)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusNotFound, gin.H{"error": "api key not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"api_key": record})
}

// DeleteUserAPIKey deletes a user-created API key.
func (h *Handler) DeleteUserAPIKey(c *gin.Context) {
	store := h.getUserAPIKeyStore()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user api key store unavailable"})
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	if err := store.Delete(id); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusNotFound, gin.H{"error": "api key not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handler) getUserAPIKeyStore() *userkeys.Store {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.userAPIKeyStore
}
