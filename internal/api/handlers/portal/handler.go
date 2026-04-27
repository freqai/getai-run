package portal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/access/userkeys"
	portalstore "github.com/router-for-me/CLIProxyAPI/v6/internal/portal"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/usage"
)

const userContextKey = "portal_user"

// Handler serves user-facing dashboard APIs.
type Handler struct {
	store        portalstore.DataStore
	userKeyStore userkeys.KeyStore
	emailer      portalstore.EmailSender
}

// NewHandler creates a user portal API handler.
func NewHandler(store portalstore.DataStore, userKeyStore userkeys.KeyStore, emailer portalstore.EmailSender) *Handler {
	return &Handler{store: store, userKeyStore: userKeyStore, emailer: emailer}
}

// AuthMiddleware authenticates dashboard users by bearer session token.
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearerToken(c.GetHeader("Authorization"))
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing session token"})
			return
		}
		user, ok := h.store.UserForToken(token)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid session token"})
			return
		}
		c.Set(userContextKey, user)
		c.Next()
	}
}

// RequestAuthCode sends a registration or login verification code.
func (h *Handler) RequestAuthCode(c *gin.Context) {
	var req struct {
		Email   string `json:"email"`
		Purpose string `json:"purpose"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	code, err := h.store.CreateEmailCode(req.Email, req.Purpose)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.emailer == nil {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "code": code})
		return
	}
	if err := h.emailer.SendAuthCode(c.Request.Context(), req.Email, req.Purpose, code); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Register creates a dashboard account and returns a session token.
func (h *Handler) Register(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
		Code     string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.emailer != nil {
		if err := h.store.VerifyEmailCode(req.Email, "register", req.Code); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid verification code"})
			return
		}
	}
	user, token, err := h.store.Register(req.Email, req.Password, req.Name)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "already registered") {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"user": user, "token": token})
}

// Login validates credentials and returns a session token.
func (h *Handler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user, token, err := h.store.Login(req.Email, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user, "token": token})
}

// ResetPassword resets the user's password using an email verification code.
func (h *Handler) ResetPassword(c *gin.Context) {
	var req struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user, token, err := h.store.ResetPassword(req.Email, req.Code, req.NewPassword)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "at least 8 characters") {
			status = http.StatusBadRequest
		} else if strings.Contains(err.Error(), "verification code") {
			status = http.StatusUnauthorized
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user, "token": token})
}

// Logout removes the current session.
func (h *Handler) Logout(c *gin.Context) {
	_ = h.store.Logout(bearerToken(c.GetHeader("Authorization")))
	c.Status(http.StatusNoContent)
}

// Me returns the current user profile.
func (h *Handler) Me(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"user": currentUser(c)})
}

// Plans lists recharge packages.
func (h *Handler) Plans(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"plans": portalstore.DefaultPlans()})
}

// ListAPIKeys lists API keys owned by the current user.
func (h *Handler) ListAPIKeys(c *gin.Context) {
	user := currentUser(c)
	c.JSON(http.StatusOK, gin.H{"api_keys": h.userKeyStore.ListByOwner(user.ID)})
}

// CreateAPIKey creates an API key owned by the current user.
func (h *Handler) CreateAPIKey(c *gin.Context) {
	user := currentUser(c)
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
	record, key, err := h.userKeyStore.CreateForOwner(user.ID, req.Name, req.Group, expiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"api_key": record, "key": key})
}

// PatchAPIKey updates an owned API key.
func (h *Handler) PatchAPIKey(c *gin.Context) {
	user := currentUser(c)
	var req userkeys.UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	record, err := h.userKeyStore.UpdateForOwner(user.ID, c.Param("id"), req)
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

// DeleteAPIKey deletes an owned API key.
func (h *Handler) DeleteAPIKey(c *gin.Context) {
	user := currentUser(c)
	if err := h.userKeyStore.DeleteForOwner(user.ID, c.Param("id")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusNotFound, gin.H{"error": "api key not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// ListOrders lists recharge orders for the current user.
func (h *Handler) ListOrders(c *gin.Context) {
	user := currentUser(c)
	c.JSON(http.StatusOK, gin.H{"orders": h.store.ListOrders(user.ID)})
}

// CreateOrder creates a pending recharge order.
func (h *Handler) CreateOrder(c *gin.Context) {
	user := currentUser(c)
	var req struct {
		PlanID string `json:"plan_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	order, err := h.store.CreateOrder(user.ID, req.PlanID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown recharge plan"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"order": order})
}

// MockPayOrder marks an order paid. Replace this with a payment provider webhook in production.
func (h *Handler) MockPayOrder(c *gin.Context) {
	user := currentUser(c)
	order, updatedUser, err := h.store.MarkOrderPaid(user.ID, c.Param("id"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusNotFound, gin.H{"error": "order not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"order": order, "user": updatedUser})
}

// ListUsageLogs returns API usage logs.
// By default, it shows ALL usage records (for development/debugging).
// Query parameters:
//   - limit: number of records to return (default 50, max 500)
//   - filter: "user" to filter by user's API keys, "all" to show all (default)
func (h *Handler) ListUsageLogs(c *gin.Context) {
	user := currentUser(c)
	plugin := usage.GlobalPostgresUsagePlugin()
	if plugin == nil {
		c.JSON(http.StatusOK, gin.H{
			"usage_logs":    []usage.UsageLog{},
			"notice":        "PostgreSQL usage plugin not enabled. Set USAGE_PG_DSN or PGSTORE_DSN environment variable.",
			"plugin_status": "disabled",
		})
		return
	}

	apiKeys := h.userKeyStore.ListByOwner(user.ID)
	filterMode := strings.ToLower(strings.TrimSpace(c.Query("filter")))

	var logs []usage.UsageLog
	var err error
	var notice string
	var filterStatus string

	limit := 50
	if limitStr := strings.TrimSpace(c.Query("limit")); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil {
			limit = parsed
		}
	}

	keyPrefixes := make([]string, 0, len(apiKeys))
	for _, key := range apiKeys {
		if key.KeyPrefix != "" {
			keyPrefixes = append(keyPrefixes, key.KeyPrefix)
		}
	}

	if filterMode == "user" && len(keyPrefixes) > 0 {
		logs, err = plugin.ListUsageLogsByKeyPrefixes(context.Background(), keyPrefixes, limit)
		notice = fmt.Sprintf("Filtered by %d user API key prefix(es). Use ?filter=all or no filter to see all records.", len(keyPrefixes))
		filterStatus = "filtered_by_user"
	} else {
		logs, err = plugin.ListUsageLogsAll(context.Background(), limit)
		if len(keyPrefixes) > 0 {
			notice = fmt.Sprintf("Showing all %d usage records. Use ?filter=user to filter by your %d API key(s).", len(logs), len(keyPrefixes))
		} else {
			notice = "Showing all usage records. Create an API key and use ?filter=user to filter by your own keys."
		}
		filterStatus = "all"
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"usage_logs":    logs,
		"notice":        notice,
		"plugin_status": "enabled",
		"filter_status": filterStatus,
		"api_key_count": len(apiKeys),
		"key_prefixes":  keyPrefixes,
	})
}

func currentUser(c *gin.Context) portalstore.PublicUser {
	value, _ := c.Get(userContextKey)
	user, _ := value.(portalstore.PublicUser)
	return user
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return header
}
