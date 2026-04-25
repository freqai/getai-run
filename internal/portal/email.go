package portal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const resendEndpoint = "https://api.resend.com/emails"

// EmailSender sends short-lived authentication codes.
type EmailSender interface {
	SendAuthCode(ctx context.Context, email, purpose, code string) error
}

// ResendMailer sends email through Resend.
type ResendMailer struct {
	apiKey string
	from   string
}

// NewResendMailerFromEnv returns a Resend mailer when RESEND_API_KEY is set.
func NewResendMailerFromEnv() *ResendMailer {
	apiKey := strings.TrimSpace(os.Getenv("RESEND_API_KEY"))
	if apiKey == "" {
		return nil
	}
	from := strings.TrimSpace(os.Getenv("RESEND_FROM_EMAIL"))
	if from == "" {
		from = "getai.run <onboarding@resend.dev>"
	}
	return &ResendMailer{apiKey: apiKey, from: from}
}

// SendAuthCode sends an authentication code email.
func (m *ResendMailer) SendAuthCode(ctx context.Context, email, purpose, code string) error {
	if m == nil {
		return nil
	}
	email = normalizeEmail(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}
	subject := "getai.run 登录验证码"
	action := "登录"
	if normalizePurpose(purpose) == "register" {
		subject = "getai.run 注册验证码"
		action = "注册"
	}
	html := fmt.Sprintf(`<div style="font-family:Arial,sans-serif;line-height:1.7;color:#111827">
<h2>getai.run %s验证码</h2>
<p>你的验证码是：</p>
<p style="font-size:28px;font-weight:700;letter-spacing:6px">%s</p>
<p>验证码 10 分钟内有效。如果不是你本人操作，请忽略这封邮件。</p>
</div>`, action, code)
	payload := map[string]any{
		"from":    m.from,
		"to":      []string{email},
		"subject": subject,
		"html":    html,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal resend payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resendEndpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create resend request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send resend email: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(readSmallBody(resp.Body, 4096))
		if message == "" {
			return fmt.Errorf("resend email failed with status %d", resp.StatusCode)
		}
		return fmt.Errorf("resend email failed with status %d: %s", resp.StatusCode, message)
	}
	return nil
}

func readSmallBody(r io.Reader, limit int64) string {
	if r == nil {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return ""
	}
	return string(data)
}
