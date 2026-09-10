// Package mailer sends outbound email via SMTP, using settings the
// instance operator configures at runtime through the admin panel (see
// internal/api/admin_handlers.go's SMTP endpoints and web/admin.html) —
// not an env var, since the whole point is letting an operator change
// mail settings (or set them up for the first time) without a redeploy.
// Settings live in Postgres (smtp_settings, a singleton row) and are read
// fresh on every send, so a change takes effect on the very next email.
//
// This is the one place in Passvault that sends anything to a third
// party by design (Have I Been Pwned's k-anonymity lookup is the other,
// client-side and opt-in). Every email this package sends is a small,
// operational, plaintext notice (an invite, a security-relevant status
// change) — never vault content, which this package has no way to read
// in the first place.
package mailer

import (
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type Settings struct {
	Host        string
	Port        int
	Username    string
	Password    string
	FromAddress string
	FromName    string
	UseTLS      bool // STARTTLS (or implicit TLS on port 465); false only makes sense for an unauthenticated local/LAN relay
}

// ErrNotConfigured means the operator hasn't set an SMTP host yet. Every
// caller that triggers mail as a side effect of some other action (an
// emergency-access invite, a request notice) must treat this as "skip
// sending, don't fail the underlying action" — only the admin's own
// test-email endpoint should surface it as a user-facing error.
var ErrNotConfigured = errors.New("SMTP is not configured")

func LoadSettings(db *sql.DB) (Settings, error) {
	var s Settings
	err := db.QueryRow(`
		SELECT host, port, username, password, from_address, from_name, use_tls
		FROM smtp_settings WHERE id=1`).
		Scan(&s.Host, &s.Port, &s.Username, &s.Password, &s.FromAddress, &s.FromName, &s.UseTLS)
	if err != nil {
		return Settings{}, err
	}
	if s.Host == "" {
		return Settings{}, ErrNotConfigured
	}
	return s, nil
}

// Send delivers one plaintext email. Port 465 gets an implicit-TLS
// connection (smtp.SendMail can't do this — it only ever does
// opportunistic STARTTLS); every other port goes through smtp.SendMail,
// which negotiates STARTTLS itself when the server advertises it.
func Send(s Settings, to, subject, body string) error {
	if s.Host == "" {
		return ErrNotConfigured
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	msg := buildMessage(s, to, subject, body)

	var a smtp.Auth
	if s.Username != "" {
		a = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}

	if s.Port == 465 {
		return sendImplicitTLS(s, addr, a, to, msg)
	}
	return smtp.SendMail(addr, a, s.FromAddress, []string{to}, msg)
}

func sendImplicitTLS(s Settings, addr string, auth smtp.Auth, to string, msg []byte) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{ServerName: s.Host})
	if err != nil {
		return err
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return err
	}
	defer client.Close()
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(s.FromAddress); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// sanitizeHeader strips CR/LF from anything interpolated into a header
// line (To/From/Subject) — cheap, necessary defense against header
// injection (CWE-93) for any value that ultimately traces back to
// user-supplied data (an account email, say), even though nothing here is
// raw unvalidated input today. The body is untouched — newlines there are
// normal and only ever appear after the header/body blank-line boundary.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

func buildMessage(s Settings, to, subject, body string) []byte {
	from := sanitizeHeader(s.FromAddress)
	if s.FromName != "" {
		from = fmt.Sprintf("%s <%s>", sanitizeHeader(s.FromName), from)
	}
	return []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		from, sanitizeHeader(to), sanitizeHeader(subject), body,
	))
}
