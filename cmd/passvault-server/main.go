// passvault-server is Passvault's server: personal vaults + attachments (no
// orgs/collections/bwcompat yet — see README.md for the roadmap). It never
// sees a master password or usable vault key — only authKey and opaque
// client-encrypted blobs (internal/crypto, internal/auth, docs/PROTOCOL.md).
// One self-hosted instance, admin-issued invites — no tenant/billing
// concept, same posture as Vaultwarden.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/toshost/passvault/internal/api"
	"github.com/toshost/passvault/internal/auth"
	"github.com/toshost/passvault/internal/db"
	"github.com/toshost/passvault/internal/ratelimit"
)

func main() {
	dsn := requireEnv("PASSVAULT_DB_DSN")
	adminToken := requireEnv("PASSVAULT_ADMIN_TOKEN")
	listenAddr := envOr("PASSVAULT_LISTEN", "127.0.0.1:8098") // nginx is the only intended caller in prod, see install/
	webDir := envOr("PASSVAULT_WEB_DIR", "web")
	signupsAllowed := envOr("PASSVAULT_SIGNUPS_ALLOWED", "false") == "true"
	attachmentsDir := envOr("PASSVAULT_ATTACHMENTS_DIR", "attachments")
	sendsDir := envOr("PASSVAULT_SENDS_DIR", "sends")

	if err := os.MkdirAll(attachmentsDir, 0o700); err != nil {
		log.Fatalf("attachments dir: %v", err)
	}
	if err := os.MkdirAll(sendsDir, 0o700); err != nil {
		log.Fatalf("sends dir: %v", err)
	}

	sqlDB, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("db open failed: %v", err)
	}
	defer sqlDB.Close()

	if err := auth.EnsureServerSecret(sqlDB); err != nil {
		log.Fatalf("server secret init failed: %v", err)
	}

	srv := &api.Server{
		DB: sqlDB, AdminToken: adminToken, SignupsAllowed: signupsAllowed,
		AttachmentsDir: attachmentsDir, SendsDir: sendsDir,
	}

	apiHandler := srv.Routes() // one mux instance, registered once, mounted at both prefixes it actually serves
	mux := http.NewServeMux()
	mux.Handle("/v1/", apiHandler)
	mux.Handle("/public/", apiHandler)
	mux.Handle("/", http.FileServer(http.Dir(webDir)))

	go runPeriodicSweeps(srv)

	if signupsAllowed {
		log.Println("PASSVAULT_SIGNUPS_ALLOWED=true — anyone can register without an invite")
	}
	log.Printf("passvault-server listening on %s", listenAddr)
	httpSrv := &http.Server{
		Addr:    listenAddr,
		Handler: logRequests(mux),
		// Bounds how long a slow/malicious client can tie up a connection
		// before ever reaching a handler — nothing in this API needs an
		// unbounded read, and a large attachment/Send download is the one
		// thing that legitimately takes a while to WRITE, hence the wider
		// WriteTimeout than Read*.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(httpSrv.ListenAndServe())
}

// runPeriodicSweeps handles the two background jobs that don't need (or
// want) a request to trigger them: reclaiming disk space from expired
// Sends nobody ever revisits (an accessed-to-exhaustion Send is already
// purged eagerly by HandleAccessSend — this only catches the ones that
// just time out unread), and auto-granting emergency access requests
// whose waiting period elapsed without the grantor rejecting them. Both
// are day/hour-granularity concerns, so an hourly ticker is plenty for a
// self-hosted single-instance app — no external cron dependency needed.
func runPeriodicSweeps(srv *api.Server) {
	sweepOnce(srv) // catch anything already due from before this boot
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		sweepOnce(srv)
	}
}

func sweepOnce(srv *api.Server) {
	srv.SweepExpiredSends()
	srv.SweepEmergencyAccessGrants()
	ratelimit.Sweep(srv.DB)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s must be set", key)
	}
	return v
}
