package models

import "time"

// User holds everything the server needs to run the zero-knowledge protocol
// without ever seeing a master password or a usable key. AuthHash is
// Argon2id(authKey) (crypto.HashAuthKey) — not a password hash of the
// master password itself. WrappedVaultKey/WrappedX25519PrivateKey are
// opaque client-encrypted blobs the server stores and returns verbatim.
type User struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`

	CryptoRealm string `json:"crypto_realm"` // native | bwcompat

	KDFMemoryKiB   uint32 `json:"kdf_memory_kib"`
	KDFIterations  uint32 `json:"kdf_iterations"`
	KDFParallelism uint8  `json:"kdf_parallelism"`
	KDFSalt        string `json:"kdf_salt"` // base64, client-generated at signup

	AuthHash string `json:"-"` // Argon2id(authKey), never serialized to clients

	WrappedVaultKey         string `json:"wrapped_vault_key"`
	X25519PublicKey         string `json:"x25519_public_key"`
	WrappedX25519PrivateKey string `json:"wrapped_x25519_private_key"`

	// TOTP2FASecret is server-side and NEVER serialized — see the
	// totp_2fa_secret column comment in internal/db/db.go for why this
	// one field is deliberately outside the zero-knowledge boundary.
	TOTP2FASecret  *string `json:"-"`
	TOTP2FAEnabled bool    `json:"totp_2fa_enabled"`

	// EmailAliasProvider/WrappedEmailAliasAPIKey are scanned here for
	// query convenience but returned to clients only via their own
	// dedicated endpoint (internal/api/email_alias_handlers.go), not
	// bundled into a login/sync response.
	EmailAliasProvider      string  `json:"-"`
	WrappedEmailAliasAPIKey *string `json:"-"`

	// RecoveryCodeHash/WrappedVaultKeyForRecovery back the account
	// recovery kit (internal/api/recovery_handlers.go) — never serialized
	// directly; exposed only as a has-a-kit boolean via that endpoint.
	RecoveryCodeHash           *string `json:"-"`
	WrappedVaultKeyForRecovery *string `json:"-"`

	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

// Device represents one logged-in client (web session, CLI, extension,
// mobile). RefreshTokenHash is crypto.HashToken(refreshToken) — the raw
// token is only ever returned once, at login/refresh time.
type Device struct {
	ID               int64      `json:"id"`
	UserID           int64      `json:"user_id"`
	Label            string     `json:"label"`
	RefreshTokenHash string     `json:"-"`
	AccessTokenHash  string     `json:"-"`
	AccessExpiresAt  time.Time  `json:"-"`
	LastSeenAt       time.Time  `json:"last_seen_at"`
	CreatedAt        time.Time  `json:"created_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

// Folder is a personal, user-owned grouping. Its name is opaque to the
// server (EncryptedName), like every other user-authored string.
type Folder struct {
	ID               int64      `json:"id"`
	UserID           int64      `json:"user_id"`
	WrappedFolderKey string     `json:"wrapped_folder_key"`
	EncryptedName    string     `json:"encrypted_name"`
	RevisionTS       int64      `json:"revision_ts"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
}

// Cipher is one vault item (login, note, card, ...). Owned by exactly one
// user in Phase 1 (org/collection ownership arrives later). EncryptedBlob
// holds every user-authored field (name/username/password/TOTP/notes/URIs) —
// the server never parses it, only stores and relays it.
type Cipher struct {
	ID             int64      `json:"id"`
	UserID         int64      `json:"user_id"`
	FolderID       *int64     `json:"folder_id,omitempty"`
	Type           string     `json:"type"` // login | note | card | identity | totp | ssh_key
	WrappedItemKey string     `json:"wrapped_item_key"`
	EncryptedBlob  string     `json:"encrypted_blob"`
	RevisionTS     int64      `json:"revision_ts"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
}

// CipherShare grants one other user read access to one item. Unlike
// Cipher.WrappedItemKey (wrapped under the owner's vaultKey), WrappedItemKey
// here is wrapped via an X25519 ECDH-derived key between owner and
// recipient — see web/crypto.js's deriveSharedWrapKey and docs/PROTOCOL.md.
type CipherShare struct {
	ID               int64     `json:"id"`
	CipherID         int64     `json:"cipher_id"`
	OwnerUserID      int64     `json:"owner_user_id"`
	SharedWithUserID int64     `json:"shared_with_user_id"`
	WrappedItemKey   string    `json:"wrapped_item_key"`
	CreatedAt        time.Time `json:"created_at"`
}

// Attachment is a file encrypted client-side before upload. The server
// stores and streams ciphertext bytes verbatim (internal/api/attachment_handlers.go)
// — same opacity guarantee as Cipher.EncryptedBlob. WrappedAttachmentKey
// wraps under the parent cipher's itemKey (not vaultKey directly), so an
// attachment is only reachable via its item, mirroring "this file belongs
// to this item." StoragePath is server-internal and never serialized.
type Attachment struct {
	ID                   int64     `json:"id"`
	CipherID             int64     `json:"cipher_id"`
	WrappedAttachmentKey string    `json:"wrapped_attachment_key"`
	EncryptedFilename    string    `json:"encrypted_filename"`
	SizeBytes            int64     `json:"size_bytes"`
	StoragePath          string    `json:"-"`
	CreatedAt            time.Time `json:"created_at"`
}

// Send is a Bitwarden-Send-style one-time/expiring anonymous share.
// WrappedSendKey wraps the content key under the owner's vaultKey (so the
// owner's own client can re-decrypt it from "My Sends"); EncryptedLabel is
// likewise vaultKey-encrypted and owner-only. EncryptedContent/
// EncryptedFilename are encrypted under a *different* key — a random
// sendKey that lives only in the recipient URL's fragment — which is why
// they need their own wrap (WrappedSendKey) rather than reusing an
// existing item's key. StoragePath is server-internal, never serialized.
// See docs/PROTOCOL.md and internal/api/send_handlers.go.
type Send struct {
	ID                string     `json:"id"`
	OwnerUserID       int64      `json:"-"`
	Type              string     `json:"type"` // text | file
	WrappedSendKey    string     `json:"wrapped_send_key"`
	EncryptedLabel    string     `json:"encrypted_label"`
	EncryptedContent  *string    `json:"encrypted_content,omitempty"`
	EncryptedFilename *string    `json:"encrypted_filename,omitempty"`
	StoragePath       *string    `json:"-"`
	SizeBytes         *int64     `json:"size_bytes,omitempty"`
	PasswordHash      *string    `json:"-"`
	HasPassword       bool       `json:"has_password"`
	MaxViews          *int       `json:"max_views,omitempty"`
	ViewCount         int        `json:"view_count"`
	ExpiresAt         time.Time  `json:"expires_at"`
	AvailableAt       *time.Time `json:"available_at,omitempty"` // nil = available immediately
	CreatedAt         time.Time  `json:"created_at"`
	DeletedAt         *time.Time `json:"deleted_at,omitempty"`
}

// SMTPSettings is the instance operator's mail relay config (see
// internal/mailer), editable at runtime from web/admin.html. Password is
// never serialized to a client — HasPassword tells the admin UI whether
// one is already saved, so it can omit the field on save to mean "keep
// the existing one" rather than forcing it to be retyped every edit.
type SMTPSettings struct {
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Username    string    `json:"username"`
	Password    string    `json:"-"`
	HasPassword bool      `json:"has_password"`
	FromAddress string    `json:"from_address"`
	FromName    string    `json:"from_name"`
	UseTLS      bool      `json:"use_tls"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// EmergencyAccess is one grantor→grantee trust relationship. See the
// emergency_access table comment in internal/db/db.go for the full state
// machine and crypto shape. WrappedVaultKeyForGrantee is only set once
// status reaches "confirmed"; it's nil before that.
type EmergencyAccess struct {
	ID                        int64      `json:"id"`
	GrantorUserID             int64      `json:"grantor_user_id"`
	GrantorEmail              string     `json:"grantor_email,omitempty"`
	GrantorX25519PublicKey    string     `json:"grantor_x25519_public_key,omitempty"`
	GranteeUserID             int64      `json:"grantee_user_id"`
	GranteeEmail              string     `json:"grantee_email,omitempty"`
	GranteeX25519PublicKey    string     `json:"grantee_x25519_public_key,omitempty"`
	AccessType                string     `json:"access_type"` // view | takeover
	WaitDays                  int        `json:"wait_days"`
	Status                    string     `json:"status"`
	WrappedVaultKeyForGrantee *string    `json:"wrapped_vault_key_for_grantee,omitempty"`
	RequestedAt               *time.Time `json:"requested_at,omitempty"`
	AccessAt                  *time.Time `json:"access_at,omitempty"`
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`
}

// AuditEvent is an append-only record of security-relevant actions
// (login, logout, device revoked, password changed, cipher created/deleted).
// Never contains plaintext secrets — Target is a short machine label, not
// user data.
type AuditEvent struct {
	ID        int64     `json:"id"`
	UserID    *int64    `json:"user_id,omitempty"`
	Event     string    `json:"event"`
	Target    string    `json:"target,omitempty"`
	IP        string    `json:"ip,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
