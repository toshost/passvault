# Security policy

Passvault handles master passwords and vault contents. If you find a way to
break the zero-knowledge guarantee described in `docs/PROTOCOL.md` — the
server, or anyone with **passive** access to it (a database dump, a disk
image, a network capture), learning a master password, a vault key, or
item plaintext without a client ever supplying it — that's a security
vulnerability, not a bug. See `docs/PROTOCOL.md`'s "Threat model boundary"
section for the one thing this deliberately does *not* cover: an attacker
who can actively modify the code the server serves (rather than just read
its data) can target a victim directly, the same limitation every
browser-delivered E2EE app has. A report along those lines is still
welcome as a documentation/hardening issue, just not as a break of the
core guarantee.

## Reporting

**Do not open a public GitHub issue for a security vulnerability.** Use
GitHub's private vulnerability reporting instead: open the repository's
"Security" tab → "Report a vulnerability". This creates a private advisory
only the maintainers can see until it's resolved.

If that's unavailable to you for any reason, email the maintainer address
listed in the repository's GitHub profile. Include:

- What you found and why it matters (what a client-supplied secret would be
  exposed, and to whom — a malicious server operator? a passive network
  observer? another user on the same instance?).
- Steps to reproduce, or a proof-of-concept if you have one.
- The version/commit you tested against.

## What's in scope

- The zero-knowledge crypto protocol (`docs/PROTOCOL.md`) and its
  implementation in `web/crypto.js` (client) and `internal/crypto` /
  `internal/auth` (server) — any gap between what the protocol document
  claims and what the code actually does.
- Authentication and session handling (`internal/auth`) — token forgery,
  privilege escalation, one user reaching another user's data.
- The HTTP API (`internal/api`) — injection, auth bypass, information
  disclosure via error messages or timing.
- The vendored Argon2id build (`web/vendor/hash-wasm/`) being tampered with
  or out of date relative to a known CVE in hash-wasm upstream.

## What's out of scope

- Vulnerabilities requiring physical access to an already-unlocked, logged-in
  device.
- Missing security headers or hardening on a self-hoster's own reverse proxy
  — see `install/` for the recommended nginx/systemd configuration, but this
  project doesn't control how you deploy it.
- Social engineering, or a self-hoster deliberately misconfiguring
  `PASSVAULT_SIGNUPS_ALLOWED=true` on a server they intend to keep private.

## Response

There's no formal SLA (this is a young, unfunded open-source project) but
security reports get triaged ahead of everything else. Expect an initial
response within a few days. Credit is given in the release notes unless you
ask not to be named.
