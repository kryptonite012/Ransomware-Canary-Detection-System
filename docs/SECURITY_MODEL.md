# Security Model

SENTINEL is a security product, so its own trust boundaries matter as much as its
detection logic.

## Trust boundaries

| Boundary | Control |
| --- | --- |
| Who can instruct the agent | The agent acts only on **Ed25519-signed** instructions (monitored directories, commands, policies). The backend holds the private key; the agent holds only the public key. A process that can write to the database — or the agent host itself — cannot forge instructions. Unsigned or badly-signed rows are rejected and raise a `configuration_tamper` signal. |
| Who can use the dashboard | All API routes except `/api/health` and login require a valid JWT. Roles: **viewer** (read), **analyst** (operate: directories, canaries, acknowledge/resolve, feedback), **admin** (approve containment, publish policy, manage users). |
| Agent → backend data | The agent writes telemetry; it never accepts executable instructions except signed commands. |
| High-impact actions | Process termination and live network isolation always require explicit admin approval and are audited. |

## Authentication

- **Passwords**: Argon2id (`time_cost=3, memory_cost=64MiB, parallelism=4`), with
  automatic rehash on parameter changes.
- **Access tokens**: short-lived JWT (HS256), held only in memory by the client.
- **Refresh tokens**: random, stored only as SHA-256 hashes, **rotated on every
  use**. Re-use of a revoked refresh token is treated as theft and revokes the
  entire token family.
- **Lockout**: configurable failed-login threshold locks the account temporarily.
  Login responses are timing-equalised against user enumeration.

## Hardening

- Per-IP token-bucket rate limiting (global + stricter login bucket).
- Strict security headers on every response: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, a restrictive `Content-Security-Policy`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`.
- No unauthenticated administrative interface; the WebSocket requires a valid token.
- Secrets (Ed25519 private key, JWT secret, HMAC key) are written `0600` in a
  `0700` secrets directory and are git-ignored.
- The database file is created `0600`; SQLite runs in WAL mode with foreign keys on.
- Input validation via Pydantic on every request body; path fields reject NUL and
  are length-bounded.
- Path-traversal protection in the simulator sandbox and in canary naming.
- systemd units ship with `NoNewPrivileges`, `ProtectSystem=strict`,
  `PrivateTmp`, syscall filtering and an empty capability set by default.
- The Docker image runs as a non-root `sentinel` user.

## Tamper-evident audit log

Every security-relevant action (login, policy publish, directory change, action
approval, incident change) is written to an append-only audit log where each entry
hashes the previous entry's hash plus its own content. `GET /api/forensics/audit/verify`
recomputes the chain and reports any insertion, deletion or modification. Failed
logins and refresh-token-reuse events are committed even though the request fails,
so attacks are recorded rather than rolled back.

## Data integrity

- Evidence copies and backup snapshots carry HMAC-signed manifests (agent-local
  key); restore refuses an unverified snapshot.
- Signed policy documents are schema-validated before signing and again before the
  agent applies them.

## Privilege

- The agent runs with the **minimum** privileges needed to read the monitored
  trees. Privileged process attribution (fanotify/audit, ETW, Endpoint Security) is
  optional; without it the agent degrades gracefully to I/O-correlation attribution.
- Run the agent as a dedicated low-privilege service account unless privileged
  attribution is explicitly required (see LINUX_DEPLOYMENT.md).

## Reporting vulnerabilities

See [CONTRIBUTING.md](CONTRIBUTING.md). Do not file publicly exploitable details in
a public issue.
