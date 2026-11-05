# Troubleshooting

### The agent starts but no events appear
- Check the directory is actually monitored: the endpoint health (`python -m agent
  status`, or the dashboard Monitoring page) lists each watch and its state
  (`active` / `missing` / `error`).
- A directory registered from the dashboard must be **signed**; if the agent has no
  control-plane public key it rejects it and raises a `configuration_tamper`
  finding. Run `python -m backend init-keys` so the public key exists where the
  agent expects it (`<data_dir>/secrets/control_plane_ed25519.pub`).

### "control-plane public key not found" / signed instructions rejected
- The API generates the keypair on first start, or run `python -m backend
  init-keys`. The agent and API must share the same data directory (or you must
  copy the `.pub` to the agent's `secrets/` directory).

### Dashboard shows "control-plane signing unavailable" (HTTP 503 on changes)
- The backend cannot find its Ed25519 **private** key. Run `python -m backend
  init-keys` and restart the API.

### inotify: "failed to monitor … ENOSPC" (Linux)
- The inotify watch limit is exhausted. Raise it:
  `sudo sysctl fs.inotify.max_user_watches=524288` (see LINUX_DEPLOYMENT.md).

### High CPU during a scan or attack
- Entropy analysis reads file content; it is rate-limited
  (`entropy.max_analyses_per_second`) and cached. Lower the rate or raise
  `entropy.min_file_size` for very busy endpoints. Peak CPU during a genuine
  mass-encryption burst is expected (that is the agent hashing/analysing).

### Too many / too few alerts
- Tune thresholds in the policy (`behavior.*`, `entropy.*`, `risk.*`). Publish a
  signed policy from **Settings → Policy**; the agent applies it on its next config
  poll. Use alert feedback (true/false positive) on the Threat Detection page to
  review accuracy.

### Canary files keep triggering on deployment
- The self-write guard suppresses the agent's own writes for a short window. If a
  backup/AV tool touches canaries immediately, exclude that tool or directory, or
  disable `alert_on_read`.

### Login problems
- After too many failed logins the account locks for `lockout_minutes`. Wait, or an
  admin can reset. Refresh tokens are single-use; if a refresh returns 401, log in
  again (a reused refresh token revokes the session by design).

### "no space left on device"
- The data directory (database, evidence vault, snapshots) filled up. Reduce
  retention horizons, lower evidence budgets (`response.evidence.*`), or move the
  data directory. Retention runs periodically; it never deletes incidents/evidence
  automatically.

### WebSocket not updating
- The WS requires a valid access token (`/api/ws?token=…`). If it keeps
  reconnecting, your access token may have expired — the dashboard refreshes it
  automatically on the next API call.

### Database locked (SQLite)
- The agent retries transient locks with backoff. Persistent locking usually means
  two agents share one SQLite file; use one agent per SQLite database, or switch to
  PostgreSQL for multi-writer deployments.
