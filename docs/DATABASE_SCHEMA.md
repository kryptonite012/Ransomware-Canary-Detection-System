# Database Schema

SENTINEL uses SQLAlchemy models (`backend/models/`) with Alembic migrations
(`backend/database/migrations/`). SQLite (WAL mode, foreign keys on) is the default
for single-host deployments; PostgreSQL is supported for enterprise deployments via
`SENTINEL_DATABASE_URL`. The same models and migrations serve both.

Timestamps are stored as UTC (`UTCDateTime` type) on every backend.

## Tables

### Identity
- **users** — `id, username, email, password_hash (Argon2id), role, is_active,
  failed_login_count, locked_until, last_login, created_at`.
- **refresh_tokens** — rotating refresh tokens stored as hashes:
  `id, user_id→users, token_hash, family_id, expires_at, revoked_at, replaced_by,
  ip_address, user_agent, created_at`.

### Endpoints & monitoring
- **endpoints** — `id, hostname, operating_system, agent_version, status, last_seen,
  started_at, current_risk_score, current_risk_level, risk_details(JSON),
  health(JSON), capabilities(JSON), policy_version, created_at`.
- **monitored_directories** — `id, endpoint_id→endpoints, directory_path, recursive,
  monitoring_enabled, signature (Ed25519), status, status_detail, protected,
  created_by→users, created_at`. Unique on `(endpoint_id, directory_path)`.

### Telemetry
- **file_events** — `id, endpoint_id, file_path, dest_path, event_type,
  is_directory, process_id, process_name, attribution, file_size, timestamp,
  metadata(JSON)`. Indexed on `(endpoint_id, timestamp)`, `(event_type, timestamp)`,
  `file_path`.
- **file_inventory** — current known files: `id, endpoint_id, file_path, extension,
  category, size, mtime, entropy, magic_ok, last_scanned, last_modified_event,
  deleted`. Unique on `(endpoint_id, file_path)`.
- **entropy_history** — `id, endpoint_id, file_path, file_category,
  previous_entropy, current_entropy, entropy_delta, max_chunk_entropy, magic_ok,
  suspicious, reason, timestamp`. Indexed on `(file_path, timestamp)`.
- **processes** — `id, endpoint_id, process_id, process_name, executable_path,
  command_line, parent_process_id, username, create_time, first_seen, last_seen,
  is_running, state, cpu_percent, memory_rss, write_bytes_rate, total_write_bytes,
  files_modified, suspicious, risk_score, suspicion_reasons(JSON)`. Unique on
  `(endpoint_id, process_id, create_time)`.

### Canaries
- **canary_files** — `id, endpoint_id, file_path, directory, canary_type,
  original_hash, file_size, status, last_verified, last_interaction,
  last_interaction_type, trigger_count, generation, created_at`. Unique on
  `(endpoint_id, file_path)`.

### Detection & response
- **incidents** — `id, endpoint_id, title, severity, risk_score, summary,
  affected_files(JSON), affected_directories(JSON), affected_processes(JSON),
  signals(JSON), response_status, response_level, created_at, updated_at,
  acknowledged_by/at, resolved_by/at, resolution_note`.
- **security_alerts** — `id, endpoint_id, incident_id→incidents, alert_type,
  severity, risk_score, risk_level, title, description, signals(JSON),
  file_paths(JSON), process_info(JSON), timestamp, status, feedback, feedback_note,
  feedback_by`.
- **response_actions** — `id, endpoint_id, incident_id, response_level, action_type,
  target(JSON), status, requires_approval, requested_by, approved_by, reason,
  result(JSON), rollback_data(JSON), created_at, decided_at, executed_at,
  expires_at`.
- **evidence_items** — `id, endpoint_id, incident_id, item_type, original_path,
  stored_path, sha256, size, details(JSON), created_at`.
- **snapshots** — `id, endpoint_id, source_directory, snapshot_path, file_count,
  total_bytes, manifest_hash, status, created_at, verified_at`.

### Control plane
- **agent_commands** — `id, endpoint_id, command, params(JSON), signature (Ed25519),
  status, created_by, created_at, started_at, completed_at, result(JSON)`.
- **system_configuration** — signed policy documents: `id, version, policy(JSON),
  signature (Ed25519), created_by, comment, created_at`.
- **audit_logs** — tamper-evident chain: `id, user_id, username, action, resource,
  timestamp, result, ip_address, details(JSON), prev_hash, entry_hash`.

## Relationships (summary)

```
users 1─* refresh_tokens
endpoints 1─* monitored_directories, file_events, file_inventory, processes,
             canary_files, incidents, security_alerts, response_actions,
             evidence_items, snapshots, agent_commands
incidents 1─* security_alerts, response_actions, evidence_items
users 1─* (created_by/approved_by/… nullable references across control tables)
```

## Migrations

Schema changes are managed with Alembic. The runtime applies migrations
automatically on agent/API startup (`backend.database.run_migrations`). To create a
new migration during development:

```bash
alembic -c alembic.ini revision --autogenerate -m "describe change"
```

## Retention

A retention runner (`agent/core/retention.py`) purges aged rows per policy
(`retention` section) while preserving high-value records:

| Table | Default horizon | Scope |
| --- | --- | --- |
| file_events | 30 days | all |
| entropy_history | 90 days | all |
| processes | 30 days | exited only |
| agent_commands | 30 days | completed/failed/rejected/expired |
| security_alerts | 365 days | resolved/false-positive only |

Incidents and evidence are retained indefinitely by default.
