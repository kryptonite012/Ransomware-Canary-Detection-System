# API Documentation

The backend exposes a REST API plus a WebSocket for live updates. Interactive
OpenAPI docs are served at **`/api/docs`** and the raw schema at
**`/api/openapi.json`** when the API is running.

Base URL (default): `http://127.0.0.1:8443` (use TLS in production).

## Authentication

All routes except `/api/health`, `/api/auth/login` and `/api/auth/refresh` require
a bearer access token:

```
Authorization: Bearer <access_token>
```

### Flow

```bash
# login -> access + refresh tokens
curl -s -X POST http://127.0.0.1:8443/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}'

# use the access token
curl -s http://127.0.0.1:8443/api/dashboard/overview \
  -H "Authorization: Bearer $ACCESS"

# rotate when the access token expires (refresh tokens are single-use)
curl -s -X POST http://127.0.0.1:8443/api/auth/refresh \
  -H 'Content-Type: application/json' -d '{"refresh_token":"..."}'
```

Access tokens are short-lived (default 30 min). Refresh tokens rotate on every use;
re-using a spent refresh token revokes the whole session (theft detection).

## Roles (RBAC)

- **viewer** – read dashboards, alerts, incidents, telemetry.
- **analyst** – viewer + manage monitored directories & canaries, acknowledge /
  resolve incidents, submit alert feedback, create snapshots.
- **admin** – analyst + approve/reject/rollback response actions, manual
  containment, publish signed policy, manage users, restore snapshots, view audit.

## Endpoints

| Method | Path | Summary |
| --- | --- | --- |
| `GET` | `/api/actions` | List Actions |
| `POST` | `/api/actions/{action_id}/approve` | Approve Action |
| `POST` | `/api/actions/{action_id}/reject` | Reject Action |
| `POST` | `/api/actions/{action_id}/rollback` | Rollback Action |
| `POST` | `/api/auth/change-password` | Change Password |
| `POST` | `/api/auth/login` | Login |
| `POST` | `/api/auth/logout` | Logout |
| `GET` | `/api/auth/profile` | Profile |
| `POST` | `/api/auth/refresh` | Refresh |
| `GET` | `/api/auth/users` | List Users |
| `POST` | `/api/auth/users` | Create User |
| `GET` | `/api/canaries` | List Canaries |
| `POST` | `/api/canaries/deploy` | Deploy Canaries |
| `POST` | `/api/canaries/regenerate` | Regenerate Canaries |
| `POST` | `/api/canaries/verify` | Verify Canaries |
| `GET` | `/api/dashboard/activity` | Dashboard Activity |
| `GET` | `/api/dashboard/overview` | Dashboard Overview |
| `GET` | `/api/dashboard/statistics` | Dashboard Statistics |
| `GET` | `/api/detection/alerts` | List Alerts |
| `GET` | `/api/detection/alerts/{alert_id}` | Get Alert |
| `POST` | `/api/detection/alerts/{alert_id}/feedback` | Alert Feedback |
| `GET` | `/api/detection/entropy-history` | Entropy History |
| `GET` | `/api/detection/events` | List Events |
| `GET` | `/api/detection/risk-score` | Risk Score |
| `GET` | `/api/endpoints` | List Endpoints |
| `GET` | `/api/forensics/audit` | List Audit |
| `GET` | `/api/forensics/audit/verify` | Verify Audit |
| `GET` | `/api/forensics/evidence` | List Evidence |
| `GET` | `/api/health` | Health |
| `GET` | `/api/incidents` | List Incidents |
| `GET` | `/api/incidents/{incident_id}` | Get Incident |
| `POST` | `/api/incidents/{incident_id}/acknowledge` | Acknowledge Incident |
| `POST` | `/api/incidents/{incident_id}/contain` | Contain Incident |
| `POST` | `/api/incidents/{incident_id}/resolve` | Resolve Incident |
| `GET` | `/api/monitoring/directories` | List Directories |
| `POST` | `/api/monitoring/directories` | Add Directory |
| `DELETE` | `/api/monitoring/directories/{dir_id}` | Disable Directory |
| `GET` | `/api/monitoring/status` | Monitoring Status |
| `GET` | `/api/processes` | List Processes |
| `GET` | `/api/system/configuration` | Get Configuration |
| `PUT` | `/api/system/configuration` | Update Configuration |
| `GET` | `/api/system/health` | System Health |
| `POST` | `/api/system/restore` | Restore Snapshot |
| `POST` | `/api/system/snapshot` | Create Snapshot |

## WebSocket

Connect to `/api/ws?token=<access_token>`. On connect the server sends a
`snapshot` message, then streams deltas:

| Message `type` | Payload |
| --- | --- |
| `snapshot` | `{ overview }` – full overview on connect |
| `overview` | updated dashboard overview metrics |
| `alert` | a newly created security alert |
| `incident` | a newly created incident |

```js
const ws = new WebSocket(`wss://host/api/ws?token=${accessToken}`);
ws.onmessage = (e) => { const { type, data } = JSON.parse(e.data); /* ... */ };
```

## Errors

Errors use standard HTTP status codes with a JSON body `{ "detail": "..." }`.
Common codes: `401` (missing/invalid/expired token), `403` (insufficient role),
`404` (not found), `409` (conflict, e.g. duplicate user / action not pending),
`422` (validation / invalid policy), `429` (rate limited),
`503` (control-plane signing key unavailable).

## Rate limiting

A global per-IP limit (default 300/min) applies to `/api/*`; login/refresh have a
stricter bucket (default 10/min). Exceeding a limit returns `429`.
