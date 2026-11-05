# System Architecture

PROJECT SENTINEL has three cooperating tiers that share one database: the
**endpoint agent**, the **backend control plane / API**, and the **dashboard**.
On a single host all three run locally; in an enterprise deployment many agents
report to one control plane backed by PostgreSQL.

## 1. Endpoint agent (`agent/`)

The agent is a background service that runs independently of the dashboard and
works offline. It is organised as a set of threads around a bounded event queue.

```
 watchdog observer ─► BoundedEventQueue ─► pipeline thread ─► DetectionCoordinator
 (inotify / RDCW /         (coalescing          │                 ├─ CanaryEngine
  FSEvents)                 dedup +             │                 ├─ EntropyAnalyzer (async worker)
                            backpressure)        │                 ├─ BehaviorEngine
                                                 │                 ├─ RiskEngine
                                                 ▼                 └─ ProcessMonitor
                                           AgentStore  ◄───────────  ProtectionManager
                                        (batched writer)             (alerts / incidents / response)

 heartbeat thread : health, risk decay, policy reload, retention, inventory rescan
 command thread   : executes signed control-plane commands
 inventory thread : background baseline scan (entropy + inventory)
```

Key properties:

- **Non-blocking capture.** The watchdog callback does minimal work and pushes to
  a bounded queue; under load it drops and counts events rather than stalling.
- **Coalescing dedup.** Repeated `(type, src, dest)` events within a short window
  are collapsed so behavioural counters are not inflated.
- **Async entropy.** Reading file content for entropy happens on a separate
  rate-limited worker, never on the event path.
- **Batched persistence.** Telemetry is buffered and flushed in batches by a
  dedicated writer thread with retry/backpressure.
- **Self-healing.** Worker loops restart with exponential backoff if they crash.
- **No feedback loops.** The agent's own storage and the files it writes (canary
  deployment) are excluded from monitoring.

Component modules:

| Module | Responsibility |
| --- | --- |
| `agent/filesystem/` | watchdog monitor, exclusion rules, self-write guard, inventory scan |
| `agent/entropy/` | file-type knowledge, Shannon entropy, header checks, caching |
| `agent/canary/` | synthetic decoy generation, deploy/verify/regenerate |
| `agent/behavior/` | sliding-window detectors + adaptive baseline |
| `agent/detection/` | risk engine + coordinator that fuses all signals |
| `agent/telemetry/` | process sampling + I/O-correlation attribution |
| `agent/response/` | evidence vault, recovery/snapshots, action executors, protection manager |
| `agent/core/` | config, signing, store, policy, queue, events, agent orchestrator |
| `agent/service/` | foreground runner (systemd notify) + Windows service wrapper |

## 2. Backend control plane + API (`backend/`)

A FastAPI application that is both the **dashboard API** and the **control plane**.

- Holds the Ed25519 **private** key and signs every instruction the agent will
  trust (monitored directories, commands, policy documents). The agent holds only
  the public key, so a compromised agent host cannot forge instructions.
- Authentication (Argon2id, JWT access + rotating refresh with reuse detection),
  RBAC (viewer / analyst / admin), per-IP rate limiting, security headers + CSP.
- Tamper-evident, hash-chained audit log.
- Aggregation queries for the dashboard and a WebSocket hub that broadcasts live
  deltas by polling the database (decoupled from the agent's in-process bus).

## 3. Dashboard (`frontend/`)

React + TypeScript + Vite + Tailwind + Recharts. Eight pages (Command Center,
File Intelligence, Canary Management, Process Intelligence, Threat Detection,
Incident Response, Forensics, Settings) rendered entirely from live backend data,
with a WebSocket live feed. The built bundle is served by the API.

## Data flow: a ransomware event

1. A process begins rewriting documents with encrypted content and renaming them.
2. watchdog reports create/modify/move/delete events → queue → coordinator.
3. The behaviour engine crosses mass-modification and suspicious-extension
   thresholds; the entropy worker flags high-entropy rewrites and header
   mismatches; a canary is touched.
4. Each signal feeds the risk engine; independent signals add a correlation bonus,
   pushing the score to High/Critical.
5. The protection manager raises alerts, opens/updates an incident, preserves
   evidence, and queues response actions (reversible ones may auto-run; process
   termination and live network isolation require approval).
6. The dashboard shows the incident, risk breakdown, affected files/processes and
   pending actions in real time; an analyst approves containment.

## Database

SQLite (WAL) by default for single-host; PostgreSQL for enterprise. The same
SQLAlchemy models and Alembic migrations serve both. See
[DATABASE_SCHEMA.md](DATABASE_SCHEMA.md).

## Trust boundaries

See [SECURITY_MODEL.md](SECURITY_MODEL.md). In short: the agent trusts only
signed instructions; the dashboard is authenticated and authorised; high-impact
actions require explicit approval and are audited; the agent never auto-terminates
arbitrary processes or destroys user data.
