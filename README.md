# PROJECT SENTINEL

**Enterprise-grade ransomware canary & early-detection platform.**

PROJECT SENTINEL is a locally deployable defensive security platform that watches
file-system activity in real time, deploys decoy *canary* files, analyses file
entropy, correlates abnormal behaviour into a ransomware risk score, and runs a
policy-driven, authorization-gated response workflow — all backed by a real-time
SOC-style dashboard.

It is a functional product, not a mock-up: a background agent captures live
filesystem telemetry, the detection engines run on real file content, incidents
are persisted, and the dashboard shows actual backend data. It runs fully offline.

> **Defensive tool.** SENTINEL detects and contains ransomware behaviour. It never
> encrypts, deletes or damages user data, and the included simulator only ever
> operates inside a disposable sandbox it creates.

---

## Highlights

- **Continuous filesystem monitoring** (inotify / ReadDirectoryChangesW / FSEvents
  via `watchdog`) with event coalescing, backpressure and exclusion rules.
- **Multi-signal detection** — no single point of failure:
  - *Canary files*: realistic, secret-free decoys; any touch is a high-confidence
    signal, detected both on-event and by periodic hash verification.
  - *Entropy analysis*: file-type-aware Shannon entropy with history deltas and
    header/magic checks, so a `.zip` is not confused with an encrypted document.
  - *Behavioural detection*: mass modification/deletion/rename, suspicious
    extension changes, file replacement, ransom notes, and an adaptive baseline.
  - *Process attribution*: psutil-based I/O correlation (privileged adapters where
    available).
- **Risk scoring** that fuses signals into a 0–100 score with de-duplication,
  correlation bonuses, decay and full explainability.
- **Tiered response** (observe → warn → protect → contain) with reversible actions,
  an approval workflow for high-impact/irreversible actions, forensic evidence
  preservation, and verified backup snapshots / restore.
- **Control plane** that signs every instruction the agent trusts (Ed25519), plus
  Argon2id auth, JWT with refresh rotation + reuse detection, RBAC, rate limiting,
  a tamper-evident audit log, and strict security headers.
- **Measured performance**: see [docs/benchmarks/benchmark_report.md](docs/benchmarks/benchmark_report.md).

## Architecture at a glance

```
          ┌──────────────────────────── Endpoint ────────────────────────────┐
          │  SENTINEL AGENT (background service)                              │
 files →  │  watchdog → event queue → detection coordinator                  │
          │                    ├─ canary engine     ─┐                        │
          │                    ├─ entropy engine      ├─ risk engine →        │
          │                    ├─ behaviour engine   ─┘   protection manager  │
          │                    └─ process telemetry        (alerts/incidents/ │
          │                                                  response)        │
          └───────────────┬──────────────────────────────────┬──────────────┘
                          │  shared database (SQLite / PostgreSQL)
          ┌───────────────┴──────────────┐      ┌─────────────┴──────────────┐
          │  BACKEND API + control plane  │◄────►│  REACT DASHBOARD (8 pages)  │
          │  FastAPI, auth, RBAC, signing │  WS  │  live SOC console           │
          └───────────────────────────────┘      └─────────────────────────────┘
```

Full detail in [docs/SYSTEM_ARCHITECTURE.md](docs/SYSTEM_ARCHITECTURE.md).

## Quick start (local, SQLite)

```bash
# 1. Python environment
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Initialise the data directory, database and control-plane keys
python -m agent init
python -m backend init-keys

# 3. Create a dashboard admin
python -m backend create-user admin admin@example.com --role admin

# 4. Build the dashboard (served by the API)
cd frontend && npm install && npm run build && cd ..

# 5. Run the API (control plane + dashboard) and the agent
python -m backend run      # http://127.0.0.1:8443
python -m agent run        # in another terminal
```

Edit `config/sentinel.yaml` to choose which directories to protect, or register
them from the dashboard **Settings → Monitoring** page (they are signed by the
control plane before the agent applies them).

### Docker

```bash
cp .env.example .env            # set SENTINEL_ADMIN_PASSWORD
docker compose up --build
```

### Try a safe simulation

```bash
# Runs entirely inside a disposable sandbox; no real files are touched.
python -m simulator attack
python -m simulator benchmark   # measures detection rate / latency / FP rate
```

## Documentation

| Document | Contents |
| --- | --- |
| [SYSTEM_ARCHITECTURE.md](docs/SYSTEM_ARCHITECTURE.md) | Components, data flow, threading model |
| [INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md) | Install options, prerequisites |
| [WINDOWS_DEPLOYMENT.md](docs/WINDOWS_DEPLOYMENT.md) | Windows Service deployment |
| [LINUX_DEPLOYMENT.md](docs/LINUX_DEPLOYMENT.md) | systemd deployment & hardening |
| [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) | REST + WebSocket reference |
| [DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) | Tables, relationships, retention |
| [DETECTION_ENGINE.md](docs/DETECTION_ENGINE.md) | Entropy, canary, behaviour, risk |
| [INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md) | Response levels & approval workflow |
| [SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Trust model, signing, auth, hardening |
| [TESTING_GUIDE.md](docs/TESTING_GUIDE.md) | Running tests, the simulator, benchmarks |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | Development workflow |

## Repository layout

```
agent/       endpoint agent: filesystem, entropy, canary, behaviour, detection, response, telemetry, service
backend/     FastAPI control plane + dashboard API, auth, models, migrations, services, websocket
frontend/    React + TypeScript + Vite + Tailwind dashboard (8 pages)
simulator/   safe, sandbox-only ransomware simulator + benchmark harness
tests/       unit + integration tests
deployment/  windows / linux / docker / macos deployment artifacts
docs/        documentation + benchmark reports
config/      default configuration
```

## Status

All six development phases are implemented and tested (unit + integration),
including an end-to-end detection benchmark. See the per-phase commit history and
[docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md).

## License

MIT — see [LICENSE](LICENSE).
