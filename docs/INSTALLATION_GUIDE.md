# Installation Guide

PROJECT SENTINEL has two runtime components (the **agent** and the **backend
API/control plane**) plus a **dashboard** that the API serves. They share one
database.

## Prerequisites

- Python **3.12+**
- Node.js **20+** and npm (to build the dashboard)
- Linux, Windows or macOS
- (Optional) PostgreSQL 14+ for an enterprise database
- (Optional) Docker + Docker Compose

## Option A — local / development (SQLite)

```bash
git clone <repository-url> && cd Ransomware-Canary-Detection-System

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt           # add -r requirements-dev.txt for tests

# initialise data dir, DB schema and control-plane keys
python -m agent init
python -m backend init-keys

# create a dashboard admin (you will be prompted for a password)
python -m backend create-user admin admin@example.com --role admin

# build the dashboard (served by the API)
cd frontend && npm install && npm run build && cd ..

# run (two terminals, or use scripts/dev_run.sh)
python -m backend run      # http://127.0.0.1:8443
python -m agent run
```

Open `http://127.0.0.1:8443` and sign in. Add directories to protect under
**Settings → Monitoring**, or edit `config/sentinel.yaml` before starting the agent.

`scripts/dev_run.sh` runs the agent, API and the Vite dev server (hot reload on
`:5173`, proxying the API) together.

## Option B — Docker

```bash
cp .env.example .env
# edit .env and set SENTINEL_ADMIN_PASSWORD (and SENTINEL_WATCH_DIR)
docker compose up --build
```

The `api` and `agent` services share a data volume. The admin user is bootstrapped
from `SENTINEL_ADMIN_*` on first run. To use PostgreSQL, uncomment the `db` service
and the `SENTINEL_DATABASE_URL` lines in `docker-compose.yml`.

## Option C — system service (production)

See [LINUX_DEPLOYMENT.md](LINUX_DEPLOYMENT.md) (systemd) and
[WINDOWS_DEPLOYMENT.md](WINDOWS_DEPLOYMENT.md) (Windows Service). macOS uses the
launchd plist in `deployment/macos/`.

## Configuration

- `config/sentinel.yaml` holds bootstrap settings (`agent` section: data dir,
  database URL, intervals) and the **default policy** (monitoring, entropy, canary,
  behaviour, risk, response, retention).
- The `agent` section is read only from the file / environment. All other sections
  are defaults that a **signed policy** published from the dashboard can override.
- Environment overrides: `SENTINEL_CONFIG`, `SENTINEL_DATA_DIR`,
  `SENTINEL_DATABASE_URL`, `SENTINEL_LOG_LEVEL`, and the `SENTINEL_API_*` settings
  (see `.env.example`).

## PostgreSQL

```bash
export SENTINEL_DATABASE_URL="postgresql+psycopg://sentinel:password@localhost:5432/sentinel"
python -m agent init        # runs migrations against PostgreSQL
```

Set the same URL for both the agent and the API.

## Verifying the install

```bash
python -m agent status            # shows the endpoint's recorded status
curl -s localhost:8443/api/health # {"status":"ok",...}
python -m simulator benchmark     # safe, sandbox-only detection benchmark
```
