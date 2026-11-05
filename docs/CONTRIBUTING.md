# Contributing

## Development setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cd frontend && npm install && cd ..
```

Run the stack locally with `scripts/dev_run.sh` (agent + API + Vite dev server).

## Before you push

```bash
python -m pytest                 # all tests must pass
cd frontend && npm run build     # dashboard must build (tsc + vite); 0 npm audit highs
```

## Code style & conventions

- Python: standard library + the pinned dependencies in `requirements.txt`; keep
  modules focused and typed. New detection logic belongs under `agent/` with unit
  tests; new API surface under `backend/` with an integration test.
- Keep the agent's hot path non-blocking: never do file I/O or network calls on the
  watchdog callback or the pipeline thread; use the async workers and batched store.
- Any new agent-trusted instruction must be **signed** by the control plane and
  verified by the agent. Never add an unauthenticated way to instruct the agent.
- Any destructive or high-impact response must be reversible or approval-gated, and
  must preserve evidence first.

## Database changes

Edit the models in `backend/models/`, then generate a migration:

```bash
alembic -c alembic.ini revision --autogenerate -m "describe change"
```

Review the generated migration; migrations run automatically on startup.

## Tests

- Unit tests go in `tests/unit/`, integration tests in `tests/integration/`
  (mark them `@pytest.mark.integration`).
- Anything that simulates ransomware behaviour **must** use the `simulator` sandbox
  — never write tests that touch paths outside a created sandbox or `tmp_path`.

## Security

- Do not commit secrets. The `data/`, `secrets/`, `*.key`, `.env` paths are
  git-ignored.
- Report security issues privately rather than in a public issue with exploit
  details.

## Commits & PRs

- Keep commits scoped and descriptive. Reference the phase/component you touched.
- Describe the behaviour change and how you tested it (include benchmark/test
  output where relevant).
