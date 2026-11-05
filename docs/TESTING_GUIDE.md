# Testing Guide

## Test suites

```bash
source .venv/bin/activate
pip install -r requirements-dev.txt

python -m pytest tests/unit          # fast, no I/O side effects
python -m pytest tests/integration   # real filesystem, DB, agent lifecycle, API
python -m pytest                     # everything
```

Integration tests are marked with `@pytest.mark.integration`; run only unit tests
with `-m "not integration"`.

### What is covered

- **Unit** — entropy maths & file-type logic, canary generation/trigger/regenerate,
  behaviour detectors & adaptive baseline, risk scoring (dedup/correlation/decay),
  queue coalescing & backpressure, exclusions, Ed25519/HMAC signing, config
  validation, evidence vault, snapshot create/verify/restore, action executors,
  retention, and the tamper-evident audit chain.
- **Integration** — live filesystem capture (create/modify/rename/delete), agent
  startup + persistence + heartbeat, signed directories & commands, the full
  detection pipeline against simulated attacks, a benign false-positive check, the
  protection pipeline (alert → incident → pending actions → approval → execute →
  rollback), snapshot/restore via signed command, and the API (auth rotation/reuse/
  lockout, RBAC, control-plane signing, policy validation, security headers,
  WebSocket auth).

## Safe ransomware simulator

The simulator reproduces ransomware **behaviour** without any real malware and
**only inside a disposable sandbox it creates and marks**. It refuses to operate on
any directory lacking its marker, and rejects protected locations and path escapes.

```bash
python -m simulator create                 # create + populate a sandbox
python -m simulator run mass_modification  # one scenario
python -m simulator attack                 # full attack sequence
python -m simulator destroy ./sandbox/sentinel-sim
```

Scenarios: `benign`, `mass_modification`, `extension_rename`, `encrypt_and_replace`,
`mass_deletion`, `ransom_notes`, `canary_modify`, `canary_delete`.

### Manual end-to-end test

```bash
# terminal 1: run the agent pointed at a sandbox
python -m simulator create
# add the sandbox path under Settings -> Monitoring (or config/sentinel.yaml)
python -m agent run

# terminal 2: launch the attack and watch the dashboard light up
python -m simulator attack ./sandbox/sentinel-sim
```

## Benchmark

```bash
python -m simulator benchmark --output ./benchmark-results
```

Measures detection rate, false-positive rate, detection latency, agent CPU/memory,
event throughput and canary reliability, writing `benchmark_report.{json,md}`.
A captured run is in [benchmarks/benchmark_report.md](benchmarks/benchmark_report.md):

| Metric | Result |
| --- | --- |
| Detection rate | 100% |
| False-positive rate | 0% |
| Mean detection latency | ~0.05 s |
| Canary reliability | 100% |

(Exact numbers vary with hardware and thresholds; re-run to reproduce on your host.)

## Evaluation metrics (definitions)

- **Detection rate** — fraction of malicious scenarios that raised risk to
  High/Critical.
- **False-positive rate** — fraction of benign scenarios that wrongly raised risk.
- **Detection latency** — time from attack start to the first High/Critical signal.
- **Throughput** — file events processed per second by the agent.
- **Canary reliability** — fraction of tampered canaries that fired.

## Databases

The suite runs against SQLite by default. To exercise PostgreSQL, point
`SENTINEL_DATABASE_URL` at a test database before running; migrations and batched
writes are covered on both backends.
