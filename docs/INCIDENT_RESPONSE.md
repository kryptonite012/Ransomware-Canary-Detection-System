# Incident Response

SENTINEL's response engine is deliberately conservative. It follows five escalating
levels, and **every high-impact or irreversible action requires explicit
authorization**, is audit-logged, and is reversible where technically possible.

## Hard safety rules

- Never automatically terminate arbitrary system processes.
- Never delete suspicious files as a default response.
- Never encrypt, overwrite or modify user data (including during testing).
- Critical OS processes are on a protected allow-list and are never suspended or
  killed.
- Evidence is preserved **before** any protective action touches a target.

## Response levels

Risk level → response level is set by `response.policy` (configurable). Defaults:

| Risk level | Response level | Actions |
| --- | --- | --- |
| normal / low | **OBSERVE** | record telemetry, update risk score |
| elevated | **WARN** | desktop notification, dashboard event, preserve telemetry |
| high | **PROTECT** | preserve evidence; write-protect affected directories (auto only if configured, else queued for approval); open an incident |
| critical | **CONTAIN** | preserve evidence; queue process suspension and (optional) network isolation; termination is always approval-gated |

## Alerts and incidents

- A **SecurityAlert** is created when the risk level reaches `alert_min_level`
  (or for any canary/integrity signal), subject to a per-signal cooldown.
- An **Incident** is opened when the level reaches `incident_min_level` (or on any
  canary hit) and correlates subsequent alerts within a merge window, accumulating
  affected files, directories and processes and tracking the peak risk.

## Response actions and the approval workflow

Each action is a `ResponseAction` row with a status lifecycle:

```
pending_approval ─approve─► approved ─► executing ─► completed ─► (rolled_back)
       │                                                   └────► failed
       └─reject─► rejected        └─(timeout)─► expired
```

- **Reversible actions** (`suspend_process`, `protect_directory`) record rollback
  data so they can be undone (`resume_process`, restore directory permissions).
  They may run automatically only when explicitly configured
  (`auto_protect_directories`, `auto_suspend_on_canary`).
- **Irreversible / high-impact actions** (`terminate_process`, live
  `isolate_network`) are always created as `pending_approval` and run only after an
  authorised approval. Network isolation defaults to **dry-run** (records intent
  without cutting the network).
- Approval/rejection/rollback is issued from the dashboard (admin role) and
  delivered to the agent as an **Ed25519-signed command**; the agent verifies the
  signature before executing. Manual containment from the Incident page works the
  same way.

## Evidence preservation (`agent/response/evidence.py`)

On PROTECT and above, affected files are copied read-only into a tamper-evident
vault with per-file SHA-256 and an HMAC-signed manifest. Collection is bounded by
file-count and byte budgets and **never modifies the originals**. Process metadata
is preserved before any containment action (including before termination, which is
irreversible). `verify_manifest` later proves the vault is intact.

## Recovery (`agent/response/recovery.py`)

- **Snapshots**: point-in-time copies of a protected directory with an HMAC-signed
  manifest of file hashes.
- **Verification**: a snapshot is used for restore only after its signature and
  every file hash verify — a corrupted or tampered snapshot is refused.
- **Restore**: compares the live directory against the verified snapshot and
  restores missing/changed files, reporting exactly what it changed. Restore is an
  explicit, authorised action (CLI or approved command), never automatic. A dry-run
  mode lists what *would* be restored.

## Analyst workflow (dashboard)

1. **Command Center / Threat Detection** surfaces the rising risk and the signal
   breakdown.
2. **Incident Response** shows the incident, affected files/processes, preserved
   evidence and queued actions.
3. The analyst acknowledges, approves or rejects containment actions, and resolves
   the incident; every step is written to the tamper-evident audit log.
4. If data was damaged, **Settings/CLI** can create or restore from a verified
   snapshot.
