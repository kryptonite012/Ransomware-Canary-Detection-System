# Detection Engine

SENTINEL combines four independent detection mechanisms and fuses them into a
single explainable risk score. The design goal is **early detection with a low
false-positive rate**: no single signal is trusted to be decisive on its own
(except a canary hit), and corroboration between independent signals is what
drives the score into actionable territory.

## 1. Entropy analysis (`agent/entropy/`)

Encrypted data has ~8 bits/byte of entropy — but so do ZIP, JPEG, MP4 and other
compressed formats. A naive "entropy > 7.5 ⇒ ransomware" rule produces constant
false positives. SENTINEL uses three complementary ideas:

- **File-type baseline.** Each extension maps to a category with an
  `expected_high_entropy` flag. High entropy in a `.zip` is normal; high entropy
  in a `.txt`/`.csv`/`.docx` is not.
- **History delta.** The analyzer keeps the previous entropy per file. The classic
  encryption signature is a file that *was* structured (low/medium entropy) and
  suddenly becomes near-random. The delta, not the absolute value, is the signal.
- **Structure / magic check.** Encryption destroys file headers. A `.pdf` that no
  longer starts with `%PDF`, or a `.docx` that is no longer a ZIP, is suspicious
  regardless of the exact entropy number.

Other properties: chunked analysis (catches partial/intermittent encryption),
configurable minimum file size, an LRU cache keyed on `(mtime, size)` so unchanged
files are never re-read, and a token-bucket rate limiter. Shannon entropy is
computed with NumPy over byte-frequency distributions.

Signals emitted: `entropy_spike` (sudden high-entropy transformation),
`magic_mismatch` (header destroyed).

## 2. Canary detection (`agent/canary/`)

Canary files are realistic but entirely synthetic decoys (e.g.
`Financial_Records_Canary.xlsx`, `Employee_Database_Canary.csv`). No legitimate
user or application has a reason to open, modify, rename or delete them, so any
interaction is a high-confidence signal.

- Content is generated per-file with a seed so each deployment is unique; a guard
  (`assert_no_secrets`) ensures a canary never contains anything that looks like a
  real credential or key.
- Generated files are structurally valid for their type (valid OOXML ZIP, valid
  PDF, etc.) so they survive an attacker's file-type filter.
- Detection is dual: **event-driven** (sub-second reaction to modify/rename/delete)
  and **periodic hash verification** (catches events dropped under load or missed
  by the OS). The agent stores the authoritative SHA-256 of each canary.
- The agent's own writes during deployment/regeneration are suppressed via a
  self-write guard so they are never mistaken for tampering.
- Auto-regeneration restores a canary shortly after it is triggered.

Signals: `canary_modified`, `canary_deleted`, `canary_renamed`, `canary_accessed`,
`multiple_canaries` (≥2 distinct canaries touched).

## 3. Behavioural detection (`agent/behavior/`)

Sliding time-windows over change events detect the *shape* of a ransomware run:

| Signal | Trigger |
| --- | --- |
| `rapid_mass_modification` | ≥ N files modified within the window |
| `directory_spread` | mass modification spanning ≥ N directories |
| `mass_deletion` | ≥ N deletions within the window |
| `suspicious_extension_change` | ≥ N extension changes (weighted up for known ransomware extensions) |
| `file_replacement` | documents replaced with a different extension |
| `repeated_rewrites` | many files rewritten several times rapidly |
| `ransom_note` | creation of files matching ransom-note name/extension heuristics |
| `baseline_deviation` | change rate exceeds this endpoint's learned normal (Welford mean/variance, σ-based) |

All thresholds are configurable; a per-signal cooldown prevents one burst from
emitting the same signal repeatedly.

## 4. Process attribution (`agent/telemetry/`)

Most cross-platform FS notification APIs do not report the responsible PID. Where
privileged adapters are unavailable, SENTINEL uses **I/O correlation**: a sampling
thread tracks each process's `write_bytes` rate; the most likely author of a burst
is the process dominating disk writes. Results are tagged `attribution=io_correlation`
so a heuristic is never presented as ground truth. Processes crossing file-count
or write-rate thresholds raise `suspicious_process` (critical OS processes on an
allow-list are never flagged).

## Risk scoring (`agent/detection/risk.py`)

Signals are fused into a 0–100 score:

- Each active signal contributes its configurable **base weight once**; repeats add
  a small, capped increment (no unbounded inflation from duplicates).
- A **correlation bonus** is added when ≥2 *distinct* signal types are active —
  several independent indicators at once is far more telling than any one alone.
- Signals **decay** after a TTL, so the score returns to normal once activity stops.
- Every score carries the full list of contributing signals and the points each
  added, which is exactly what the dashboard's Threat Detection page renders.

Default weights (configurable via signed policy):

| Signal | Weight |
| --- | --- |
| canary_modified / _deleted / _renamed | 50 |
| ransom_note | 30 |
| rapid_mass_modification | 20 |
| suspicious_process | 20 |
| multiple_canaries / canary_accessed | 20 |
| entropy_spike / magic_mismatch / suspicious_extension_change | 15 |
| mass_deletion / file_replacement | 15 |
| directory_spread / baseline_deviation | 10 |
| repeated_rewrites | 5 |

Risk levels: 0–19 normal, 20–39 low, 40–59 elevated, 60–79 high, 80–100 critical.

## Tuning

Everything above is configurable through `config/sentinel.yaml` (defaults) or a
signed policy published from the dashboard. See [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md)
for how risk levels map to response actions, and the
[benchmark report](benchmarks/benchmark_report.md) for measured accuracy.
