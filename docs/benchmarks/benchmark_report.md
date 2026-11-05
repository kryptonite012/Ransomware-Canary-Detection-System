# PROJECT SENTINEL - Detection Benchmark Report

_Generated 2026-11-05T23:01:42.911853+00:00_

## Summary

| Metric | Value |
| --- | --- |
| Detection rate (malicious scenarios) | **100%** |
| False-positive rate (benign scenarios) | **0%** |
| Mean detection latency | 0.05s |
| Event throughput | 4 events/s |
| Canary detection reliability | 100% |
| Peak agent CPU | 91.5% |
| Peak agent memory | 106.6 MB |

## Scenarios

| Scenario | Type | Files | Detected | Peak risk | Latency | Result |
| --- | --- | --- | --- | --- | --- | --- |
| benign_activity | benign | 15 | False | 25 (low) | — | ✅ |
| mass_modification | malicious | 41 | True | 100 (critical) | 0.11s | ✅ |
| extension_rename | malicious | 41 | True | 100 (critical) | 0.05s | ✅ |
| ransom_notes | malicious | 3 | True | 100 (critical) | 0.01s | ✅ |
| canary_modify | malicious | 6 | True | 100 (critical) | 0.02s | ✅ |

## Environment

- **platform**: Linux-6.18.44-fc-v236-x86_64-with-glibc2.39
- **python**: 3.13.18
- **cpu_count**: 4
- **filesystem_backend**: InotifyObserver

> All scenarios run inside a disposable sandbox using the safe simulator.
> No real files are encrypted or harmed.
