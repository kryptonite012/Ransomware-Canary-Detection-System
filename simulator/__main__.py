"""Safe ransomware simulator CLI.

Everything runs inside a disposable sandbox the tool creates and marks. It will
refuse to operate on any directory it did not create (missing marker), so it can
never touch real data.

    python -m simulator create                 # create a sandbox
    python -m simulator run <scenario> [path]  # run one scenario in the sandbox
    python -m simulator attack [path]          # run the full attack sequence
    python -m simulator benchmark              # run the detection benchmark + report
    python -m simulator destroy <path>         # delete a sandbox
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from simulator import scenarios
from simulator.sandbox import Sandbox, SandboxError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-simulator",
                                     description="Safe, sandbox-only ransomware behaviour simulator")
    parser.add_argument("--base", default="./sandbox", help="base directory for sandboxes")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("create")
    r = sub.add_parser("run"); r.add_argument("scenario", choices=sorted(scenarios.SCENARIOS))
    r.add_argument("path", nargs="?")
    a = sub.add_parser("attack"); a.add_argument("path", nargs="?")
    b = sub.add_parser("benchmark"); b.add_argument("--output", default="./benchmark-results")
    d = sub.add_parser("destroy"); d.add_argument("path")
    args = parser.parse_args(argv)

    try:
        if args.command == "create":
            sb = Sandbox.create(Path(args.base))
            scenarios.populate_benign(sb)
            print(f"sandbox ready: {sb.path}")
            return 0
        if args.command == "destroy":
            Sandbox.attach(Path(args.path)).destroy()
            print(f"destroyed {args.path}")
            return 0
        if args.command == "run":
            sb = Sandbox.attach(Path(args.path)) if args.path else Sandbox.create(Path(args.base))
            if not args.path:
                scenarios.populate_benign(sb)
            result = scenarios.SCENARIOS[args.scenario](sb)
            print(f"{result.name}: {result.files_touched} files in {result.duration_seconds:.2f}s "
                  f"(sandbox {sb.path})")
            return 0
        if args.command == "attack":
            sb = Sandbox.attach(Path(args.path)) if args.path else Sandbox.create(Path(args.base))
            scenarios.populate_benign(sb)
            print(f"[*] sandbox {sb.path}")
            for name in ("mass_modification", "extension_rename", "ransom_notes", "canary_modify"):
                res = scenarios.SCENARIOS[name](sb)
                print(f"    {res.name}: {res.files_touched} files")
            print("[+] attack sequence complete (sandbox only)")
            return 0
        if args.command == "benchmark":
            from simulator.benchmark import run_benchmark
            report = run_benchmark(Path(args.base), Path(args.output))
            print(f"detection rate   : {report.detection_rate:.0%}")
            print(f"false positives  : {report.false_positive_rate:.0%}")
            print(f"mean latency     : "
                  + (f"{report.mean_latency_seconds:.2f}s" if report.mean_latency_seconds else "n/a"))
            print(f"canary reliability: {report.canary_reliability:.0%}")
            print(f"report written to {args.output}/benchmark_report.md")
            return 0
    except SandboxError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
