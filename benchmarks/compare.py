#!/usr/bin/env python3
"""
Compare two Kiro Cortex benchmark JSON reports.

Usage:
  python3 benchmarks/compare.py benchmarks/baseline.json benchmarks/latest-public-benchmark.json
  python3 benchmarks/compare.py --before run1/ --after run2/   # compare all matching reports
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def flatten(d: dict, prefix: str = "") -> dict[str, float]:
    """Flatten nested dict to dot-separated keys, keeping only numeric values."""
    out = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            out[key] = float(v)
        elif isinstance(v, dict):
            out.update(flatten(v, key))
    return out


def compare(before: dict, after: dict) -> list[dict]:
    fb = flatten(before)
    fa = flatten(after)
    all_keys = sorted(set(fb) | set(fa))

    rows = []
    for k in all_keys:
        b = fb.get(k)
        a = fa.get(k)
        if b is None or a is None:
            rows.append({"metric": k, "before": b, "after": a, "delta": None, "pct": None})
            continue
        delta = a - b
        pct = (delta / b * 100) if b != 0 else None
        rows.append({"metric": k, "before": b, "after": a, "delta": delta, "pct": pct})
    return rows


def format_table(rows: list[dict], title: str = "") -> str:
    lines = []
    if title:
        lines.append(f"\n## {title}\n")
    lines.append(f"| {'Metric':<45} | {'Before':>10} | {'After':>10} | {'Delta':>10} | {'%':>8} |")
    lines.append(f"|{'-'*47}|{'-'*12}|{'-'*12}|{'-'*12}|{'-'*10}|")

    for r in rows:
        b = f"{r['before']:.4f}" if r['before'] is not None else "—"
        a = f"{r['after']:.4f}" if r['after'] is not None else "—"
        d = f"{r['delta']:+.4f}" if r['delta'] is not None else "—"
        p = f"{r['pct']:+.1f}%" if r['pct'] is not None else "—"
        lines.append(f"| {r['metric']:<45} | {b:>10} | {a:>10} | {d:>10} | {p:>8} |")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare two benchmark JSON reports")
    parser.add_argument("before", help="Path to baseline JSON report")
    parser.add_argument("after", help="Path to new JSON report")
    parser.add_argument("--only-changed", action="store_true", help="Only show metrics that changed")
    parser.add_argument("--threshold", type=float, default=0.0, help="Min absolute delta to show")
    args = parser.parse_args()

    before = json.loads(Path(args.before).read_text(encoding="utf-8"))
    after = json.loads(Path(args.after).read_text(encoding="utf-8"))

    # Show metadata
    print(f"Before: {before.get('generated_at', '?')} — {Path(args.before).name}")
    print(f"After:  {after.get('generated_at', '?')} — {Path(args.after).name}")

    rows = compare(before, after)

    if args.only_changed:
        rows = [r for r in rows if r["delta"] is not None and abs(r["delta"]) > args.threshold]

    if not rows:
        print("\nNo differences found.")
        return 0

    # Group by top-level key
    groups: dict[str, list[dict]] = {}
    for r in rows:
        group = r["metric"].split(".")[0]
        groups.setdefault(group, []).append(r)

    for group, group_rows in groups.items():
        print(format_table(group_rows, group))

    # Summary: highlight significant changes
    significant = [r for r in rows if r["pct"] is not None and abs(r["pct"]) > 5]
    if significant:
        print(f"\n### Significant changes (>5%):")
        for r in sorted(significant, key=lambda x: abs(x["pct"] or 0), reverse=True):
            emoji = "📈" if (r["delta"] or 0) > 0 else "📉"
            print(f"  {emoji} {r['metric']}: {r['before']:.4f} → {r['after']:.4f} ({r['pct']:+.1f}%)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
