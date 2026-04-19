#!/usr/bin/env python3
"""
Public benchmark harness for Kiro Cortex.

This script benchmarks two detector families against public corpora:
1. Prompt injection detection:
   - Giskard prompt-injections
   - WAInjectBench (text-only subset)
2. Secret detection:
   - Curated public test vectors from Yelp/detect-secrets plugin tests

Requirements:
  - A built `kiro-cortex` binary, default: ./target/release/kiro-cortex
  - Network access on the first run to download/cache public corpora

Examples:
  python3 benchmarks/public_benchmark.py --mode all
  python3 benchmarks/public_benchmark.py --mode injection --json-out /tmp/cortex-bench.json
  python3 benchmarks/public_benchmark.py --mode secrets --cortex-bin ./target/release/kiro-cortex
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.error import URLError
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from bench_utils import build_report_metadata, describe_source


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BIN = ROOT / "target" / "release" / "kiro-cortex"
CACHE_DIR = ROOT / "benchmarks" / ".cache"

GISKARD_URL = (
    "https://raw.githubusercontent.com/Giskard-AI/prompt-injections/main/"
    "prompt_injections.csv"
)
WA_BENIGN_URLS = {
    "email_msg": (
        "https://raw.githubusercontent.com/Norrrrrrr-lyn/WAInjectBench/main/"
        "data/text/benign/email_msg.jsonl"
    ),
    "comment_issue": (
        "https://raw.githubusercontent.com/Norrrrrrr-lyn/WAInjectBench/main/"
        "data/text/benign/comment_issue.jsonl"
    ),
}
WA_MALICIOUS_URLS = {
    "popup": (
        "https://raw.githubusercontent.com/Norrrrrrr-lyn/WAInjectBench/main/"
        "data/text/malicious/popup.jsonl"
    ),
    "wasp": (
        "https://raw.githubusercontent.com/Norrrrrrr-lyn/WAInjectBench/main/"
        "data/text/malicious/wasp.jsonl"
    ),
}


@dataclass
class Case:
    suite: str
    label: int
    text: str
    meta: str


@dataclass
class Result:
    suite: str
    label: int
    pred: int
    rc: int
    latency_ms: float
    meta: str
    text_preview: str


def ensure_cache_dir() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def download_to_cache(name: str, url: str) -> Path:
    ensure_cache_dir()
    path = CACHE_DIR / name
    if path.exists():
        return path
    try:
        with urllib.request.urlopen(url) as resp:
            path.write_bytes(resp.read())
    except URLError as exc:
        raise RuntimeError(
            f"failed to download {url}. "
            f"Run once with network access or pre-seed {path}."
        ) from exc
    return path


def sample_jsonl(path: Path, label: int, suite: str, sample_size: int | None) -> list[Case]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            rows.append(Case(suite=suite, label=label, text=obj["text"], meta=path.name))
    if sample_size is not None and len(rows) > sample_size:
        rows = random.sample(rows, sample_size)
    return rows


def preview(text: str, limit: int = 120) -> str:
    flat = text.replace("\n", " ").strip()
    return flat[:limit] + ("..." if len(flat) > limit else "")


def summarize(results: list[Result]) -> dict[str, Any]:
    tp = sum(1 for r in results if r.label == 1 and r.pred == 1)
    tn = sum(1 for r in results if r.label == 0 and r.pred == 0)
    fp = sum(1 for r in results if r.label == 0 and r.pred == 1)
    fn = sum(1 for r in results if r.label == 1 and r.pred == 0)
    total = len(results)
    avg_ms = statistics.mean(r.latency_ms for r in results) if results else 0.0
    p95_ms = sorted(r.latency_ms for r in results)[int(0.95 * (total - 1))] if results else 0.0
    return {
        "total": total,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": (tp / (tp + fp)) if (tp + fp) else 0.0,
        "recall": (tp / (tp + fn)) if (tp + fn) else 0.0,
        "false_positive_rate": (fp / (fp + tn)) if (fp + tn) else 0.0,
        "accuracy": ((tp + tn) / total) if total else 0.0,
        "avg_ms": avg_ms,
        "p95_ms": p95_ms,
    }


def run_post_tool(cortex_bin: Path, cwd: str, session_id: str, text: str) -> tuple[int, float]:
    payload = {
        "hook_event_name": "postToolUse",
        "cwd": cwd,
        "session_id": session_id,
        "tool_name": "benchmark",
        "tool_input": {},
        "tool_response": {"body": text},
    }
    start = time.perf_counter()
    proc = subprocess.run(
        [str(cortex_bin), "hook", "post-tool"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    return proc.returncode, elapsed_ms


def run_injection_benchmark(
    cortex_bin: Path,
    benign_sample: int,
    malicious_sample: int,
) -> dict[str, Any]:
    random.seed(0)
    cases: list[Case] = []

    giskard_csv = download_to_cache("giskard_prompt_injections.csv", GISKARD_URL)
    with giskard_csv.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cases.append(
                Case(
                    suite="Giskard",
                    label=1,
                    text=row["prompt"],
                    meta=row.get("group") or row.get("name") or "giskard",
                )
            )

    for name, url in WA_MALICIOUS_URLS.items():
        path = download_to_cache(f"wa_{name}.jsonl", url)
        cases.extend(sample_jsonl(path, 1, "WAInjectBench-malicious", malicious_sample))

    for name, url in WA_BENIGN_URLS.items():
        path = download_to_cache(f"wa_{name}.jsonl", url)
        cases.extend(sample_jsonl(path, 0, "WAInjectBench-benign", benign_sample))

    results: list[Result] = []
    with tempfile.TemporaryDirectory() as tmp:
        kiro = Path(tmp) / ".kiro"
        kiro.mkdir(parents=True, exist_ok=True)
        (kiro / "cortex.toml").write_text(
            'mode = "enforce"\n[injection]\nenable_tier1 = true\n',
            encoding="utf-8",
        )
        for idx, case in enumerate(cases):
            rc, elapsed_ms = run_post_tool(cortex_bin, tmp, f"injection-{idx}", case.text)
            results.append(
                Result(
                    suite=case.suite,
                    label=case.label,
                    pred=1 if rc == 1 else 0,
                    rc=rc,
                    latency_ms=elapsed_ms,
                    meta=case.meta,
                    text_preview=preview(case.text),
                )
            )

    by_suite = {
        suite: summarize([r for r in results if r.suite == suite])
        for suite in sorted({r.suite for r in results})
    }
    false_negatives = [asdict(r) for r in results if r.label == 1 and r.pred == 0][:10]
    false_positives = [asdict(r) for r in results if r.label == 0 and r.pred == 1][:10]
    return {
        "suite": "prompt_injection",
        "summary": summarize(results),
        "by_suite": by_suite,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "cases": len(results),
    }


def public_secret_cases() -> list[Case]:
    # Curated public test vectors from Yelp/detect-secrets plugin tests.
    return [
        Case(
            suite="detect-secrets",
            label=1,
            text="sk-" + "NOT-A-REAL-KEY-JUST-A-TEST-FIXTURE-0000000000",
            meta="openai_test.py:positive",
        ),
        Case(
            suite="detect-secrets",
            label=1,
            text="sk-proj-TESTKEY00000000000000000000000000000000000000",
            meta="openai_test.py:positive",
        ),
        Case(
            suite="detect-secrets",
            label=0,
            text="sk-proj-TESTKEY11111111111111111111111111111111111111",
            meta="openai_test.py:negative",
        ),
        Case(
            suite="detect-secrets",
            label=1,
            text="AKIAZZZZZZZZZZZZZZZZ",
            meta="aws_key_test.py:positive",
        ),
        Case(
            suite="detect-secrets",
            label=1,
            text="A3T0ZZZZZZZZZZZZZZZZ",
            meta="aws_key_test.py:positive",
        ),
        Case(
            suite="detect-secrets",
            label=1,
            text="ASIAZZZZZZZZZZZZZZZZ",
            meta="aws_key_test.py:positive",
        ),
        Case(
            suite="detect-secrets",
            label=1,
            text="aws_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
            meta="aws_key_test.py:positive",
        ),
        Case(
            suite="detect-secrets",
            label=0,
            text="akiazzzzzzzzzzzzzzzz",
            meta="aws_key_test.py:negative",
        ),
        Case(
            suite="detect-secrets",
            label=0,
            text="AKIAZZZ",
            meta="aws_key_test.py:negative",
        ),
        Case(
            suite="detect-secrets",
            label=0,
            text="aws_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYa\"",
            meta="aws_key_test.py:negative",
        ),
        Case(
            suite="detect-secrets",
            label=1,
            text="ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
            meta="github_token_test.py:positive",
        ),
        Case(
            suite="detect-secrets",
            label=0,
            text="foo_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx",
            meta="github_token_test.py:negative",
        ),
        Case(
            suite="detect-secrets",
            label=1,
            text="sk_" + "live_00000000NOTREAL00000000",
            meta="stripe_key_test.py:positive",
        ),
        Case(
            suite="detect-secrets",
            label=1,
            text="rk_" + "live_00000000NOTREAL00000000",
            meta="stripe_key_test.py:positive",
        ),
        Case(
            suite="detect-secrets",
            label=0,
            text="pk_live_j5krY8XTgIcDaHDb3YrsAfCl",
            meta="stripe_key_test.py:negative",
        ),
        Case(
            suite="detect-secrets",
            label=1,
            text=(
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "super secret private key here\n"
                "-----END RSA PRIVATE KEY-----"
            ),
            meta="private_key_test.py:positive",
        ),
        Case(
            suite="detect-secrets",
            label=1,
            text="some text here\n-----BEGIN PRIVATE KEY-----\nyabba dabba doo",
            meta="private_key_test.py:positive",
        ),
        Case(
            suite="detect-secrets",
            label=0,
            text="public_key = ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCexample",
            meta="synthetic-negative",
        ),
    ]


def run_secret_benchmark(cortex_bin: Path) -> dict[str, Any]:
    results: list[Result] = []
    cases = public_secret_cases()
    with tempfile.TemporaryDirectory() as tmp:
        kiro = Path(tmp) / ".kiro"
        kiro.mkdir(parents=True, exist_ok=True)
        (kiro / "cortex.toml").write_text('mode = "enforce"\n', encoding="utf-8")
        for idx, case in enumerate(cases):
            rc, elapsed_ms = run_post_tool(cortex_bin, tmp, f"secret-{idx}", case.text)
            results.append(
                Result(
                    suite=case.suite,
                    label=case.label,
                    pred=1 if rc == 1 else 0,
                    rc=rc,
                    latency_ms=elapsed_ms,
                    meta=case.meta,
                    text_preview=preview(case.text),
                )
            )
    false_negatives = [asdict(r) for r in results if r.label == 1 and r.pred == 0][:10]
    false_positives = [asdict(r) for r in results if r.label == 0 and r.pred == 1][:10]
    return {
        "suite": "secret_detection",
        "summary": summarize(results),
        "by_suite": {"detect-secrets": summarize(results)},
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "cases": len(results),
    }


def print_summary(name: str, data: dict[str, Any]) -> None:
    summary = data["summary"]
    print(f"\n== {name} ==")
    print(
        f"cases={summary['total']} tp={summary['tp']} tn={summary['tn']} "
        f"fp={summary['fp']} fn={summary['fn']}"
    )
    print(
        f"precision={summary['precision']:.4f} "
        f"recall={summary['recall']:.4f} "
        f"fpr={summary['false_positive_rate']:.4f} "
        f"avg_ms={summary['avg_ms']:.1f} "
        f"p95_ms={summary['p95_ms']:.1f}"
    )

    if data["false_negatives"]:
        print("sample_false_negatives:")
        for item in data["false_negatives"][:5]:
            print(f"  - {item['meta']}: {item['text_preview']}")
    if data["false_positives"]:
        print("sample_false_positives:")
        for item in data["false_positives"][:5]:
            print(f"  - {item['meta']}: {item['text_preview']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run public benchmarks for Kiro Cortex")
    parser.add_argument(
        "--mode",
        choices=["all", "injection", "secrets"],
        default="all",
        help="Which benchmark family to run.",
    )
    parser.add_argument(
        "--cortex-bin",
        default=str(DEFAULT_BIN),
        help="Path to kiro-cortex binary.",
    )
    parser.add_argument(
        "--wa-benign-sample",
        type=int,
        default=20,
        help="Per-file benign sample size from WAInjectBench.",
    )
    parser.add_argument(
        "--wa-malicious-sample",
        type=int,
        default=40,
        help="Per-file malicious sample size from WAInjectBench.",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional path to write JSON results.",
    )
    args = parser.parse_args()

    cortex_bin = Path(args.cortex_bin).resolve()
    if not cortex_bin.exists():
        print(f"error: kiro-cortex binary not found at {cortex_bin}", file=sys.stderr)
        return 2

    payload: dict[str, Any] = {
        **build_report_metadata(
            cortex_bin,
            rounds=1,
            warmup_runs=0,
            config={
                "mode": args.mode,
                "wa_benign_sample_per_file": args.wa_benign_sample,
                "wa_malicious_sample_per_file": args.wa_malicious_sample,
            },
            datasets=[
                describe_source(
                    "giskard_prompt_injections",
                    GISKARD_URL,
                    CACHE_DIR / "giskard_prompt_injections.csv",
                ),
                describe_source(
                    "wainjectbench_benign_email_msg",
                    WA_BENIGN_URLS["email_msg"],
                    CACHE_DIR / "wa_email_msg.jsonl",
                ),
                describe_source(
                    "wainjectbench_benign_comment_issue",
                    WA_BENIGN_URLS["comment_issue"],
                    CACHE_DIR / "wa_comment_issue.jsonl",
                ),
                describe_source(
                    "wainjectbench_malicious_popup",
                    WA_MALICIOUS_URLS["popup"],
                    CACHE_DIR / "wa_popup.jsonl",
                ),
                describe_source(
                    "wainjectbench_malicious_wasp",
                    WA_MALICIOUS_URLS["wasp"],
                    CACHE_DIR / "wa_wasp.jsonl",
                ),
                describe_source(
                    "detect_secrets_plugin_tests",
                    "https://github.com/Yelp/detect-secrets/tree/master/tests/plugins",
                ),
            ],
        ),
        "results": {},
    }

    if args.mode in ("all", "injection"):
        payload["results"]["injection"] = run_injection_benchmark(
            cortex_bin,
            benign_sample=args.wa_benign_sample,
            malicious_sample=args.wa_malicious_sample,
        )
        print_summary("Prompt Injection", payload["results"]["injection"])

    if args.mode in ("all", "secrets"):
        payload["results"]["secrets"] = run_secret_benchmark(cortex_bin)
        print_summary("Secret Detection", payload["results"]["secrets"])

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nWrote JSON report to {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
