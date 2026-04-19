#!/usr/bin/env python3
"""
Embedding benchmark for Kiro Cortex.

Compares BM25-only vs Hybrid (BM25 + vector) retrieval quality.
Requires: binary built with --features embedding + model downloaded.

Usage:
  # Build with embedding
  cargo build --release --features embedding

  # Download model
  ./target/release/kiro-cortex memory init

  # Run benchmark
  python3 benchmarks/embedding_benchmark.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from bench_utils import build_report_metadata, describe_source

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BIN = ROOT / "target" / "release" / "kiro-cortex"
CORPUS_PATH = ROOT / "benchmarks" / "data" / "memory_corpus.json"
QUERIES_PATH = ROOT / "benchmarks" / "data" / "memory_queries.json"
SEMANTIC_CORPUS_PATH = ROOT / "benchmarks" / "data" / "semantic_memory_corpus.json"
SEMANTIC_QUERIES_PATH = ROOT / "benchmarks" / "data" / "semantic_memory_queries.json"

# Semantic queries: use different words than corpus but expect same doc_ids
SEMANTIC_QUERIES = [
    {"query": "database container orchestration", "expected_doc_id": "docker-postgres",
     "note": "semantic: docker compose postgresql → database container"},
    {"query": "cloud storage backup retention", "expected_doc_id": "s3-backups",
     "note": "semantic: S3 nightly backups → cloud storage backup"},
    {"query": "infrastructure as code provisioning", "expected_doc_id": "terraform-infra",
     "note": "semantic: terraform → infrastructure as code"},
    {"query": "payment processing webhooks", "expected_doc_id": "stripe-billing",
     "note": "semantic: stripe billing → payment processing"},
    {"query": "container deployment health checks", "expected_doc_id": "kubernetes-staging",
     "note": "semantic: kubernetes rolling updates readiness → deployment health"},
    {"query": "error tracking alerting", "expected_doc_id": "sentry-monitoring",
     "note": "semantic: sentry alerts → error tracking"},
    {"query": "authentication token management", "expected_doc_id": "auth-service-owner",
     "note": "semantic: JWT OAuth → authentication token"},
    {"query": "frontend state management library", "expected_doc_id": "react-frontend",
     "note": "semantic: zustand react query → state management"},
]


def run(cwd: Path, cmd: list[str], stdin: str | None = None) -> tuple[int, str, str, float]:
    start = time.perf_counter()
    proc = subprocess.run(cmd, cwd=str(cwd), input=stdin, text=True, capture_output=True, check=False)
    elapsed = (time.perf_counter() - start) * 1000
    return proc.returncode, proc.stdout, proc.stderr, elapsed


def write_enforce_config(cwd: Path):
    kiro = cwd / ".kiro"
    kiro.mkdir(parents=True, exist_ok=True)
    (kiro / "cortex.toml").write_text('mode = "enforce"\n')


def ingest_chunk(cortex_bin: Path, cwd: Path, session_id: str, content: str) -> tuple[int, float]:
    payload = {
        "hook_event_name": "postToolUse", "cwd": str(cwd), "session_id": session_id,
        "tool_name": "read", "tool_input": {}, "tool_response": {"content": content},
    }
    rc, _, _, ms = run(cwd, [str(cortex_bin), "hook", "post-tool"], stdin=json.dumps(payload))
    return rc, ms


def memory_search(cortex_bin: Path, cwd: Path, query: str) -> tuple[list[dict], float]:
    rc, stdout, stderr, ms = run(cwd, [str(cortex_bin), "memory", "search", query, "--format", "json"])
    try:
        results = json.loads(stdout) if stdout.strip() and stdout.strip() != "No results found." else []
    except json.JSONDecodeError:
        results = []
    return results, ms


def evaluate_queries(cortex_bin: Path, cwd: Path, queries: list[dict]) -> dict:
    hits_1 = 0
    hits_5 = 0
    rrs = []
    latencies = []
    misses = []

    for q in queries:
        results, ms = memory_search(cortex_bin, cwd, q["query"])
        latencies.append(ms)
        expected = f"[doc_id:{q['expected_doc_id']}]"
        rank = None
        for idx, item in enumerate(results[:5], start=1):
            if expected in item.get("content", ""):
                rank = idx
                break
        if rank == 1: hits_1 += 1
        if rank is not None:
            hits_5 += 1
            rrs.append(1.0 / rank)
        else:
            rrs.append(0.0)
            misses.append({"query": q["query"], "expected": q["expected_doc_id"],
                           "note": q.get("note", "")})

    n = len(queries)
    return {
        "queries": n,
        "recall_at_1": hits_1 / n if n else 0,
        "recall_at_5": hits_5 / n if n else 0,
        "mrr_at_5": sum(rrs) / n if n else 0,
        "avg_ms": sum(latencies) / n if n else 0,
        "misses": misses,
    }


def run_suite(
    name: str,
    cortex_bin: Path,
    corpus: list[dict],
    queries: list[dict],
) -> tuple[dict[str, Any], dict[str, Any]]:
    print(f"\n== {name}: BM25-only Baseline ==")
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        write_enforce_config(cwd)
        for i, doc in enumerate(corpus):
            ingest_chunk(cortex_bin, cwd, f"{name}-bm25-{i}", doc["content"])
        bm25 = evaluate_queries(cortex_bin, cwd, queries)

    print(
        f"queries={bm25['queries']} recall@1={bm25['recall_at_1']:.4f} "
        f"recall@5={bm25['recall_at_5']:.4f} mrr@5={bm25['mrr_at_5']:.4f} "
        f"avg_ms={bm25['avg_ms']:.1f}"
    )
    if bm25["misses"]:
        print("misses:")
        for m in bm25["misses"][:5]:
            print(f"  - {m['expected']}: {m['query']} ({m['note']})")

    print(f"\n== {name}: Hybrid (BM25 + Embedding) ==")
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        write_enforce_config(cwd)
        for i, doc in enumerate(corpus):
            ingest_chunk(cortex_bin, cwd, f"{name}-hybrid-{i}", doc["content"])
        hybrid = evaluate_queries(cortex_bin, cwd, queries)

    print(
        f"queries={hybrid['queries']} recall@1={hybrid['recall_at_1']:.4f} "
        f"recall@5={hybrid['recall_at_5']:.4f} mrr@5={hybrid['mrr_at_5']:.4f} "
        f"avg_ms={hybrid['avg_ms']:.1f}"
    )
    if hybrid["misses"]:
        print("misses:")
        for m in hybrid["misses"][:5]:
            print(f"  - {m['expected']}: {m['query']} ({m['note']})")

    print(f"\n== {name}: Comparison ==")
    print(f"{'Metric':<15} {'BM25':>10} {'Hybrid':>10} {'Delta':>10}")
    print("-" * 50)
    for metric in ["recall_at_1", "recall_at_5", "mrr_at_5"]:
        b = bm25[metric]
        h = hybrid[metric]
        d = h - b
        print(f"{metric:<15} {b:>10.4f} {h:>10.4f} {d:>+10.4f}")
    print(f"{'avg_ms':<15} {bm25['avg_ms']:>10.1f} {hybrid['avg_ms']:>10.1f} {hybrid['avg_ms'] - bm25['avg_ms']:>+10.1f}")

    return bm25, hybrid


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Embedding benchmark for Kiro Cortex")
    parser.add_argument("--cortex-bin", default=str(DEFAULT_BIN))
    parser.add_argument("--json-out", default="")
    args = parser.parse_args()

    cortex_bin = Path(args.cortex_bin).resolve()
    if not cortex_bin.exists():
        print(f"error: binary not found at {cortex_bin}", file=sys.stderr)
        return 2

    # Check if embedding is available
    rc, stdout, stderr, _ = run(Path("."), [str(cortex_bin), "memory", "init"])
    if rc != 0 and "not available" in stderr.lower():
        print("error: binary not built with --features embedding", file=sys.stderr)
        print("Run: cargo build --release --features embedding", file=sys.stderr)
        return 2

    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    base_queries = json.loads(QUERIES_PATH.read_text(encoding="utf-8"))
    all_queries = base_queries + SEMANTIC_QUERIES
    semantic_corpus = json.loads(SEMANTIC_CORPUS_PATH.read_text(encoding="utf-8"))
    semantic_queries = json.loads(SEMANTIC_QUERIES_PATH.read_text(encoding="utf-8"))

    bm25, hybrid = run_suite("Curated Corpus", cortex_bin, corpus, all_queries)
    semantic_bm25, semantic_hybrid = run_suite("Semantic Stress Corpus", cortex_bin, semantic_corpus, semantic_queries)

    # --- Reindex benchmark ---
    print("\n== Reindex Benchmark ==")
    reindex_result = {}
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        write_enforce_config(cwd)
        # Ingest chunks WITHOUT embedding (simulate pre-embedding data)
        for i, doc in enumerate(corpus):
            ingest_chunk(cortex_bin, cwd, f"reindex-{i}", doc["content"])
        # Now reindex
        start_t = time.perf_counter()
        rc, stdout, stderr, reindex_ms = run(cwd, [str(cortex_bin), "memory", "reindex"])
        reindex_result = {
            "chunks": len(corpus),
            "reindex_ms": reindex_ms,
            "chunks_per_sec": (len(corpus) / (reindex_ms / 1000.0)) if reindex_ms else 0,
            "output": stdout.strip(),
        }
        # Retrieval quality AFTER reindex
        post_reindex = evaluate_queries(cortex_bin, cwd, all_queries)
        reindex_result["recall_at_5_after"] = post_reindex["recall_at_5"]
        reindex_result["mrr_at_5_after"] = post_reindex["mrr_at_5"]

    print(f"chunks={reindex_result['chunks']} reindex_ms={reindex_result['reindex_ms']:.1f} "
          f"chunks/s={reindex_result['chunks_per_sec']:.1f}")
    print(f"recall@5 after reindex={reindex_result['recall_at_5_after']:.4f} "
          f"mrr@5={reindex_result['mrr_at_5_after']:.4f}")

    report = {
        **build_report_metadata(
            cortex_bin,
            rounds=1,
            warmup_runs=0,
            dataset_mode="custom",
            sample_size=len(corpus),
            config={"base_queries": len(base_queries), "semantic_queries": len(SEMANTIC_QUERIES)},
            datasets=[
                describe_source("memory_corpus", path=CORPUS_PATH),
                describe_source("memory_queries", path=QUERIES_PATH),
                describe_source("semantic_memory_corpus", path=SEMANTIC_CORPUS_PATH),
                describe_source("semantic_memory_queries", path=SEMANTIC_QUERIES_PATH),
            ],
        ),
        "bm25": bm25,
        "hybrid": hybrid,
        "semantic_stress_bm25": semantic_bm25,
        "semantic_stress_hybrid": semantic_hybrid,
        "reindex": reindex_result,
        "semantic_queries_count": len(SEMANTIC_QUERIES),
        "base_queries_count": len(base_queries),
        "semantic_stress_queries_count": len(semantic_queries),
    }

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nWrote JSON report to {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
