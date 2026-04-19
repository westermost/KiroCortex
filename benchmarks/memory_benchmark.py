#!/usr/bin/env python3
"""
Memory benchmark for Kiro Cortex.

Measures:
1. Retrieval quality on a curated corpus with ground-truth queries.
2. Storage/search/forget latency on a larger synthetic corpus.
3. Session injection quality for AgentSpawn/UserPromptSubmit.
4. CLI import throughput and resulting memory stats.

Examples:
  python3 benchmarks/memory_benchmark.py
  python3 benchmarks/memory_benchmark.py --storage-count 1000 --json-out benchmarks/latest-memory-benchmark.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import sys

sys.path.insert(0, str(Path(__file__).parent))
from bench_utils import build_report_metadata, describe_source


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BIN = ROOT / "target" / "release" / "kiro-cortex"
CORPUS_PATH = ROOT / "benchmarks" / "data" / "memory_corpus.json"
QUERIES_PATH = ROOT / "benchmarks" / "data" / "memory_queries.json"


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(p * (len(ordered) - 1))
    return ordered[idx]


def run(cwd: Path, cmd: list[str], stdin: str | None = None) -> tuple[int, str, str, float]:
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    return proc.returncode, proc.stdout, proc.stderr, elapsed_ms


def write_enforce_config(project_dir: Path) -> None:
    kiro = project_dir / ".kiro"
    kiro.mkdir(parents=True, exist_ok=True)
    (kiro / "cortex.toml").write_text(
        'mode = "enforce"\n[memory]\nenabled = true\nauto_inject = true\n',
        encoding="utf-8",
    )


def ingest_chunk(cortex_bin: Path, cwd: Path, session_id: str, text: str) -> tuple[int, float]:
    payload = {
        "hook_event_name": "postToolUse",
        "cwd": str(cwd),
        "session_id": session_id,
        "tool_name": "memory-benchmark",
        "tool_input": {},
        "tool_response": {"body": text},
    }
    rc, _stdout, _stderr, elapsed_ms = run(
        cwd,
        [str(cortex_bin), "hook", "post-tool"],
        stdin=json.dumps(payload),
    )
    return rc, elapsed_ms


def memory_search(cortex_bin: Path, cwd: Path, query: str) -> tuple[list[dict[str, Any]], float]:
    rc, stdout, stderr, elapsed_ms = run(
        cwd,
        [str(cortex_bin), "memory", "search", query, "--format", "json"],
    )
    if rc != 0:
        raise RuntimeError(f"memory search failed: {stderr or stdout}")
    text = stdout.strip()
    if text == "No results found.":
        data = []
    else:
        data = json.loads(text)
    return data, elapsed_ms


def memory_stats(cortex_bin: Path, cwd: Path) -> tuple[str, float]:
    rc, stdout, stderr, elapsed_ms = run(cwd, [str(cortex_bin), "memory", "stats"])
    if rc != 0:
        raise RuntimeError(f"memory stats failed: {stderr or stdout}")
    return stdout, elapsed_ms


def memory_forget(cortex_bin: Path, cwd: Path, before: str) -> tuple[str, float]:
    rc, stdout, stderr, elapsed_ms = run(
        cwd,
        [str(cortex_bin), "memory", "forget", "--before", before],
    )
    if rc != 0:
        raise RuntimeError(f"memory forget failed: {stderr or stdout}")
    return stdout, elapsed_ms


def hook_spawn(cortex_bin: Path, cwd: Path, session_id: str) -> tuple[int, str, float]:
    payload = {
        "hook_event_name": "agentSpawn",
        "cwd": str(cwd),
        "session_id": session_id,
    }
    rc, stdout, _stderr, elapsed_ms = run(
        cwd,
        [str(cortex_bin), "hook", "spawn"],
        stdin=json.dumps(payload),
    )
    return rc, stdout, elapsed_ms


def hook_prompt(cortex_bin: Path, cwd: Path, session_id: str, prompt: str) -> tuple[int, str, float]:
    payload = {
        "hook_event_name": "userPromptSubmit",
        "cwd": str(cwd),
        "session_id": session_id,
        "prompt": prompt,
    }
    rc, stdout, _stderr, elapsed_ms = run(
        cwd,
        [str(cortex_bin), "hook", "prompt"],
        stdin=json.dumps(payload),
    )
    return rc, stdout, elapsed_ms


def evaluate_retrieval(cortex_bin: Path, corpus: list[dict[str, str]], queries: list[dict[str, str]]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        write_enforce_config(cwd)

        ingest_latencies = []
        for i, doc in enumerate(corpus):
            rc, elapsed_ms = ingest_chunk(cortex_bin, cwd, f"quality-{i}", doc["content"])
            if rc not in (0, 1):
                raise RuntimeError(f"unexpected rc={rc} during ingest for {doc['id']}")
            ingest_latencies.append(elapsed_ms)

        search_latencies = []
        hits_at_1 = 0
        hits_at_5 = 0
        reciprocal_ranks = []
        misses = []

        for q in queries:
            results, elapsed_ms = memory_search(cortex_bin, cwd, q["query"])
            search_latencies.append(elapsed_ms)
            expected = f"[doc_id:{q['expected_doc_id']}]"
            rank = None
            for idx, item in enumerate(results[:5], start=1):
                if expected in item["content"]:
                    rank = idx
                    break
            if rank == 1:
                hits_at_1 += 1
            if rank is not None:
                hits_at_5 += 1
                reciprocal_ranks.append(1.0 / rank)
            else:
                reciprocal_ranks.append(0.0)
                misses.append(
                    {
                        "query": q["query"],
                        "expected_doc_id": q["expected_doc_id"],
                        "top_result": results[0]["content"][:140] if results else "",
                    }
                )

        stats_text, stats_ms = memory_stats(cortex_bin, cwd)
        db_size = (cwd / ".kiro" / "cortex-memory.db").stat().st_size

        total_queries = len(queries)
        return {
            "corpus_docs": len(corpus),
            "queries": total_queries,
            "recall_at_1": hits_at_1 / total_queries if total_queries else 0.0,
            "recall_at_5": hits_at_5 / total_queries if total_queries else 0.0,
            "mrr_at_5": statistics.mean(reciprocal_ranks) if reciprocal_ranks else 0.0,
            "ingest_avg_ms": statistics.mean(ingest_latencies) if ingest_latencies else 0.0,
            "ingest_p95_ms": percentile(ingest_latencies, 0.95),
            "search_avg_ms": statistics.mean(search_latencies) if search_latencies else 0.0,
            "search_p95_ms": percentile(search_latencies, 0.95),
            "stats_ms": stats_ms,
            "db_size_bytes": db_size,
            "stats_output": stats_text.strip(),
            "misses": misses[:5],
        }


def synthetic_docs(base_corpus: list[dict[str, str]], target_count: int) -> list[str]:
    docs = []
    for i in range(target_count):
        base = base_corpus[i % len(base_corpus)]
        docs.append(
            f"[doc_id:synthetic-{i}] {base['content']} synthetic copy={i} "
            f"batch={(i // max(1, len(base_corpus)))} note=memory-benchmark-{i}"
        )
    return docs


def evaluate_storage(cortex_bin: Path, base_corpus: list[dict[str, str]], queries: list[dict[str, str]], storage_count: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        write_enforce_config(cwd)

        docs = synthetic_docs(base_corpus, storage_count)
        ingest_latencies = []
        started = time.perf_counter()
        for i, doc in enumerate(docs):
            rc, elapsed_ms = ingest_chunk(cortex_bin, cwd, f"storage-{i}", doc)
            if rc not in (0, 1):
                raise RuntimeError(f"unexpected rc={rc} during synthetic ingest #{i}")
            ingest_latencies.append(elapsed_ms)
        total_ingest_ms = (time.perf_counter() - started) * 1000

        search_latencies = []
        sample_queries = queries[:5]
        for q in sample_queries:
            _results, elapsed_ms = memory_search(cortex_bin, cwd, q["query"])
            search_latencies.append(elapsed_ms)

        stats_text, stats_ms = memory_stats(cortex_bin, cwd)
        db_path = cwd / ".kiro" / "cortex-memory.db"
        db_size = db_path.stat().st_size

        forget_output, forget_ms = memory_forget(cortex_bin, cwd, "2099-01-01T00:00:00Z")
        post_forget_stats, post_forget_ms = memory_stats(cortex_bin, cwd)

        return {
            "stored_chunks": storage_count,
            "ingest_total_ms": total_ingest_ms,
            "ingest_avg_ms": statistics.mean(ingest_latencies) if ingest_latencies else 0.0,
            "ingest_p95_ms": percentile(ingest_latencies, 0.95),
            "throughput_chunks_per_sec": (storage_count / (total_ingest_ms / 1000.0)) if total_ingest_ms else 0.0,
            "search_avg_ms": statistics.mean(search_latencies) if search_latencies else 0.0,
            "search_p95_ms": percentile(search_latencies, 0.95),
            "stats_ms": stats_ms,
            "db_size_bytes": db_size,
            "stats_output": stats_text.strip(),
            "forget_ms": forget_ms,
            "forget_output": forget_output.strip(),
            "post_forget_stats_ms": post_forget_ms,
            "post_forget_stats_output": post_forget_stats.strip(),
        }


def evaluate_store_only(cortex_bin: Path, count: int) -> dict[str, Any]:
    """Layer 2: Pure memory store + search without hook overhead."""
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        write_enforce_config(cwd)

        # Direct memory import (bypasses hook scan)
        import_path = Path(tmp) / "store_test.txt"
        lines = [f"Store-only benchmark chunk {i}: synthetic content about topic-{i % 20} with details-{i}" for i in range(count)]
        import_path.write_text("\n".join(lines), encoding="utf-8")

        start = time.perf_counter()
        rc, stdout, stderr, import_ms = run(cwd, [str(cortex_bin), "memory", "import", str(import_path)])
        elapsed = (time.perf_counter() - start) * 1000

        # Search latency (pure memory, no hook)
        search_latencies = []
        for i in range(min(20, count)):
            _, search_ms = memory_search(cortex_bin, cwd, f"topic-{i}")
            search_latencies.append(search_ms)

        # Stats
        rc2, stats_out, _, stats_ms = run(cwd, [str(cortex_bin), "memory", "stats"])

        # Forget latency
        rc3, _, _, forget_ms = run(cwd, [str(cortex_bin), "memory", "forget", "--before", "2099-01-01T00:00:00Z"])

        return {
            "layer": "store_only",
            "chunks": count,
            "import_ms": import_ms,
            "import_throughput": (count / (import_ms / 1000.0)) if import_ms else 0,
            "search_avg_ms": sum(search_latencies) / len(search_latencies) if search_latencies else 0,
            "search_p95_ms": percentile(search_latencies, 0.95) if search_latencies else 0,
            "stats_ms": stats_ms,
            "forget_ms": forget_ms,
        }


def evaluate_session_injection(cortex_bin: Path, corpus: list[dict[str, str]], queries: list[dict[str, str]]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        write_enforce_config(cwd)

        for i, doc in enumerate(corpus):
            rc, _elapsed_ms = ingest_chunk(cortex_bin, cwd, f"inject-{i}", doc["content"])
            if rc not in (0, 1):
                raise RuntimeError(f"unexpected rc={rc} during injection ingest for {doc['id']}")

        spawn_rc, spawn_out, spawn_ms = hook_spawn(cortex_bin, cwd, "spawn-bench")
        if spawn_rc != 0:
            raise RuntimeError(f"spawn benchmark failed with rc={spawn_rc}")

        spawn_contains_security = "[Kiro Cortex Security Context]" in spawn_out
        spawn_contains_memory = "[Kiro Cortex Memory Context]" in spawn_out
        spawn_known_doc_ids = sum(
            1 for doc in corpus if f"[doc_id:{doc['id']}]" in spawn_out
        )

        prompt_hits = 0
        prompt_latencies = []
        prompt_misses = []
        for i, q in enumerate(queries):
            rc, out, elapsed_ms = hook_prompt(cortex_bin, cwd, f"prompt-{i}", q["query"])
            prompt_latencies.append(elapsed_ms)
            if rc != 0:
                prompt_misses.append(
                    {
                        "query": q["query"],
                        "expected_doc_id": q["expected_doc_id"],
                        "reason": f"rc={rc}",
                    }
                )
                continue
            if f"[doc_id:{q['expected_doc_id']}]" in out:
                prompt_hits += 1
            else:
                prompt_misses.append(
                    {
                        "query": q["query"],
                        "expected_doc_id": q["expected_doc_id"],
                        "reason": "expected doc_id not injected",
                    }
                )

        return {
            "spawn_latency_ms": spawn_ms,
            "spawn_contains_security_context": spawn_contains_security,
            "spawn_contains_memory_context": spawn_contains_memory,
            "spawn_known_doc_ids": spawn_known_doc_ids,
            "prompt_queries": len(queries),
            "prompt_hit_rate": (prompt_hits / len(queries)) if queries else 0.0,
            "prompt_avg_ms": statistics.mean(prompt_latencies) if prompt_latencies else 0.0,
            "prompt_p95_ms": percentile(prompt_latencies, 0.95),
            "prompt_misses": prompt_misses[:5],
        }


def evaluate_import_cli(cortex_bin: Path, base_corpus: list[dict[str, str]], import_count: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        write_enforce_config(cwd)

        import_path = cwd / "import.txt"
        lines = []
        for i in range(import_count):
            base = base_corpus[i % len(base_corpus)]
            lines.append(f"[import_doc:{i}] {base['content']} import-batch={i}")
        import_path.write_text("\n".join(lines), encoding="utf-8")

        rc, stdout, stderr, import_ms = run(
            cwd,
            [str(cortex_bin), "memory", "import", str(import_path)],
        )
        if rc != 0:
            raise RuntimeError(f"memory import failed: {stderr or stdout}")

        stats_text, stats_ms = memory_stats(cortex_bin, cwd)
        db_size = (cwd / ".kiro" / "cortex-memory.db").stat().st_size

        return {
            "import_docs": import_count,
            "import_file_bytes": import_path.stat().st_size,
            "import_latency_ms": import_ms,
            "throughput_docs_per_sec": (import_count / (import_ms / 1000.0)) if import_ms else 0.0,
            "stats_ms": stats_ms,
            "stats_output": stats_text.strip(),
            "db_size_bytes": db_size,
            "import_output": stdout.strip(),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run memory benchmark for Kiro Cortex")
    parser.add_argument("--cortex-bin", default=str(DEFAULT_BIN), help="Path to kiro-cortex binary")
    parser.add_argument("--corpus", default=str(CORPUS_PATH), help="Path to benchmark memory corpus JSON")
    parser.add_argument("--queries", default=str(QUERIES_PATH), help="Path to benchmark query JSON")
    parser.add_argument("--storage-count", type=int, default=500, help="Synthetic chunk count for storage benchmark")
    parser.add_argument("--import-count", type=int, default=200, help="Line count for CLI import benchmark")
    parser.add_argument("--rounds", type=int, default=1, help="Number of measurement rounds (avg reported)")
    parser.add_argument("--warmup", type=int, default=0, help="Warmup rounds before measurement")
    parser.add_argument("--json-out", default="", help="Optional path to write JSON report")
    args = parser.parse_args()

    cortex_bin = Path(args.cortex_bin).resolve()
    if not cortex_bin.exists():
        print(f"error: kiro-cortex binary not found at {cortex_bin}", file=sys.stderr)
        return 2

    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    queries = json.loads(Path(args.queries).read_text(encoding="utf-8"))

    print("  [1/5] Retrieval quality...", flush=True)
    quality = evaluate_retrieval(cortex_bin, corpus, queries)
    print("  [2/5] Storage e2e_hook...", flush=True)
    storage = evaluate_storage(cortex_bin, corpus, queries, args.storage_count)
    print("  [3/5] Storage store_only...", flush=True)
    store_only = evaluate_store_only(cortex_bin, args.storage_count)
    print("  [4/5] Session injection...", flush=True)
    injection = evaluate_session_injection(cortex_bin, corpus, queries)
    print("  [5/5] Import CLI...", flush=True)
    import_cli = evaluate_import_cli(cortex_bin, corpus, args.import_count)

    print("\n== Memory Retrieval Quality ==")
    print(
        f"docs={quality['corpus_docs']} queries={quality['queries']} "
        f"recall@1={quality['recall_at_1']:.4f} "
        f"recall@5={quality['recall_at_5']:.4f} "
        f"mrr@5={quality['mrr_at_5']:.4f}"
    )
    print(
        f"ingest_avg_ms={quality['ingest_avg_ms']:.1f} "
        f"search_avg_ms={quality['search_avg_ms']:.1f} "
        f"search_p95_ms={quality['search_p95_ms']:.1f} "
        f"db_size_bytes={quality['db_size_bytes']}"
    )
    if quality["misses"]:
        print("sample_misses:")
        for item in quality["misses"]:
            print(f"  - {item['expected_doc_id']}: {item['query']}")

    print("\n== Memory Storage / Lifecycle (e2e_hook) ==")
    print(
        f"stored_chunks={storage['stored_chunks']} "
        f"throughput_chunks_per_sec={storage['throughput_chunks_per_sec']:.1f} "
        f"ingest_avg_ms={storage['ingest_avg_ms']:.1f} "
        f"search_avg_ms={storage['search_avg_ms']:.1f} "
        f"forget_ms={storage['forget_ms']:.1f} "
        f"db_size_bytes={storage['db_size_bytes']}"
    )

    print("\n== Memory Store-Only (no hook overhead) ==")
    print(
        f"chunks={store_only['chunks']} "
        f"import_ms={store_only['import_ms']:.1f} "
        f"throughput={store_only['import_throughput']:.1f} chunks/s "
        f"search_avg_ms={store_only['search_avg_ms']:.1f} "
        f"forget_ms={store_only['forget_ms']:.1f}"
    )

    print("\n== Session Injection Quality ==")
    print(
        f"spawn_ms={injection['spawn_latency_ms']:.1f} "
        f"spawn_security={injection['spawn_contains_security_context']} "
        f"spawn_memory={injection['spawn_contains_memory_context']} "
        f"spawn_doc_ids={injection['spawn_known_doc_ids']} "
        f"prompt_hit_rate={injection['prompt_hit_rate']:.4f} "
        f"prompt_avg_ms={injection['prompt_avg_ms']:.1f}"
    )

    print("\n== Memory Import CLI ==")
    print(
        f"import_docs={import_cli['import_docs']} "
        f"import_ms={import_cli['import_latency_ms']:.1f} "
        f"throughput_docs_per_sec={import_cli['throughput_docs_per_sec']:.1f} "
        f"db_size_bytes={import_cli['db_size_bytes']}"
    )

    report = {
        **build_report_metadata(
            cortex_bin,
            rounds=args.rounds,
            warmup_runs=args.warmup,
            config={
                "storage_count": args.storage_count,
                "import_count": args.import_count,
            },
            datasets=[
                describe_source("memory_corpus", path=Path(args.corpus)),
                describe_source("memory_queries", path=Path(args.queries)),
            ],
        ),
        "quality": quality,
        "storage_e2e_hook": storage,
        "storage_store_only": store_only,
        "injection": injection,
        "import_cli": import_cli,
    }

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nWrote JSON report to {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
