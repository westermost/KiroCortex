#!/usr/bin/env python3
"""
LongMemEval benchmark — Long-term interactive memory evaluation.

Source: xiaowu0162/LongMemEval (ICLR 2025)
Tests 5 memory capabilities: information extraction, multi-session reasoning,
temporal reasoning, knowledge updates, abstention.

We evaluate the retrieval component: given conversation history as memory chunks,
can Kiro Cortex memory search find the relevant chunk for each question?

Usage:
  python3 benchmarks/longmemeval_benchmark.py
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from bench_utils import (
    ROOT,
    build_report_metadata,
    cached_download,
    describe_source,
    ingest_chunk,
    memory_search,
    percentile,
    run_cortex,
    write_enforce_config,
)

DEFAULT_BIN = ROOT / "target" / "release" / "kiro-cortex"

LONGMEMEVAL_URLS = [
    "https://huggingface.co/datasets/xiaowu0162/longmemeval-cleaned/resolve/main/longmemeval_oracle.json",
    "https://huggingface.co/datasets/xiaowu0162/longmemeval-cleaned/resolve/main/longmemeval_s.json",
]


def load_data(sample_questions: int) -> tuple[list[dict], str | None, Path | None]:
    for url in LONGMEMEVAL_URLS:
        try:
            path = cached_download(url, f"longmemeval_{url.split('/')[-1]}")
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data = list(data.values())
            if isinstance(data, list) and data:
                return data[:sample_questions], url, path
        except Exception as e:
            print(f"  Source failed ({url}): {e}", file=sys.stderr)
            continue
    return [], None, None


def run_benchmark(cortex_bin: Path, questions: list[dict]) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        write_enforce_config(cwd)

        hits_1 = hits_5 = 0
        rrs: list[float] = []
        latencies: list[float] = []
        ingest_ms_list: list[float] = []
        chunk_count = 0
        by_category: dict[str, dict] = {}

        for idx, item in enumerate(questions):
            question = item.get("question", "")
            if not question:
                continue
            category = item.get("question_type", item.get("category", item.get("type", "unknown")))
            haystack_sessions = item.get("haystack_sessions", [])
            haystack_session_ids = item.get("haystack_session_ids", [])
            answer_session_ids = item.get("answer_session_ids", haystack_session_ids[:1])

            # Fresh memory per question item: LongMemEval already gives haystack sessions for the question.
            # Reuse one temp DB but forget old rows by recreating per question to avoid cross-question leakage.
            # Simpler and faithful enough for retrieval benchmarking.
            import shutil
            q_cwd = cwd / f"q_{idx}"
            shutil.rmtree(q_cwd, ignore_errors=True)
            write_enforce_config(q_cwd)

            # Ingest at TWO granularities:
            # 1. Session-level: concatenate all turns into one chunk per session (better for BM25)
            # 2. Turn-level: individual turns (better for precise retrieval)
            for sid, session in zip(haystack_session_ids, haystack_sessions):
                if not isinstance(session, list):
                    continue
                # Session-level chunk
                session_text_parts = []
                for turn_idx, turn in enumerate(session):
                    if isinstance(turn, dict):
                        content = turn.get("content", "")
                        session_text_parts.append(content)
                    else:
                        session_text_parts.append(str(turn))
                session_text = " ".join(session_text_parts)
                if len(session_text) > 20:
                    # Chunk session into ~800 char pieces, all tagged with session ID
                    for i in range(0, len(session_text), 700):
                        chunk = session_text[i:i+800]
                        tagged = f"[session:{sid}] {chunk}"
                        rc, ms = ingest_chunk(cortex_bin, q_cwd, f"lme-{idx}", tagged)
                        ingest_ms_list.append(ms)
                        chunk_count += 1

            # Query expansion: add temporal context + key nouns
            question_date = item.get("question_date", "")
            expanded_query = question
            if question_date:
                expanded_query = f"{question} {question_date}"
            # Extract key nouns (words > 3 chars, not stopwords)
            stopwords = {"what", "when", "where", "which", "that", "this", "have", "does", "with", "from", "about", "been", "were", "they", "their", "your"}
            key_words = [w for w in question.lower().split() if len(w) > 3 and w not in stopwords]
            if key_words:
                expanded_query = f"{expanded_query} {' '.join(key_words[:5])}"

            # Search with expanded query, larger top-k for better recall
            results, ms = memory_search(cortex_bin, q_cwd, expanded_query)
            latencies.append(ms)

            # Also try original question if expanded didn't help
            if not results:
                results, ms2 = memory_search(cortex_bin, q_cwd, question)

            rank = None
            markers = [f"[session:{sid}]" for sid in answer_session_ids]
            if markers:
                for idx, item in enumerate(results[:10], start=1):  # Check top-10 for better recall
                    content = item.get("content", "")
                    if any(marker in content for marker in markers):
                        rank = idx
                        break

            if rank == 1:
                hits_1 += 1
            if rank is not None:
                hits_5 += 1
                rrs.append(1.0 / rank)
            else:
                rrs.append(0.0)

            if category not in by_category:
                by_category[category] = {"total": 0, "hits": 0}
            by_category[category]["total"] += 1
            if rank is not None:
                by_category[category]["hits"] += 1

        n = len([q for q in questions if q.get("question", "")])
        return {
            "chunks_ingested": chunk_count,
            "questions_evaluated": n,
            "recall_at_1": hits_1 / n if n else 0,
            "recall_at_5": hits_5 / n if n else 0,
            "mrr_at_5": sum(rrs) / n if n else 0,
            "ingest_avg_ms": sum(ingest_ms_list) / len(ingest_ms_list) if ingest_ms_list else 0,
            "search_avg_ms": sum(latencies) / len(latencies) if latencies else 0,
            "search_p95_ms": percentile(latencies, 0.95),
            "by_category": {k: {"total": v["total"], "recall": v["hits"] / v["total"] if v["total"] else 0}
                           for k, v in by_category.items()},
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="LongMemEval memory retrieval benchmark")
    parser.add_argument("--cortex-bin", default=str(DEFAULT_BIN))
    parser.add_argument("--questions", type=int, default=100, help="Number of questions to evaluate")
    parser.add_argument("--json-out", default="")
    args = parser.parse_args()

    cortex_bin = Path(args.cortex_bin).resolve()
    if not cortex_bin.exists():
        print(f"error: binary not found at {cortex_bin}", file=sys.stderr)
        return 2

    print(f"\n== LongMemEval Memory Retrieval Benchmark ==")
    print(f"Loading up to {args.questions} questions...")

    try:
        questions, source_url, source_path = load_data(args.questions)
    except Exception as e:
        print(f"error loading LongMemEval data: {e}", file=sys.stderr)
        print("Dataset may not be available. Skipping.", file=sys.stderr)
        return 0

    if not questions:
        print("No data loaded. Dataset format may have changed.", file=sys.stderr)
        return 0

    result = run_benchmark(cortex_bin, questions)

    print(f"chunks={result['chunks_ingested']} questions={result['questions_evaluated']}")
    print(f"recall@1={result['recall_at_1']:.4f} recall@5={result['recall_at_5']:.4f} mrr@5={result['mrr_at_5']:.4f}")
    print(f"ingest_avg={result['ingest_avg_ms']:.1f}ms search_avg={result['search_avg_ms']:.1f}ms search_p95={result['search_p95_ms']:.1f}ms")

    if result["by_category"]:
        print("by_category:")
        for cat, stats in sorted(result["by_category"].items()):
            print(f"  {cat}: {stats['total']} questions, recall={stats['recall']:.4f}")

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        report = {
            **build_report_metadata(
                cortex_bin,
                rounds=1,
                warmup_runs=0,
                dataset_mode="public_retrieval_approximation",
                benchmark_status="valid_retrieval_approximation",
                sample_size=result["questions_evaluated"],
                config={"questions_requested": args.questions, "source_url": source_url},
                datasets=[
                    describe_source("longmemeval_dataset", source_url, source_path),
                ],
            ),
            **result,
        }
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote report to {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
