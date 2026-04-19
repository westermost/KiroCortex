#!/usr/bin/env python3
"""
LoCoMo benchmark — Long Conversation Memory (Snap Research).

Source: snap-research/locomo
Tests multi-session conversational memory with QA annotations.

Usage:
  python3 benchmarks/locomo_benchmark.py
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

LOCOMO_URL = "https://raw.githubusercontent.com/snap-research/locomo/main/data/locomo10.json"


def load_data(sample: int) -> list[dict]:
    path = cached_download(LOCOMO_URL, "locomo10.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = list(data.values())[:sample]
    elif isinstance(data, list):
        data = data[:sample]
    return data


def run_benchmark(cortex_bin: Path, conversations: list[dict]) -> dict:
    all_results = []

    for conv_idx, conv in enumerate(conversations):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp)
            write_enforce_config(cwd)

            # Ingest conversation turns. LoCoMo stores sessions inside a dict.
            chunk_count = 0
            conv_obj = conv.get("conversation", conv.get("turns", conv.get("sessions", [])))
            session_lists: list[tuple[str, list]] = []
            if isinstance(conv_obj, list):
                session_lists.append(("session_0", conv_obj))
            elif isinstance(conv_obj, dict):
                for key, value in conv_obj.items():
                    if key.startswith("session_") and isinstance(value, list):
                        session_lists.append((key, value))

            for session_key, turns in session_lists:
                # Session-level summary chunk (if available)
                session_text_parts = []
                for i, turn in enumerate(turns):
                    if isinstance(turn, dict):
                        dia_id = turn.get("dia_id", f"{session_key}:{i}")
                        text = turn.get("text", json.dumps(turn, ensure_ascii=False))
                        speaker = turn.get("speaker", "unknown")
                        tagged = f"[conv:{conv_idx}] [session:{session_key}] [dia_id:{dia_id}] [{speaker}] {text[:800]}"
                        session_text_parts.append(text)
                    else:
                        tagged = f"[conv:{conv_idx}] [session:{session_key}] {str(turn)[:800]}"
                        session_text_parts.append(str(turn))
                    if len(tagged.strip()) < 10:
                        continue
                    ingest_chunk(cortex_bin, cwd, f"locomo-{conv_idx}", tagged)
                    chunk_count += 1

                # Also ingest session-level concatenation for better BM25 coverage
                session_concat = " ".join(session_text_parts)
                if len(session_concat) > 50:
                    for j in range(0, len(session_concat), 700):
                        chunk = session_concat[j:j+800]
                        tagged = f"[conv:{conv_idx}] [session:{session_key}] [summary] {chunk}"
                        ingest_chunk(cortex_bin, cwd, f"locomo-{conv_idx}", tagged)
                        chunk_count += 1

            # Ingest observations (if available in dataset)
            observations = conv.get("observation", conv.get("observations", []))
            if isinstance(observations, list):
                for obs in observations:
                    text = obs if isinstance(obs, str) else obs.get("text", obs.get("content", json.dumps(obs, ensure_ascii=False)))
                    if len(str(text)) > 20:
                        tagged = f"[conv:{conv_idx}] [observation] {str(text)[:800]}"
                        ingest_chunk(cortex_bin, cwd, f"locomo-{conv_idx}", tagged)
                        chunk_count += 1

            # Ingest session summaries (if available)
            summaries = conv.get("session_summary", conv.get("summaries", {}))
            if isinstance(summaries, dict):
                for skey, sval in summaries.items():
                    text = sval if isinstance(sval, str) else json.dumps(sval, ensure_ascii=False)
                    if len(text) > 20:
                        tagged = f"[conv:{conv_idx}] [session:{skey}] [session_summary] {text[:800]}"
                        ingest_chunk(cortex_bin, cwd, f"locomo-{conv_idx}", tagged)
                        chunk_count += 1
            elif isinstance(summaries, list):
                for sval in summaries:
                    text = sval if isinstance(sval, str) else json.dumps(sval, ensure_ascii=False)
                    if len(text) > 20:
                        tagged = f"[conv:{conv_idx}] [session_summary] {text[:800]}"
                        ingest_chunk(cortex_bin, cwd, f"locomo-{conv_idx}", tagged)
                        chunk_count += 1

            # Evaluate QA
            qas = conv.get("qa", conv.get("questions", conv.get("qa_pairs", [])))
            if not isinstance(qas, list):
                continue

            for qa in qas:
                question = qa.get("question", qa.get("q", ""))
                answer = qa.get("answer", qa.get("a", ""))
                if not question:
                    continue
                # Safely convert answer to string for fallback word overlap
                if not isinstance(answer, str):
                    answer = json.dumps(answer) if isinstance(answer, (dict, list)) else str(answer)

                results, ms = memory_search(cortex_bin, cwd, question)
                evidence = qa.get("evidence", [])
                evidence_markers = []
                if isinstance(evidence, list):
                    evidence_markers = [f"[dia_id:{item}]" for item in evidence if item]
                elif evidence:
                    evidence_markers = [f"[dia_id:{evidence}]"]

                answer_words = set(answer.lower().split()) if answer else set()
                # Also extract key nouns from question for matching
                question_words = set(w for w in question.lower().split() if len(w) > 3)
                match_words = answer_words | question_words

                hit = False
                evidence_hit = False
                # 1. Check evidence dia_id markers
                if results and evidence_markers:
                    for r in results[:5]:
                        content = r.get("content", "")
                        if any(marker in content for marker in evidence_markers):
                            hit = True
                            evidence_hit = True
                            break
                # 2. Check session-level match (evidence may reference session)
                if not hit and results:
                    evidence_sessions = set()
                    for e in (evidence if isinstance(evidence, list) else [evidence]):
                        s = str(e)
                        if "session_" in s:
                            evidence_sessions.add(s.split(":")[0] if ":" in s else s)
                    if evidence_sessions:
                        for r in results[:5]:
                            content = r.get("content", "")
                            if any(f"[session:{s}]" in content for s in evidence_sessions):
                                hit = True
                                break
                # 3. Fallback: keyword overlap
                if not hit and results and match_words:
                    for r in results[:5]:
                        content_lower = r.get("content", "").lower()
                        content_words = set(content_lower.split())
                        # Score: overlap of answer+question keywords with retrieved content
                        overlap = len(match_words & content_words) / len(match_words) if match_words else 0
                        if overlap > 0.2:  # 20% keyword overlap = hit
                            hit = True
                            break

                all_results.append({
                    "conv": conv_idx,
                    "question": question[:100],
                    "hit": hit,
                    "evidence_hit": evidence_hit,
                    "latency_ms": ms,
                    "category": qa.get("category", qa.get("type", "unknown")),
                })

    total = len(all_results)
    hits = sum(1 for r in all_results if r["hit"])
    evidence_hits = sum(1 for r in all_results if r.get("evidence_hit"))
    latencies = [r["latency_ms"] for r in all_results]

    by_category: dict[str, dict] = {}
    for r in all_results:
        cat = r["category"]
        if cat not in by_category:
            by_category[cat] = {"total": 0, "hits": 0}
        by_category[cat]["total"] += 1
        if r["hit"]:
            by_category[cat]["hits"] += 1

    return {
        "conversations": len(conversations),
        "questions": total,
        "recall": hits / total if total else 0,
        "evidence_hit_rate": evidence_hits / total if total else 0,
        "avg_ms": sum(latencies) / len(latencies) if latencies else 0,
        "p95_ms": percentile(latencies, 0.95),
        "by_category": {k: {"total": v["total"], "recall": v["hits"] / v["total"] if v["total"] else 0}
                       for k, v in by_category.items()},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="LoCoMo multi-session memory benchmark")
    parser.add_argument("--cortex-bin", default=str(DEFAULT_BIN))
    parser.add_argument("--sample", type=int, default=5, help="Number of conversations")
    parser.add_argument("--json-out", default="")
    args = parser.parse_args()

    cortex_bin = Path(args.cortex_bin).resolve()
    if not cortex_bin.exists():
        print(f"error: binary not found at {cortex_bin}", file=sys.stderr)
        return 2

    print(f"\n== LoCoMo Multi-Session Memory Benchmark (experimental retrieval approximation) ==")
    print(f"Loading {args.sample} conversations...")

    try:
        conversations = load_data(args.sample)
    except Exception as e:
        print(f"error loading LoCoMo data: {e}", file=sys.stderr)
        print("Dataset may not be available. Skipping.", file=sys.stderr)
        return 0

    if not conversations:
        print("No data loaded. Skipping.", file=sys.stderr)
        return 0

    result = run_benchmark(cortex_bin, conversations)

    print(f"conversations={result['conversations']} questions={result['questions']}")
    print(f"recall={result['recall']:.4f} evidence_hit={result['evidence_hit_rate']:.4f} avg_ms={result['avg_ms']:.1f} p95_ms={result['p95_ms']:.1f}")

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
                benchmark_status="experimental_retrieval_approximation",
                sample_size=result["questions"],
                config={"conversations_requested": args.sample},
                datasets=[
                    describe_source("locomo10", LOCOMO_URL, ROOT / "benchmarks" / ".cache" / "locomo10.json"),
                ],
            ),
            **result,
        }
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote report to {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
