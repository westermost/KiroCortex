#!/usr/bin/env python3
"""
BEIR/MTEB retrieval benchmark — measures retrieval engine quality.

Uses SciFact from BEIR (small, well-curated) as the default dataset.
Tests BM25 vs hybrid retrieval on a standard IR benchmark.

Source: beir-cellar/beir (SciFact subset)

Usage:
  python3 benchmarks/beir_benchmark.py
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from bench_utils import (
    ROOT,
    CACHE_DIR,
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

SCIFACT_ZIP_URL = "https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets/scifact.zip"


def load_scifact(max_docs: int, max_queries: int) -> tuple[list[dict], list[dict], dict]:
    """Load SciFact corpus, queries, and relevance judgments from the official BEIR zip."""
    try:
        zip_path = cached_download(SCIFACT_ZIP_URL, "scifact.zip")
        try:
            zf = zipfile.ZipFile(zip_path)
            # Force central directory read early so partial cache is detected immediately.
            zf.namelist()
        except zipfile.BadZipFile:
            print("  Cached scifact.zip is corrupt; re-downloading...", file=sys.stderr)
            zip_path.unlink(missing_ok=True)
            zip_path = cached_download(SCIFACT_ZIP_URL, "scifact.zip")
            zf = zipfile.ZipFile(zip_path)
            zf.namelist()
    except Exception as e:
        print(f"  Source failed: {e}", file=sys.stderr)
        return [], [], {}

    def open_member(target_suffix: str):
        for name in zf.namelist():
            if name.endswith(target_suffix):
                return zf.open(name)
        raise FileNotFoundError(target_suffix)

    # Parse corpus
    corpus = []
    with open_member("corpus.jsonl") as f:
        for line in f:
            if not line.strip():
                continue
            doc = json.loads(line.decode("utf-8"))
            corpus.append({"id": doc["_id"], "text": f"{doc.get('title', '')} {doc.get('text', '')}"})
            if len(corpus) >= max_docs:
                break

    # Parse queries
    queries = []
    with open_member("queries.jsonl") as f:
        for line in f:
            if not line.strip():
                continue
            q = json.loads(line.decode("utf-8"))
            queries.append({"id": q["_id"], "text": q.get("text", "")})
            if len(queries) >= max_queries:
                break

    # Parse qrels (query_id -> {doc_id: relevance})
    qrels: dict[str, dict[str, int]] = {}
    with open_member("qrels/test.tsv") as f:
        reader = csv.reader(f, delimiter="\t")
        next(reader, None)  # Skip header
        for row in reader:
            if len(row) >= 3:
                qid, did, rel = row[0], row[1], int(row[2])
                if qid not in qrels:
                    qrels[qid] = {}
                qrels[qid][did] = rel

    return corpus, queries, qrels


def run_benchmark(cortex_bin: Path, corpus: list[dict], queries: list[dict], qrels: dict) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        write_enforce_config(cwd)

        # Ingest corpus
        print(f"  Ingesting {len(corpus)} documents...")
        ingest_times = []
        for doc in corpus:
            tagged = f"[beir_id:{doc['id']}] {doc['text'][:800]}"
            _, ms = ingest_chunk(cortex_bin, cwd, "beir", tagged)
            ingest_times.append(ms)

        # Evaluate queries that have relevance judgments
        eval_queries = [q for q in queries if q["id"] in qrels]
        print(f"  Evaluating {len(eval_queries)} queries with relevance judgments...")

        ndcg_5_list = []
        recall_5_list = []
        latencies = []

        for q in eval_queries:
            results, ms = memory_search(cortex_bin, cwd, q["text"])
            latencies.append(ms)

            relevant = qrels.get(q["id"], {})
            if not relevant:
                continue

            # Calculate NDCG@5 and Recall@5
            retrieved_ids = []
            for r in results[:5]:
                content = r.get("content", "")
                # Extract beir_id from tagged content
                if "[beir_id:" in content:
                    bid = content.split("[beir_id:")[1].split("]")[0]
                    retrieved_ids.append(bid)

            # Recall@5
            relevant_ids = {did for did, rel in relevant.items() if rel > 0}
            retrieved_relevant = len(set(retrieved_ids) & relevant_ids)
            recall = retrieved_relevant / len(relevant_ids) if relevant_ids else 0
            recall_5_list.append(recall)

            # NDCG@5 (standard log2 discount)
            import math
            dcg = 0.0
            for i, rid in enumerate(retrieved_ids[:5]):
                rel = relevant.get(rid, 0)
                dcg += rel / math.log2(i + 2)  # i+2 because rank starts at 1, log2(1+1)=1
            ideal = sorted(relevant.values(), reverse=True)[:5]
            idcg = sum(r / math.log2(i + 2) for i, r in enumerate(ideal))
            ndcg = dcg / idcg if idcg > 0 else 0
            ndcg_5_list.append(ndcg)

        n = len(eval_queries)
        return {
            "dataset": "SciFact",
            "corpus_docs": len(corpus),
            "queries_evaluated": n,
            "recall_at_5": sum(recall_5_list) / len(recall_5_list) if recall_5_list else 0,
            "ndcg_at_5": sum(ndcg_5_list) / len(ndcg_5_list) if ndcg_5_list else 0,
            "ingest_avg_ms": sum(ingest_times) / len(ingest_times) if ingest_times else 0,
            "search_avg_ms": sum(latencies) / len(latencies) if latencies else 0,
            "search_p95_ms": percentile(latencies, 0.95),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="BEIR/MTEB retrieval benchmark")
    parser.add_argument("--cortex-bin", default=str(DEFAULT_BIN))
    parser.add_argument("--dataset", default="scifact", choices=["scifact"], help="BEIR dataset (more coming)")
    parser.add_argument("--max-docs", type=int, default=1000, help="Max corpus documents")
    parser.add_argument("--max-queries", type=int, default=300, help="Max queries")
    parser.add_argument("--json-out", default="")
    args = parser.parse_args()

    cortex_bin = Path(args.cortex_bin).resolve()
    if not cortex_bin.exists():
        print(f"error: binary not found at {cortex_bin}", file=sys.stderr)
        return 2

    print(f"\n== BEIR Retrieval Benchmark (SciFact) ==")
    print(f"Loading corpus (max {args.max_docs} docs) and queries (max {args.max_queries})...")

    corpus, queries, qrels = load_scifact(args.max_docs, args.max_queries)
    if not corpus or not queries:
        print("Failed to load SciFact data. Skipping.", file=sys.stderr)
        return 0

    result = run_benchmark(cortex_bin, corpus, queries, qrels)

    print(f"corpus={result['corpus_docs']} queries={result['queries_evaluated']}")
    print(f"recall@5={result['recall_at_5']:.4f} ndcg@5={result['ndcg_at_5']:.4f}")
    print(f"ingest_avg={result['ingest_avg_ms']:.1f}ms search_avg={result['search_avg_ms']:.1f}ms p95={result['search_p95_ms']:.1f}ms")

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        report = {
            **build_report_metadata(
                cortex_bin,
                rounds=1,
                warmup_runs=0,
                dataset_mode="public_ir_benchmark",
                benchmark_status="valid",
                sample_size=result["queries_evaluated"],
                config={
                    "dataset": args.dataset,
                    "max_docs": args.max_docs,
                    "max_queries": args.max_queries,
                },
                datasets=[
                    describe_source("beir_scifact_zip", SCIFACT_ZIP_URL, CACHE_DIR / "scifact.zip"),
                ],
            ),
            **result,
        }
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote report to {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
