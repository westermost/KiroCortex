#!/usr/bin/env python3
"""
Generate Markdown summary from Kiro Cortex benchmark JSON reports.

Usage:
  python3 benchmarks/summary.py                          # Auto-find latest-*.json
  python3 benchmarks/summary.py --out BENCHMARK_RESULTS.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = ROOT / "benchmarks"


def load_report(name: str) -> dict | None:
    path = BENCH_DIR / f"latest-{name}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def fmt(v, decimals=4) -> str:
    if v is None: return "—"
    if isinstance(v, float): return f"{v:.{decimals}f}"
    return str(v)


def generate_summary() -> str:
    lines = ["# Kiro Cortex — Benchmark Results\n"]
    lines.append(f"Auto-generated from `benchmarks/latest-*.json`.\n")

    # --- Public Detection ---
    pub = load_report("public-benchmark")
    if pub:
        lines.append("## Prompt Injection Detection\n")
        inj = pub.get("results", pub).get("injection", pub.get("injection", {}))
        s = inj.get("summary", inj)
        lines.append(f"| Metric | Value |")
        lines.append(f"|---|---|")
        for k in ["total", "tp", "tn", "fp", "fn", "precision", "recall", "false_positive_rate", "avg_ms", "p95_ms"]:
            if k in s: lines.append(f"| {k} | `{fmt(s[k])}` |")
        lines.append(f"\nDataset: Giskard + WAInjectBench ({s.get('total', '?')} cases)\n")

        lines.append("## Secret Detection\n")
        sec = pub.get("results", pub).get("secrets", pub.get("secrets", {}))
        s2 = sec.get("summary", sec)
        lines.append(f"| Metric | Value |")
        lines.append(f"|---|---|")
        for k in ["total", "tp", "tn", "fp", "fn", "precision", "recall", "false_positive_rate", "avg_ms"]:
            if k in s2: lines.append(f"| {k} | `{fmt(s2[k])}` |")
        lines.append(f"\nDataset: Yelp/detect-secrets test vectors ({s2.get('total', '?')} cases)\n")

    # --- BIPIA ---
    bipia = load_report("bipia-benchmark")
    if bipia:
        lines.append("## BIPIA — Indirect Prompt Injection\n")
        mode = bipia.get("dataset_mode", "unknown")
        status = bipia.get("benchmark_status", "valid" if mode == "full" else mode)
        lines.append(f"Dataset mode: **{mode}** | Status: **{status}**\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"|---|---|")
        for k in ["total", "tp", "tn", "fp", "fn", "precision", "recall", "false_positive_rate", "avg_ms"]:
            if k in bipia: lines.append(f"| {k} | `{fmt(bipia[k])}` |")
        lines.append("")

    # --- Memory ---
    mem = load_report("memory-benchmark")
    if mem:
        lines.append("## Memory Retrieval Quality\n")
        q = mem.get("quality", {})
        lines.append(f"| Metric | Value |")
        lines.append(f"|---|---|")
        for k in ["corpus_docs", "queries", "recall_at_1", "recall_at_5", "mrr_at_5", "ingest_avg_ms", "search_avg_ms"]:
            if k in q: lines.append(f"| {k} | `{fmt(q[k])}` |")

        lines.append(f"\n## Memory Storage\n")
        lines.append(f"| Layer | Throughput | Search avg |")
        lines.append(f"|---|---|---|")
        e2e = mem.get("storage_e2e_hook", {})
        so = mem.get("storage_store_only", {})
        if e2e:
            lines.append(f"| e2e_hook | `{fmt(e2e.get('throughput_chunks_per_sec'), 1)}` chunks/s | `{fmt(e2e.get('search_avg_ms'), 1)}` ms |")
        if so:
            lines.append(f"| store_only | `{fmt(so.get('import_throughput'), 1)}` chunks/s | `{fmt(so.get('search_avg_ms'), 1)}` ms |")

        lines.append(f"\n## Session Injection\n")
        inj = mem.get("injection", {})
        lines.append(f"| Metric | Value |")
        lines.append(f"|---|---|")
        for k in ["spawn_latency_ms", "spawn_contains_security_context", "spawn_contains_memory_context", "prompt_hit_rate", "prompt_avg_ms"]:
            if k in inj: lines.append(f"| {k} | `{fmt(inj[k])}` |")
        lines.append("")

    # --- Embedding ---
    emb = load_report("embedding-benchmark")
    if emb:
        lines.append("## Embedding: BM25 vs Hybrid\n")
        lines.append(f"| Metric | BM25 | Hybrid | Delta |")
        lines.append(f"|---|---|---|---|")
        bm = emb.get("bm25", {})
        hy = emb.get("hybrid", {})
        for k in ["recall_at_1", "recall_at_5", "mrr_at_5", "avg_ms"]:
            b = bm.get(k)
            h = hy.get(k)
            d = (h - b) if b is not None and h is not None else None
            lines.append(f"| {k} | `{fmt(b)}` | `{fmt(h)}` | `{fmt(d, 4) if d is not None else '—'}` |")

        ri = emb.get("reindex", {})
        if ri:
            lines.append(f"\n**Reindex**: {ri.get('chunks', '?')} chunks, {fmt(ri.get('reindex_ms'), 1)}ms, {fmt(ri.get('chunks_per_sec'), 1)} chunks/s\n")

    # --- LongMemEval ---
    lme = load_report("longmemeval-benchmark")
    if lme:
        status = lme.get("benchmark_status", "unknown")
        lines.append(f"## LongMemEval — Retrieval Approximation (status: {status})\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"|---|---|")
        for k in ["chunks_ingested", "questions_evaluated", "recall_at_1", "recall_at_5", "mrr_at_5", "search_avg_ms"]:
            if k in lme: lines.append(f"| {k} | `{fmt(lme[k])}` |")
        lines.append("")

    # --- LoCoMo ---
    loc = load_report("locomo-benchmark")
    if loc:
        status = loc.get("benchmark_status", "unknown")
        lines.append(f"## LoCoMo — Multi-Session Memory (status: {status})\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"|---|---|")
        for k in ["conversations", "questions", "recall", "evidence_hit_rate", "avg_ms"]:
            if k in loc: lines.append(f"| {k} | `{fmt(loc[k])}` |")
        lines.append("")

    # --- BEIR ---
    beir = load_report("beir-benchmark")
    if beir:
        status = beir.get("benchmark_status", "unknown")
        lines.append(f"## BEIR — Retrieval Engine (SciFact) (status: {status})\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"|---|---|")
        for k in ["corpus_docs", "queries_evaluated", "recall_at_5", "ndcg_at_5", "search_avg_ms"]:
            if k in beir: lines.append(f"| {k} | `{fmt(beir[k])}` |")
        lines.append("")

    # --- Metadata ---
    lines.append("---\n")
    lines.append("## Metadata\n")
    if pub:
        lines.append(f"- Generated: `{pub.get('generated_at', '?')}`")
        lines.append(f"- Binary: `{pub.get('cortex_bin', '?')}`")
        if "cortex_bin_sha256" in pub:
            lines.append(f"- Binary SHA256: `{pub['cortex_bin_sha256'][:16]}...`")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Markdown summary from benchmark reports")
    parser.add_argument("--out", default="", help="Output file (default: stdout)")
    args = parser.parse_args()

    md = generate_summary()

    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"Wrote summary to {args.out}")
    else:
        print(md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
