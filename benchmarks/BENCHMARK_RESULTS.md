# Kiro Cortex — Benchmark Results

Auto-generated from `benchmarks/latest-*.json`.

## Prompt Injection Detection

| Metric | Value |
|---|---|
| total | `155` |
| tp | `34` |
| tn | `40` |
| fp | `0` |
| fn | `81` |
| precision | `1.0000` |
| recall | `0.2957` |
| false_positive_rate | `0.0000` |
| avg_ms | `286.4914` |
| p95_ms | `366.7182` |

Dataset: Giskard + WAInjectBench (155 cases)

## Secret Detection

| Metric | Value |
|---|---|
| total | `18` |
| tp | `10` |
| tn | `6` |
| fp | `1` |
| fn | `1` |
| precision | `0.9091` |
| recall | `0.9091` |
| false_positive_rate | `0.1429` |
| avg_ms | `358.1922` |

Dataset: Yelp/detect-secrets test vectors (18 cases)

## BIPIA — Indirect Prompt Injection

Dataset mode: **fallback** | Status: **fallback**

| Metric | Value |
|---|---|
| total | `13` |
| tp | `3` |
| tn | `10` |
| fp | `0` |
| fn | `0` |
| precision | `1.0000` |
| recall | `1.0000` |
| false_positive_rate | `0.0000` |
| avg_ms | `301.3390` |

## Memory Retrieval Quality

| Metric | Value |
|---|---|
| corpus_docs | `12` |
| queries | `10` |
| recall_at_1 | `1.0000` |
| recall_at_5 | `1.0000` |
| mrr_at_5 | `1.0000` |
| ingest_avg_ms | `357.1013` |
| search_avg_ms | `304.2578` |

## Memory Storage

| Layer | Throughput | Search avg |
|---|---|---|
| e2e_hook | `2.8` chunks/s | `258.7` ms |
| store_only | `69.9` chunks/s | `282.2` ms |

## Session Injection

| Metric | Value |
|---|---|
| spawn_latency_ms | `68.1965` |
| spawn_contains_security_context | `True` |
| spawn_contains_memory_context | `True` |
| prompt_hit_rate | `0.9000` |
| prompt_avg_ms | `61.0066` |

## Embedding: BM25 vs Hybrid

| Metric | BM25 | Hybrid | Delta |
|---|---|---|---|
| recall_at_1 | `0.9444` | `0.9444` | `0.0000` |
| recall_at_5 | `1.0000` | `1.0000` | `0.0000` |
| mrr_at_5 | `0.9722` | `0.9722` | `0.0000` |
| avg_ms | `246.0615` | `284.4132` | `38.3517` |

**Reindex**: 12 chunks, 661.8ms, 18.1 chunks/s

## LongMemEval — Retrieval Approximation (status: experimental_retrieval_approximation)

| Metric | Value |
|---|---|
| chunks_ingested | `2376` |
| questions_evaluated | `50` |
| recall_at_1 | `1.0000` |
| recall_at_5 | `1.0000` |
| mrr_at_5 | `1.0000` |
| search_avg_ms | `275.8344` |

## LoCoMo — Multi-Session Memory (status: experimental_retrieval_approximation)

| Metric | Value |
|---|---|
| conversations | `3` |
| questions | `497` |
| recall | `0.3622` |
| evidence_hit_rate | `0.1529` |
| avg_ms | `260.6502` |

---

## Metadata

- Generated: `2026-04-18 22:49:32`
- Binary: `/mnt/d/SourceCode/AI/KiroGuard/target/release/kiro-cortex`
- Binary SHA256: `fe285a0ec70b7d6c...`
