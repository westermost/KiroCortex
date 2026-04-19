#!/bin/bash
# Run all Kiro Cortex benchmarks.
#
# Usage:
#   ./benchmarks/all.sh
#   CORTEX_BIN=./target/release/kiro-cortex ./benchmarks/all.sh
#   SKIP_PUBLIC=1 ./benchmarks/all.sh   # Skip slow public benchmarks

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

CORTEX_BIN="${CORTEX_BIN:-./target/release/kiro-cortex}"
CORTEX_BIN="$(cd "$(dirname "$CORTEX_BIN")" && pwd)/$(basename "$CORTEX_BIN")"
SKIP_PUBLIC="${SKIP_PUBLIC:-0}"

echo ""
echo "════════════════════════════════════════════════"
echo "  Kiro Cortex — Full Benchmark Suite"
echo "════════════════════════════════════════════════"
echo "  Binary: $CORTEX_BIN"
echo ""

# ── Core benchmarks (always run) ──

echo "[1/7] Internal regression benchmark"
CORTEX_BIN="$CORTEX_BIN" ./benchmarks/run.sh

echo ""
echo "[2/7] Public detector benchmark (injection + secrets)"
python3 ./benchmarks/public_benchmark.py \
  --mode all \
  --cortex-bin "$CORTEX_BIN" \
  --json-out ./benchmarks/latest-public-benchmark.json

echo ""
echo "[3/7] Memory benchmark (3 layers: retrieval_quality + e2e_hook + store_only)"
python3 ./benchmarks/memory_benchmark.py \
  --cortex-bin "$CORTEX_BIN" \
  --json-out ./benchmarks/latest-memory-benchmark.json

# ── Public benchmarks (skip with SKIP_PUBLIC=1) ──

if [ "$SKIP_PUBLIC" = "0" ]; then

echo ""
echo "[4/7] BIPIA — Indirect prompt injection"
python3 ./benchmarks/bipia_benchmark.py \
  --cortex-bin "$CORTEX_BIN" \
  --sample 100 \
  --json-out ./benchmarks/latest-bipia-benchmark.json || echo "  ⚠ BIPIA skipped (data unavailable)"

echo ""
echo "[5/7] LongMemEval — Long-term memory retrieval"
python3 ./benchmarks/longmemeval_benchmark.py \
  --cortex-bin "$CORTEX_BIN" \
  --questions 50 \
  --json-out ./benchmarks/latest-longmemeval-benchmark.json || echo "  ⚠ LongMemEval skipped (data unavailable)"

echo ""
echo "[6/7] LoCoMo — Multi-session conversational memory"
python3 ./benchmarks/locomo_benchmark.py \
  --cortex-bin "$CORTEX_BIN" \
  --sample 3 \
  --json-out ./benchmarks/latest-locomo-benchmark.json || echo "  ⚠ LoCoMo skipped (data unavailable)"

echo ""
echo "[7/7] BEIR — Retrieval engine quality (SciFact)"
python3 ./benchmarks/beir_benchmark.py \
  --cortex-bin "$CORTEX_BIN" \
  --max-docs 500 \
  --max-queries 100 \
  --json-out ./benchmarks/latest-beir-benchmark.json || echo "  ⚠ BEIR skipped (data unavailable)"

else
  echo ""
  echo "[4-7] Public benchmarks SKIPPED (SKIP_PUBLIC=1)"
fi

# ── Embedding benchmark (optional) ──

if "$CORTEX_BIN" memory init 2>&1 | grep -q "downloaded\|already\|Embedding model"; then
  echo ""
  echo "[+] Embedding benchmark (BM25 vs Hybrid + Reindex)"
  python3 ./benchmarks/embedding_benchmark.py \
    --cortex-bin "$CORTEX_BIN" \
    --json-out ./benchmarks/latest-embedding-benchmark.json
else
  echo ""
  echo "[+] Embedding benchmark — SKIPPED (not built with --features embedding)"
fi

echo ""
echo "════════════════════════════════════════════════"
echo "  Generating Markdown summary..."
echo "════════════════════════════════════════════════"
python3 ./benchmarks/summary.py --out ./benchmarks/BENCHMARK_RESULTS.md
echo ""
echo "  Done. Reports in benchmarks/latest-*.json"
echo "  Summary: benchmarks/BENCHMARK_RESULTS.md"
echo "════════════════════════════════════════════════"
