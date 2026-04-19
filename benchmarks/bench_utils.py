"""Shared benchmark utilities for Kiro Cortex benchmarks."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / "benchmarks" / ".cache"


def ensure_cache_dir():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def cached_download(url: str, filename: str) -> Path:
    """Download a file to cache if not present."""
    ensure_cache_dir()
    dest = CACHE_DIR / filename
    if dest.exists():
        return dest
    print(f"  Downloading {filename}...", file=sys.stderr)
    urllib.request.urlretrieve(url, str(dest))
    return dest


def cached_download_json(url: str, filename: str) -> Any:
    path = cached_download(url, filename)
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def describe_source(name: str, url: str | None = None, path: Path | None = None, version: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"name": name}
    if url:
        entry["url"] = url
    if version:
        entry["version"] = version
    if path is not None:
        resolved = path.resolve()
        entry["path"] = str(resolved)
        entry["exists"] = resolved.exists()
        if resolved.exists():
            entry["size_bytes"] = resolved.stat().st_size
            entry["sha256"] = sha256_file(resolved)
    return entry


def build_report_metadata(
    cortex_bin: Path,
    *,
    rounds: int | None = None,
    warmup_runs: int | None = None,
    dataset_mode: str | None = None,
    sample_size: int | None = None,
    benchmark_status: str | None = None,  # "valid" | "loaded_but_invalid_scoring" | "fallback" | "skipped_network"
    config: dict[str, Any] | None = None,
    datasets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cortex_bin": str(cortex_bin.resolve()),
    }
    if cortex_bin.exists():
        meta["cortex_bin_sha256"] = sha256_file(cortex_bin)
        meta["cortex_bin_size_bytes"] = cortex_bin.stat().st_size
    if rounds is not None:
        meta["rounds"] = rounds
    if warmup_runs is not None:
        meta["warmup_runs"] = warmup_runs
    if dataset_mode is not None:
        meta["dataset_mode"] = dataset_mode
    if sample_size is not None:
        meta["sample_size"] = sample_size
    if benchmark_status is not None:
        meta["benchmark_status"] = benchmark_status
    if config:
        meta["config"] = config
    if datasets is not None:
        meta["datasets"] = datasets
    return meta


def run_cortex(cortex_bin: Path, cwd: Path, args: list[str], stdin: str | None = None) -> tuple[int, str, str, float]:
    """Run kiro-cortex and return (rc, stdout, stderr, elapsed_ms)."""
    start = time.perf_counter()
    proc = subprocess.run(
        [str(cortex_bin)] + args,
        cwd=str(cwd),
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
    )
    elapsed = (time.perf_counter() - start) * 1000
    return proc.returncode, proc.stdout, proc.stderr, elapsed


def write_enforce_config(cwd: Path):
    kiro = cwd / ".kiro"
    kiro.mkdir(parents=True, exist_ok=True)
    (kiro / "cortex.toml").write_text('mode = "enforce"\n')


def ingest_chunk(cortex_bin: Path, cwd: Path, session_id: str, content: str) -> tuple[int, float]:
    """Ingest a chunk via postToolUse hook."""
    payload = {
        "hook_event_name": "postToolUse",
        "cwd": str(cwd),
        "session_id": session_id,
        "tool_name": "read",
        "tool_input": {},
        "tool_response": {"content": content},
    }
    rc, _, _, ms = run_cortex(cortex_bin, cwd, ["hook", "post-tool"], stdin=json.dumps(payload))
    return rc, ms


def memory_search(cortex_bin: Path, cwd: Path, query: str) -> tuple[list[dict], float]:
    """Search memory and return (results, elapsed_ms)."""
    rc, stdout, _, ms = run_cortex(cortex_bin, cwd, ["memory", "search", query, "--format", "json"])
    try:
        results = json.loads(stdout) if stdout.strip() and stdout.strip() != "No results found." else []
    except json.JSONDecodeError:
        results = []
    return results, ms


def evaluate_retrieval(cortex_bin: Path, cwd: Path, queries: list[dict], id_field: str = "expected_doc_id", marker_prefix: str = "[doc_id:") -> dict:
    """Evaluate retrieval quality on a set of queries with ground truth."""
    hits_1 = hits_5 = 0
    rrs: list[float] = []
    latencies: list[float] = []
    misses: list[dict] = []

    for q in queries:
        results, ms = memory_search(cortex_bin, cwd, q["query"])
        latencies.append(ms)
        expected = f"{marker_prefix}{q[id_field]}]"
        rank = None
        for idx, item in enumerate(results[:5], start=1):
            if expected in item.get("content", ""):
                rank = idx
                break
        if rank == 1:
            hits_1 += 1
        if rank is not None:
            hits_5 += 1
            rrs.append(1.0 / rank)
        else:
            rrs.append(0.0)
            misses.append({"query": q["query"], "expected": q[id_field]})

    n = len(queries)
    return {
        "queries": n,
        "recall_at_1": hits_1 / n if n else 0,
        "recall_at_5": hits_5 / n if n else 0,
        "mrr_at_5": sum(rrs) / n if n else 0,
        "avg_ms": sum(latencies) / n if n else 0,
        "misses": misses[:10],
    }


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(p * (len(ordered) - 1))
    return ordered[idx]
