# Memory Module Contract (v2.0)

## Core Principle

Guard ALWAYS runs before Memory. Memory captures post-redaction content only.

## Hook Processing Order

```
HookEvent arrives
  → Guard module processes (scan, block, warn, inject)
  → IF guard exit 0: Memory module processes (capture, inject)
  → IF guard exit non-zero: Memory skips injection, but still captures event metadata
  → Combined output returned
```

## Storage Schema

```sql
memory_chunks(
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  hook_type TEXT NOT NULL,
  tool_name TEXT,
  content TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  metadata JSON,
  importance REAL DEFAULT 0.5,
  created_at TEXT NOT NULL
)

memory_vectors(
  chunk_id TEXT PRIMARY KEY REFERENCES memory_chunks(id),
  embedding BLOB NOT NULL,
  model_version TEXT NOT NULL
)

sessions(
  id TEXT PRIMARY KEY,
  project_path TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  status TEXT DEFAULT 'active',
  chunk_count INTEGER DEFAULT 0,
  summary TEXT,
  guard_stats JSON
)

entities(id INTEGER PRIMARY KEY, name TEXT, entity_type TEXT, properties JSON, created_at TEXT)
triples(id INTEGER PRIMARY KEY, subject_id INTEGER, predicate TEXT, object_id INTEGER, valid_from TEXT, valid_to TEXT, confidence REAL, source_chunk_id TEXT, created_at TEXT)
```

## 4-Layer Memory Stack

| Layer | Tokens | Loaded at | Content |
|---|---|---|---|
| L0 Identity | ~100 | AgentSpawn | User prefs from config |
| L1 Essential | ~500-800 | AgentSpawn | Top chunks by importance |
| L2 On-demand | ~200-500 | UserPromptSubmit | Semantic search results |
| L3 Deep search | Unlimited | Agent via MCP | Full search on request |

## STDOUT Combination (AgentSpawn + UserPromptSubmit only)

```
# AgentSpawn:
[Kiro Cortex Security Context]
...guard defense instructions...
[/Kiro Cortex Security Context]

[Kiro Cortex Memory Context]
...L0 identity + L1 essential memories...
[/Kiro Cortex Memory Context]

# UserPromptSubmit (exit 0, secrets found + memory):
[Kiro Cortex Warning: ...]
[Kiro Cortex Memory: ...L2 semantic results...]
```

Guard text first. Memory appended. Total capped by `max_context_tokens`.

PreToolUse: NO memory injection. STDOUT must be empty when exit 0 (hook I/O contract). File-level memory available via L3 MCP search only.

## What Gets Captured

| Hook | Captured | NOT captured |
|---|---|---|
| PostToolUse | tool_name + tool_input summary + tool_response (redacted) | Raw secrets, full tool_input |
| UserPromptSubmit | Prompt text (after guard scan) | Nothing extra |
| Stop | Session summary | Nothing extra |
| PreToolUse (blocked) | Event metadata: "blocked read .env" | tool_input content |

## Deduplication

SHA-256(content)[:16]. Skip if hash exists within 30s window.

## Chunking

~800 chars per chunk. 100 char overlap. Split on paragraph boundaries. Same algorithm as MemPalace.

## Search

Hybrid: vector similarity (0.6 weight) + BM25 keyword (0.4 weight). Over-fetch 3x for re-ranking.

## Config

```toml
[memory]
enabled = true
scope = "project"              # "project"|"global"|"workspace"
max_context_tokens = 2000
max_inject_tokens_per_prompt = 500
auto_inject = true
max_chunks = 100000
retention_days = 365
# llm_endpoint = "http://localhost:11434"  # optional, for better summaries
```

## Performance Constraints

- PostToolUse capture: <5ms (SQLite write only, embedding deferred)
- AgentSpawn context injection: <10ms (pre-computed L0+L1)
- UserPromptSubmit semantic search: <50ms (vector search + BM25)
- Embedding computation: deferred to Stop hook or background
