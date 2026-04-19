# How It Works

> Kiến trúc chi tiết của Kiro Cortex — Guard, Proxy, Memory trong một binary.

---

## Tổng quan

Kiro Cortex là một Rust binary duy nhất, tích hợp vào Kiro qua Hook system. Mỗi khi agent thực hiện hành động, Kiro gọi Kiro Cortex qua STDIN/STDOUT — không cần daemon, không cần server.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Kiro Cortex Binary                        │
│                                                                 │
│   ┌───────────────┐  ┌───────────────┐  ┌───────────────────┐  │
│   │  🛡️ GUARD      │  │  🔄 PROXY     │  │  🧠 MEMORY        │  │
│   │               │  │               │  │                   │  │
│   │ Secret scan   │  │ MCP middle-   │  │ Verbatim capture  │  │
│   │ Injection     │  │ man           │  │ Semantic search   │  │
│   │ detect        │  │ Scan+redact   │  │ Context inject    │  │
│   │ Path block    │  │ responses     │  │ Knowledge Graph   │  │
│   │               │  │               │  │                   │  │
│   │ v1.0          │  │ v1.5          │  │ v2.0              │  │
│   └───────────────┘  └───────────────┘  └───────────────────┘  │
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    Shared Storage                       │   │
│   │   SQLite: audit log + memory chunks + KG + sessions     │   │
│   │   Vector: embeddings (lazy-loaded model)                │   │
│   └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Hook Lifecycle

Kiro Cortex hook vào 5 điểm trong lifecycle của Kiro agent. Mỗi hook nhận JSON qua STDIN, trả kết quả qua exit code + STDOUT/STDERR.

```
  Agent Start        User Types         Agent Calls Tool      Tool Returns        Agent Done
      │                  │                    │                    │                   │
      ▼                  ▼                    ▼                    ▼                   ▼
 ┌─────────┐      ┌───────────┐        ┌───────────┐       ┌───────────┐       ┌─────────┐
 │  SPAWN  │      │  PROMPT   │        │ PRE-TOOL  │       │ POST-TOOL │       │  STOP   │
 │         │      │  SUBMIT   │        │   USE     │       │   USE     │       │         │
 │ Guard:  │      │ Guard:    │        │ Guard:    │       │ Guard:    │       │ Guard:  │
 │ defense │      │ scan      │        │ path+     │       │ scan      │       │ session │
 │ instruct│      │ secrets   │        │ content   │       │ response  │       │ summary │
 │         │      │           │        │ scan      │       │           │       │         │
 │ Memory: │      │ Memory:   │        │           │       │ Memory:   │       │ Memory: │
 │ L0+L1   │      │ L2        │        │ ⛔ BLOCK  │       │ capture   │       │ session │
 │ context │      │ semantic  │        │ or allow  │       │ verbatim  │       │ save    │
 └─────────┘      └───────────┘        └───────────┘       └───────────┘       └─────────┘
     │                  │                    │                    │                   │
     ▼                  ▼                    ▼                    ▼                   ▼
  exit 0             exit 0/1            exit 0/1/2           exit 0/1             exit 0
  STDOUT:            STDOUT:             STDOUT:              STDERR:              STDERR:
  context            context             (empty)              warnings             summary
```

---

## Exit Code Rules

```
┌──────────────────────────────────────────────────────────────┐
│                    EXIT CODE CONTRACT                        │
│                                                              │
│  Exit 0 ──→ STDOUT captured (may be empty)                  │
│             STDERR must be empty                             │
│                                                              │
│  Exit 1 ──→ STDERR shown as warning to user                 │
│             STDOUT must be empty                             │
│             Tool still executes (except PreToolUse)          │
│                                                              │
│  Exit 2 ──→ STDERR returned to LLM as block reason          │
│             STDOUT must be empty                             │
│             ⚠️  ONLY valid for PreToolUse                    │
│                                                              │
│  RULE: STDOUT and STDERR never both populated               │
│  RULE: Audit mode = always exit 0, both empty               │
└──────────────────────────────────────────────────────────────┘
```

| Hook | Exit 0 | Exit 1 | Exit 2 |
|---|---|---|---|
| AgentSpawn | STDOUT: defense + memory context | — | N/A |
| UserPromptSubmit | STDOUT: warning context + memory | STDERR: warn user | N/A |
| **PreToolUse** | Allow tool | STDERR: warn, allow | **⛔ BLOCK tool** |
| PostToolUse | Clean | STDERR: findings | N/A |
| Stop | Done | — | N/A |

---

## 🛡️ Guard Module (v1.0)

### PreToolUse — The Enforcement Boundary

Đây là hook duy nhất có thể **chặn tool thực sự**. Guard chạy pipeline:

```
                        tool_input arrives
                              │
                    ┌─────────▼──────────┐
                    │  Session allowlist  │──── match ────▶ skip this rule
                    │  (allow-once)       │                 continue pipeline
                    └─────────┬──────────┘
                              │ no match
                    ┌─────────▼──────────┐
                    │  extra_allow check  │──── match ────▶ skip path deny
                    │  (.env.example)     │                 go to content scan
                    └─────────┬──────────┘
                              │ no match
                    ┌─────────▼──────────┐
                    │  Path deny match   │
                    │  (~30 built-in +   │
                    │   extra_deny)      │
                    └────┬─────────┬─────┘
                         │         │
                    action=block  action=warn
                         │         │
                    ┌────▼────┐  ┌─▼──────────┐
                    │ EXIT 2  │  │ EXIT 1     │
                    │ ⛔ BLOCK │  │ ⚠️ WARN    │
                    │ (stop)  │  │ (continue) │
                    └─────────┘  └─────┬──────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │  Content scan ALL string values     │
                    │  (~40 built-in + custom rules)      │
                    │                                     │
                    │  Keyword pre-filter                 │
                    │  → RegexSet match                   │
                    │  → Entropy check (per-rule)         │
                    │  → Allowlist check                  │
                    └────────────┬────────────────────────┘
                                 │
                          match found?
                         ╱          ╲
                       yes           no
                        │             │
                   ┌────▼────┐  ┌────▼────┐
                   │ EXIT 2  │  │ EXIT 0  │
                   │ ⛔ BLOCK │  │ ✅ ALLOW │
                   └─────────┘  └─────────┘
```

### PostToolUse — Detect + Warn

```
                     tool_response arrives
                              │
                    ┌─────────▼──────────┐
                    │  Secret scan       │──── ALL string fields
                    │  (~40 rules)       │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Injection scan    │──── risky fields only
                    │  (55 patterns)     │     (per tool family)
                    └─────────┬──────────┘
                              │
                       findings found?
                      ╱              ╲
                    yes               no
                     │                 │
                ┌────▼─────┐     ┌────▼────┐
                │ EXIT 1   │     │ EXIT 0  │
                │ STDERR:  │     │ (clean) │
                │ warnings │     └─────────┘
                └──────────┘
```

### Injection Scan — Tool Family Field Policy

```
┌─────────────────────────────────────────────────────────┐
│  Tool Pattern          │  Risky Fields (injection scan) │
├────────────────────────┼────────────────────────────────┤
│  gmail_*, email_*      │  subject, body, snippet        │
│  github_*, git_*       │  title, body, description      │
│  documents_*, docs_*   │  title, name, content          │
│  slack_*, chat_*       │  text, message, content        │
│  Unknown / @mcp/*      │  name, description, content,   │
│                        │  title, body, text, message,   │
│                        │  comment, subject, notes       │
├────────────────────────┼────────────────────────────────┤
│  NEVER scanned:        │  id, url, created_at, type,    │
│                        │  status, updated_at            │
└─────────────────────────────────────────────────────────┘

Secret scan: ALWAYS all string fields (regardless of tool family)
```

---

## 🔄 MCP Proxy (v1.5)

### Vấn đề mà Proxy giải quyết

```
  Không có Proxy:                        Có Proxy:

  Agent ──▶ MCP Server ──▶ Response      Agent ──▶ Proxy ──▶ MCP Server
                │                                     │
                ▼                                     ▼
  PostToolUse chỉ WARN                   Proxy REDACT secrets
  Secret vẫn đến LLM ❌                  Proxy STRIP injection
                                         Proxy BLOCK nếu critical
                                         Clean response → Agent ✅
```

### Proxy Pipeline

```
┌──────────────────────────────────────────────────────────────┐
│                     MCP Proxy Pipeline                       │
│                                                              │
│  Kiro Agent                                                  │
│      │                                                       │
│      │ JSON-RPC request (stdio)                              │
│      ▼                                                       │
│  ┌────────────────────┐                                      │
│  │ Request Router     │                                      │
│  │                    │                                      │
│  │ initialize    ────────▶ pass-through                      │
│  │ tools/list    ────────▶ pass-through                      │
│  │ notifications ────────▶ pass-through                      │
│  │ tools/call    ────────▶ INTERCEPT ◀── only this           │
│  └────────┬───────────┘                                      │
│           │                                                  │
│           ▼                                                  │
│  ┌────────────────────┐                                      │
│  │ MCP Server (child) │  spawned as subprocess               │
│  │ e.g. npx @gmail/   │  communicates via stdio              │
│  │      mcp-server    │                                      │
│  └────────┬───────────┘                                      │
│           │ response                                         │
│           ▼                                                  │
│  ┌────────────────────┐                                      │
│  │ Secret Scan        │  ALL string values                   │
│  │ (~40 rules)        │  same engine as Guard                │
│  └────────┬───────────┘                                      │
│           ▼                                                  │
│  ┌────────────────────┐                                      │
│  │ Injection Scan     │  risky fields per tool family        │
│  │ (55 patterns)      │  same engine as Guard                │
│  └────────┬───────────┘                                      │
│           ▼                                                  │
│  ┌────────────────────┐                                      │
│  │ Risk Assessment    │                                      │
│  │                    │                                      │
│  │ risk >= threshold? │                                      │
│  │ (default: high)    │                                      │
│  └───┬────────────┬───┘                                      │
│      │            │                                          │
│     YES          NO                                          │
│      │            │                                          │
│      ▼            ▼                                          │
│  ┌────────┐  ┌──────────────┐                                │
│  │ BLOCK  │  │ REDACT       │                                │
│  │ Return │  │ secrets →    │                                │
│  │ JSON-  │  │ [REDACTED]   │                                │
│  │ RPC    │  │              │                                │
│  │ error  │  │ injection →  │                                │
│  └────────┘  │ strip markers│                                │
│              └──────┬───────┘                                │
│                     │                                        │
│                     ▼                                        │
│              Clean response                                  │
│                     │                                        │
│                     ▼                                        │
│              Kiro Agent                                      │
└──────────────────────────────────────────────────────────────┘
```

### Setup

```
  Before init --proxy:              After init --proxy:

  .kiro/settings.json               .kiro/settings.json
  {                                  {
    "mcpServers": {                    "mcpServers": {
      "gmail": {                         "gmail": {
        "command": "npx",                  "command": "kiro-cortex",
        "args": ["@gmail/mcp"]             "args": ["proxy",
      }                                      "--target",
    }                                        "npx @gmail/mcp"]
  }                                      }
                                       }
                                     }
```

---

## 🧠 Memory Module (v2.0)

### Vấn đề mà Memory giải quyết

```
  Không có Memory:                     Có Memory:

  Session 1: Setup Docker             Session 1: Setup Docker
  Session 2: "Docker là gì?"          Session 2: Agent đã biết
             Agent quên hết ❌                    project dùng Docker ✅
```

### Memory Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Memory Capture Flow                       │
│                                                             │
│  PostToolUse hook fires                                     │
│       │                                                     │
│       ▼                                                     │
│  ┌──────────────┐                                           │
│  │ Guard runs   │  scan secrets + injection                 │
│  │ FIRST        │  redact if needed                         │
│  └──────┬───────┘                                           │
│         │ redacted content                                  │
│         ▼                                                   │
│  ┌──────────────┐                                           │
│  │ Memory       │                                           │
│  │ captures     │                                           │
│  │              │                                           │
│  │ tool_name    │                                           │
│  │ + input      │                                           │
│  │   summary    │                                           │
│  │ + response   │  ◀── verbatim but REDACTED                │
│  │   (redacted) │      raw secrets never stored             │
│  └──────┬───────┘                                           │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐                                           │
│  │ Chunk        │  ~800 chars per chunk                     │
│  │ + Dedup      │  SHA-256 hash, 30s window                 │
│  │ + Store      │  SQLite write (<5ms)                      │
│  └──────┬───────┘                                           │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐                                           │
│  │ Embedding    │  deferred to Stop hook                    │
│  │ (async)      │  or background computation                │
│  └──────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

### Memory Retrieval — 4-Layer Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    Memory Retrieval                          │
│                                                             │
│  AgentSpawn hook                                            │
│       │                                                     │
│       ├──▶ L0: Identity (~100 tokens)                       │
│       │    User prefs from config                           │
│       │    "Always use TypeScript, prefer pnpm"             │
│       │                                                     │
│       └──▶ L1: Essential Story (~500-800 tokens)            │
│            Top chunks by importance score                    │
│            "Project uses Docker + PostgreSQL + React 18"     │
│                                                             │
│  UserPromptSubmit hook                                      │
│       │                                                     │
│       └──▶ L2: On-demand (~200-500 tokens)                  │
│            Semantic search matching current prompt           │
│            "Last time you set up Redis, you used..."         │
│                                                             │
│  Agent requests (via MCP)                                   │
│       │                                                     │
│       └──▶ L3: Deep Search (unlimited)                      │
│            Full hybrid search                                │
│            Agent decides what to use                         │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  STDOUT combination (AgentSpawn):                   │    │
│  │                                                     │    │
│  │  [Kiro Cortex Security Context]                       │    │
│  │  ...guard defense instructions...                   │    │
│  │  [/Kiro Cortex Security Context]                      │    │
│  │                                                     │    │
│  │  [Kiro Cortex Memory Context]                         │    │
│  │  ...L0 identity + L1 essential memories...          │    │
│  │  [/Kiro Cortex Memory Context]                        │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Hybrid Search Engine

```
┌─────────────────────────────────────────────────────────────┐
│                    Hybrid Search                            │
│                                                             │
│  Query: "How did we set up the database?"                   │
│       │                                                     │
│       ├──────────────────┐                                  │
│       ▼                  ▼                                  │
│  ┌──────────┐     ┌───────────┐                             │
│  │ Vector   │     │ BM25      │                             │
│  │ Search   │     │ Keyword   │                             │
│  │          │     │ Search    │                             │
│  │ cosine   │     │ SQLite    │                             │
│  │ similar  │     │ FTS5      │                             │
│  │ (3x over │     │           │                             │
│  │  fetch)  │     │           │                             │
│  └────┬─────┘     └─────┬─────┘                             │
│       │                 │                                   │
│       ▼                 ▼                                   │
│  ┌──────────────────────────┐                               │
│  │  Hybrid Re-rank          │                               │
│  │                          │                               │
│  │  0.6 × vector_score      │                               │
│  │  0.4 × bm25_score        │                               │
│  │                          │                               │
│  │  → Top-N results         │                               │
│  └──────────────────────────┘                               │
└─────────────────────────────────────────────────────────────┘
```

### Knowledge Graph (v2.5)

```
┌─────────────────────────────────────────────────────────────┐
│                 Temporal Knowledge Graph                     │
│                                                             │
│  Entities:                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ project  │  │ React 18 │  │ Postgres │  │  Alice   │   │
│  │ (project)│  │ (concept)│  │ (service)│  │ (person) │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │              │              │              │         │
│  Triples (with temporal validity):                          │
│       │              │              │              │         │
│       ├──── uses ───▶│              │              │         │
│       │    (2026-03 → now)          │              │         │
│       │                             │              │         │
│       ├──── uses ──────────────────▶│              │         │
│       │    (2026-01 → now)          │              │         │
│       │                                            │         │
│       │              ┌──── owns ───────────────────┤         │
│       │              │    (2026-02 → now)                    │
│       │              │                                       │
│       ├── used ──▶ [React 17]                               │
│       │   (2025-06 → 2026-03) ◀── INVALIDATED              │
│       │                                                     │
│  Query: "What does project use AS OF today?"                │
│  → React 18, PostgreSQL (valid_to = NULL)                   │
│  → React 17 excluded (valid_to = 2026-03)                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Execution Order — Guard Before Memory

Invariant: Guard ALWAYS runs before Memory trong cùng một hook invocation.

```
┌─────────────────────────────────────────────────────────────┐
│              Hook Invocation (e.g. PostToolUse)             │
│                                                             │
│  STDIN: HookEvent JSON                                      │
│       │                                                     │
│       ▼                                                     │
│  ┌──────────────────┐                                       │
│  │  1. GUARD        │  Scan secrets + injection             │
│  │     (always      │  Redact matched_text                  │
│  │      first)      │  Determine exit code                  │
│  └────────┬─────────┘                                       │
│           │                                                 │
│           │  guard_result: { findings, exit_code,           │
│           │                  redacted_content }             │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │  2. MEMORY       │  Receives POST-redaction content      │
│  │     (after       │  Never sees raw secrets               │
│  │      guard)      │  Captures verbatim (redacted)         │
│  └────────┬─────────┘                                       │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │  3. OUTPUT       │  Combine guard + memory outputs       │
│  │                  │  Guard exit code takes priority        │
│  │                  │  If guard exit ≠ 0: memory skips      │
│  │                  │  injection (but still captures)        │
│  └──────────────────┘                                       │
│                                                             │
│  WHY THIS ORDER:                                            │
│  ✅ Memory never stores raw secrets                         │
│  ✅ Guard block → memory records "blocked" event            │
│  ✅ Guard exit non-zero → memory skips STDOUT injection     │
│  ❌ If reversed: memory could store pre-redaction content   │
└─────────────────────────────────────────────────────────────┘
```

---

## Performance

```
┌─────────────────────────────────────────────────────────────┐
│                    Latency Budget                           │
│                                                             │
│  Hook              Guard        Memory        Total         │
│  ─────────────────────────────────────────────────────      │
│  AgentSpawn        <1ms         <10ms         <11ms         │
│  UserPromptSubmit  <1ms         <50ms*        <51ms         │
│  PreToolUse        <1ms         N/A           <1ms          │
│  PostToolUse       <1ms         <5ms          <6ms          │
│  Stop              <1ms         <100ms**      <101ms        │
│                                                             │
│  * L2 semantic search                                       │
│  ** Batch embedding computation                             │
│                                                             │
│  MCP Proxy         <10ms per call (scan + redact)           │
│                                                             │
│  Performance guardrails:                                    │
│  • max 1MB per string value (truncate beyond)               │
│  • max 10 levels JSON nesting                               │
│  • max 1000 string values per tool_input                    │
│  • Embedding deferred — never blocks hook response          │
└─────────────────────────────────────────────────────────────┘
```

---

## Version Roadmap

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  v1.0  ████████████████░░░░░░░░░░░░░░░░░░░░  Guard         │
│        Hooks, secret scan, injection detect,                │
│        path block, audit logging                            │
│                                                             │
│  v1.5  ████████████████████████░░░░░░░░░░░░  + Proxy + HITL│
│        MCP Proxy (scan+redact+block),                       │
│        allow-once, report, session summary                  │
│                                                             │
│  v2.0  ████████████████████████████████░░░░  + Memory       │
│        Verbatim capture, semantic search,                   │
│        context injection, session lifecycle                 │
│                                                             │
│  v2.5  ████████████████████████████████████  + Intelligence │
│        Knowledge Graph, Memory CLI/MCP,                     │
│        conversation import                                  │
│                                                             │
│  v3.0  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  + ML           │
│        Tier 2 ML detection, auto-tune,                      │
│        dashboard, team policy                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```
