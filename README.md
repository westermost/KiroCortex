# Kiro Cortex

> Protect AI Agents from Prompt Injection, sensitive data leakage, and provide persistent memory across sessions.

[🇻🇳 Tiếng Việt](README_VN.md)

Kiro Cortex is a Rust CLI binary that integrates into [Kiro CLI](https://kiro.dev/cli/) and [Kiro IDE](https://kiro.dev/) via the Hooks system. It runs automatically every time the agent reads a file, executes a command, receives tool results, or when you submit a prompt — no workflow changes needed.

---

## How It Works

Kiro Cortex has 3 core modules:

| Module | Role |
|---|---|
| `Guard` | Block, warn, detect via Kiro Hooks |
| `Proxy` | Scan and sanitize MCP responses before the agent sees them |
| `Memory` | Store, search, inject context across sessions |

### Hook Lifecycle

```text
AgentSpawn        → inject defense instructions + memory L0/L1
UserPromptSubmit  → scan prompt for secrets + inject memory L2
PreToolUse        → check sensitive paths + scan tool_input → block/warn/allow
PostToolUse       → scan tool_response for secrets + injection → warn + store memory
Stop              → write session summary + flush session state
```

### PreToolUse Enforcement Flow

```text
PreToolUse input
  → extra_allow? → yes: skip path checks
  → sensitive path matched?
     → block rule: exit 2
     → warn rule: exit 1, continue to content scan
  → scan tool_input content
     → secret found: exit 2
     → clean: exit 0
```

### MCP Proxy Sanitize Flow

```text
MCP response → secret scan → injection scan → redact secrets
  → neutralize injection text → risk >= critical: return MCP error
  → otherwise: forward sanitized response
```

### Memory Stack

```text
L0 Identity        (~100 tokens, always loaded)  — user preferences, project context
L1 Essential Story  (~500-800 tokens)             — key decisions, important context
L2 On-demand Recall (~200-500 tokens)             — semantic retrieval by current prompt
L3 Deep Search      (unlimited, via MCP/CLI)      — broader search on request
```

📖 **[Detailed Architecture →](docs/how-it-works.md)**

---

## Features

### 🛡️ Block Sensitive File Access

Blocks the agent from reading files containing secrets before the tool executes.

```
You: "Read the .env file"
⛔ Kiro Cortex: Blocked read — sensitive file detected
   Path: .env
   Rule: sf-dotenv (basename)
```

~30 built-in patterns: `.env`, `*.pem`, `*.key`, `id_rsa`, `.aws/credentials`, `kubeconfig`, `terraform.tfvars`, `secrets.yaml`...

### 🔑 Detect Secrets in All Tool Input

Scans all string values in tool input — not just file paths.

```
⛔ Kiro Cortex: Blocked shell — secret detected in tool input
   Rule: [openai-api-key] sk-p****c123
   Field: command
```

Catches: `curl -H 'Bearer sk-...'`, `OPENAI_API_KEY=sk-... python`, `write("f", "AKIA...")`.

~40 rules: AWS, GCP, Azure, OpenAI, Anthropic, GitHub, GitLab, Stripe, Slack, JWT, private keys, database URIs...

### 🔍 Detect Prompt Injection

70 regex patterns, 8 categories. Scans tool responses for injection attempts.

```
⚠ Kiro Cortex [gmail_get_message]: 2 finding(s)
  Injection:
    - body: [ignore_previous] risk=high
    - subject: [role_assumption] risk=medium
```

### 🔐 Protect Secrets in Prompts

When you paste an API key into a prompt:
- **"context" mode** (default): LLM receives instruction not to repeat the secret
- **"warn" mode**: You see a warning + redacted preview

### 🔄 MCP Proxy — Scan + Redact MCP Responses

**Problem**: PostToolUse hooks can only warn about secrets/injection in tool responses — they can't modify or block the response. The agent still sees raw secrets from MCP tools (Gmail, GitHub, Slack, databases...).

**Solution**: MCP Proxy sits between the agent and MCP servers, intercepting responses before the agent sees them.

```
Without Proxy:                      With Proxy:
Agent → MCP Server → raw response   Agent → Kiro Cortex Proxy → MCP Server
         ↓                                        ↓
  Agent sees raw secrets ❌            Scan → Redact → Neutralize
                                               ↓
                                    Agent sees clean response ✅
```

**What it does**:
- **Redacts secrets**: `"API key: sk-proj-FAKE00"` → `"API key: [REDACTED by Kiro Cortex]"`
- **Neutralizes injection**: Strips `SYSTEM:`, `[INST]`, and detected injection text
- **Blocks critical risk**: Returns MCP error instead of dangerous response

**When to use**: If your agent uses MCP tools that access external content (email, chat, documents, PRs, databases). Without proxy, secrets and injection in MCP responses bypass guard protection.

**Setup**:

```bash
# Automatic: wraps all MCP servers in .kiro/settings.json
kiro-cortex init --proxy

# What it does to your config:
# Before: { "mcpServers": { "gmail": { "command": "npx", "args": ["@gmail/mcp"] } } }
# After:  { "mcpServers": { "gmail": { "command": "kiro-cortex", "args": ["proxy", "--target", "npx @gmail/mcp"] } } }

# Verify
kiro-cortex check

# Remove proxy (restore original MCP server commands)
kiro-cortex uninstall --proxy
```

**Manual setup** (single MCP server):

```json
{
  "mcpServers": {
    "gmail": {
      "command": "kiro-cortex",
      "args": ["proxy", "--target", "npx @gmail/mcp-server"]
    }
  }
}
```

**Config** (`.kiro/cortex.toml`):

```toml
[proxy]
enabled = true
risk_threshold = "high"        # Block at "high" or "critical" risk
redact_secrets = true           # Replace secrets with [REDACTED]
neutralize_injection = true     # Strip/neutralize injection patterns
```

### 🔓 Interactive Override

```
⛔ Kiro Cortex: Blocked read — sf-dotenv
   To override: kiro-cortex allow-once sf-dotenv --session abc-123
```

Session-scoped override. Logged in audit. Does not affect other sessions.

### 📝 User Feedback + Auto-Tune

Report false positives to build feedback data:

```bash
kiro-cortex report a1b2c3d4 false-positive --rule sf-dotenv-wildcard --note "Test fixture"
```

Then auto-tune rules based on accumulated feedback:

```bash
# Review suggestions (dry-run, no changes)
kiro-cortex tune

# Apply to config (creates backup + audit trail)
kiro-cortex tune --apply
```

```
Found 2 suggestion(s):

  1. Rule: sf-dotenv-wildcard (3/3 FP, 100%)
     → Add to [sensitive_files] disable_builtin: "sf-dotenv-wildcard"
  2. Rule: generic-api-key (3/4 FP, 75%)
     → Raise entropy for rule 'generic-api-key': 3.5 → 4.0

Applied to project config: .kiro/cortex.toml
  ✅ Backup saved: .kiro/cortex.toml.bak
  ✅ Disabled builtin rule: 'sf-dotenv-wildcard'
  ✅ Audit trail: .kiro/cortex-tune-audit.jsonl
```

Guardrails: dry-run by default, config backup before changes, audit trail, safe regex patterns, minimum sample size required.

### 🧠 Persistent Memory

Kiro Cortex remembers context across sessions — the agent doesn't lose knowledge when a new session starts.

```
Session 1: You set up Docker + PostgreSQL
Session 2: Agent already knows the project uses Docker + PostgreSQL
            (Kiro Cortex injects memory context automatically)
```

**Knowledge Graph**: Tracks entities + relationships with temporal validity.

**Embedding Retrieval** (optional): For higher recall on semantic queries, enable embedding search:

```bash
# Build with embedding support
cargo build --release --features embedding

# Download model on first use (~22MB, stored in ~/.kiro/models/)
kiro-cortex memory init
```

Default search uses BM25 (keyword matching, no model needed). With `--features embedding`, search uses hybrid BM25 + vector similarity for ~98% recall.

**Reindexing existing memory:**

After enabling embedding on a project that already has memory chunks, run reindex to backfill vectors:

```bash
kiro-cortex memory reindex
```
```
✅ Reindex complete
  Model: minilm-l6-v2-int8
  Indexed: 500
  Skipped: 0 (empty)
  Errors: 0
  Total chunks: 500
  Elapsed: 12.3s
```

Run `memory reindex` when:
- After `memory init` (first time enabling embedding on existing data)
- After upgrading the embedding model
- After a large `memory import` if you want full hybrid search coverage

### 📊 Audit Logging

JSON lines log. `matched_text` is **never** written to disk. Only `redacted_preview`.

### 🔇 Audit Mode

Zero behavior change. No blocking, no warnings, no context injection, no memory writes. Only audit log. Opt-in for observation before enforcing.

```toml
mode = "audit"  # Opt-in. Default is "enforce".
```

---

## Installation & Setup

### Option 1: Download Pre-built Binary (recommended)

No Rust required. Download the binary for your OS from [GitHub Releases](../../releases/latest):

**Standard** (~7MB) — Guard + Proxy + Memory with BM25 search:

| OS | File |
|---|---|
| Linux x64 | `kiro-cortex-linux-x64` |
| Linux ARM64 | `kiro-cortex-linux-arm64` |
| macOS Intel | `kiro-cortex-macos-x64` |
| macOS Apple Silicon | `kiro-cortex-macos-arm64` |
| Windows x64 | `kiro-cortex-windows-x64.exe` |

**With Embedding** (~33MB) — adds hybrid BM25 + vector semantic search:

| OS | File |
|---|---|
| Linux x64 | `kiro-cortex-embedding-linux-x64` |
| macOS Apple Silicon | `kiro-cortex-embedding-macos-arm64` |

> Windows / macOS Intel: build from source with `cargo build --release --features embedding`

```bash
# Linux / macOS
chmod +x kiro-cortex-*
sudo mv kiro-cortex-* /usr/local/bin/kiro-cortex

# For embedding version:
# sudo mv kiro-cortex-embedding-* /usr/local/bin/kiro-cortex
# kiro-cortex memory init  # download model (~22MB)

# Windows: copy to a directory in PATH and rename to kiro-cortex.exe
```

Verify: `kiro-cortex --help`

Then skip to **Step 4: Setup for your project**.

---

### Option 2: Build from Source

**Step 1: Install Rust** (if not already installed)

**Linux / macOS:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

**Windows:**
- Download and run [rustup-init.exe](https://rustup.rs)
- Requires [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) ("Desktop development with C++")

**Step 2: Build**

```bash
git clone <repo>
cd KiroCortex
cargo build --release
# First build downloads dependencies (~2 min)
# Binary: target/release/kiro-cortex (6.8MB)

# Optional: build with embedding support for semantic memory search
cargo build --release --features embedding
# Binary: target/release/kiro-cortex (~29MB, includes ONNX Runtime)
```

**Step 3: Add to PATH**

**Linux:**
```bash
cp target/release/kiro-cortex ~/.local/bin/
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

**macOS:**
```bash
cp target/release/kiro-cortex /usr/local/bin/
```

**Windows (PowerShell):**
```powershell
copy target\release\kiro-cortex.exe $env:USERPROFILE\.cargo\bin\
```

### Step 4: Setup for Your Project

```bash
# Option A: cd into project, then init
cd ~/projects/my-app
kiro-cortex init

# Option B: specify path (no cd needed)
kiro-cortex init --path ~/projects/my-app

# Option C: global — applies to ALL projects, one-time setup
kiro-cortex init --global
```

| Method | Creates files in | Applies to |
|---|---|---|
| `kiro-cortex init` | `<project>/.kiro/` | This project only |
| `kiro-cortex init --path <dir>` | `<dir>/.kiro/` | That project only |
| `kiro-cortex init --global` | `~/.kiro/` | All projects |

Global + project configs can coexist. Project config overrides global.

### Step 5: Verify

```bash
kiro-cortex check
```
```
✅ Config parseable
✅ Agent config exists
✅ All 5 hooks present
✅ Hook ownership correct
✅ Binary accessible
✅ No duplicate hooks
```

### Step 6 (optional): Switch to Audit Mode

Default is `enforce` mode (active protection). To observe only before enforcing:
```toml
# Edit .kiro/cortex.toml
mode = "audit"
```

### Uninstall

```bash
kiro-cortex uninstall                            # Remove project hooks
kiro-cortex uninstall --path ~/projects/my-app   # Remove specific project hooks
kiro-cortex uninstall --global                   # Remove global hooks
```

### Manual Setup (Kiro CLI)

Add directly to `.kiro/agents/default.json`:

```json
{
  "name": "default",
  "hooks": {
    "agentSpawn": [{ "command": "kiro-cortex hook spawn" }],
    "userPromptSubmit": [{ "command": "kiro-cortex hook prompt" }],
    "preToolUse": [{ "matcher": "*", "command": "kiro-cortex hook pre-tool" }],
    "postToolUse": [{ "matcher": "*", "command": "kiro-cortex hook post-tool" }],
    "stop": [{ "command": "kiro-cortex hook stop" }]
  }
}
```

### Manual Setup (Kiro IDE)

`Cmd+Shift+P` → "Kiro: Open Kiro Hook UI" → Create 5 hooks:

| # | Event | Command |
|---|---|---|
| 1 | Agent Spawn | `kiro-cortex hook spawn` |
| 2 | Prompt Submit | `kiro-cortex hook prompt` |
| 3 | Pre Tool Use (`*`) | `kiro-cortex hook pre-tool` |
| 4 | Post Tool Use (`*`) | `kiro-cortex hook post-tool` |
| 5 | Agent Stop | `kiro-cortex hook stop` |

---

## Config

File: `.kiro/cortex.toml` (project) or `~/.kiro/cortex.toml` (global). Project overrides global.

```toml
mode = "enforce"  # "enforce" (default) | "audit"

[log]
path = "~/.kiro/cortex-audit.jsonl"
max_size_mb = 50
max_files = 5

[injection]
enable_tier1 = true

[prompt_scan]
enabled = true
on_detect = "context"  # "context" | "warn"

[sensitive_files]
disable_builtin = []
extra_deny = []
extra_allow = [".env.example", ".env.template"]

[[secret_rules]]
id = "internal-api-key"
regex = 'myco_[a-zA-Z0-9]{32}'
keywords = ["myco_"]
severity = "high"
action = "detect"

[allowlist]
regexes = ['AKIAIOSFODNN7EXAMPLE']
stopwords = ["test", "dummy", "sample"]

[proxy]
enabled = true
risk_threshold = "high"
redact_secrets = true
neutralize_injection = true

[memory]
enabled = true
scope = "project"
max_context_tokens = 2000
auto_inject = true
```

---

## CLI Commands

| Command | Description |
|---|---|
| `kiro-cortex init [--force] [--proxy] [--global] [--path <dir>]` | Auto setup |
| `kiro-cortex uninstall [--proxy] [--global] [--path <dir>]` | Remove hooks |
| `kiro-cortex check [--global] [--path <dir>]` | Verify setup |
| `kiro-cortex scan <path>` | Scan file/directory |
| `kiro-cortex audit summary [--since 7d]` | Audit log summary |
| `kiro-cortex allow-once <rule> --session <id>` | Override block |
| `kiro-cortex report <id> <verdict> [--rule <rule-id>] [--note "..."]` | Report finding |
| `kiro-cortex proxy --target <cmd>` | MCP Proxy |
| `kiro-cortex memory search <query>` | Search memory |
| `kiro-cortex memory stats` | Memory statistics |
| `kiro-cortex memory import <path>` | Import conversations |
| `kiro-cortex memory forget --before <date>` | Delete old memories |
| `kiro-cortex memory reindex` | Backfill/rebuild vectors for all chunks |
| `kiro-cortex tune` | Auto-tune: suggest config changes from feedback (dry-run) |
| `kiro-cortex tune --apply` | Apply tune suggestions to config (with backup) |

---

## Benchmarks

| Suite | What it measures |
|---|---|
| `benchmarks/run.sh` | Internal regression: hooks, path blocking, content scan, audit mode |
| `benchmarks/public_benchmark.py` | Public prompt injection + secret detection |
| `benchmarks/memory_benchmark.py` | Memory (3 layers): retrieval_quality, e2e_hook, store_only |
| `benchmarks/bipia_benchmark.py` | Indirect prompt injection (full BIPIA dataset when available, fallback mini-suite otherwise) |
| `benchmarks/longmemeval_benchmark.py` | Retrieval approximation on LongMemEval public memory dataset |
| `benchmarks/locomo_benchmark.py` | Retrieval approximation on LoCoMo multi-session conversations |
| `benchmarks/beir_benchmark.py` | Retrieval engine quality — NDCG@5, Recall@5 on BEIR SciFact |
| `benchmarks/embedding_benchmark.py` | BM25 vs Hybrid comparison + reindex benchmark |

### Current Results

| Metric | Injection | Secrets | Memory |
|---|---|---|---|
| Precision | 1.000 | 0.909 | — |
| Recall | 0.296 | 0.909 | 0.900 (R@5, BM25) |

> **Note**: With `--features embedding` build + `kiro-cortex memory init`, memory retrieval reaches **Recall@5=1.000** via hybrid BM25+vector search. The BM25-only results above are the default (no model) baseline. Embedding adds ~250ms latency per search but dramatically improves semantic recall.
| FP Rate | 0.000 | 0.143 | — |
| Avg Latency | 69ms | 71ms | 29ms (search) |
| Cases | 155 | 18 | 10 queries |

### Run Benchmarks

```bash
cargo build --release

# All benchmarks (public datasets auto-downloaded + cached)
bash benchmarks/all.sh

# Skip slow public benchmarks
SKIP_PUBLIC=1 bash benchmarks/all.sh

# Individual
./benchmarks/run.sh                                # Internal regression
python3 benchmarks/public_benchmark.py --mode all  # Injection + secrets
python3 benchmarks/memory_benchmark.py             # Memory (3 layers)
python3 benchmarks/bipia_benchmark.py              # BIPIA indirect injection
python3 benchmarks/longmemeval_benchmark.py        # LongMemEval memory
python3 benchmarks/locomo_benchmark.py             # LoCoMo multi-session
python3 benchmarks/beir_benchmark.py               # BEIR retrieval (SciFact)
```

### Benchmark Metadata

Every JSON benchmark report now includes:

- `generated_at`, `cortex_bin`, binary hash/size
- `rounds`, `warmup_runs`
- `dataset_mode`, `sample_size` when applicable
- `config` for benchmark-specific knobs
- `datasets[]` with source URL plus cached/local file path and SHA-256 when available

This makes results easier to reproduce and helps detect dataset drift after cache refreshes.

### Benchmark Caveats

- `public_benchmark.py` is strong for regression, but secret detection still uses a small curated public corpus; treat it as a smoke benchmark, not a full industry leaderboard.
- `bipia_benchmark.py` may run in `dataset_mode = "fallback"` if the public dataset cannot be downloaded. Do not compare fallback scores with full-dataset scores.
- `longmemeval_benchmark.py` and `locomo_benchmark.py` are retrieval approximations on public datasets, not full replications of the original paper protocols.
- `memory_benchmark.py` reports both `e2e_hook` and `store_only`; use `store_only` for memory-engine tuning and `e2e_hook` for real guard+memory overhead.
- `beir_benchmark.py` currently defaults to SciFact. Treat it as a public IR baseline, not a complete MTEB/BEIR sweep.

---

## Examples

### Agent tries to read .env

```
You: "Check the environment variables in .env"
⛔ Kiro Cortex: Blocked read — sensitive file detected
   Path: .env
   Rule: sf-dotenv (basename)
Agent: "I can't read .env as it contains sensitive data."
```

### MCP Proxy redacts email with secret

```
Without proxy: Agent receives "Here's the API key: sk-proj-FAKE00000000"
With proxy:    Agent receives "Here's the API key: [REDACTED by Kiro Cortex]"
```

### Memory across sessions

```
Session 1: You set up PostgreSQL with Docker Compose
Session 2: Agent already knows → adds Redis to existing docker-compose.yml
```

### Audit → Enforce workflow

```bash
# Week 1: Observe
kiro-cortex init --global  # enforce mode by default

# Week 2: Review
kiro-cortex audit summary --since 7d
# → 23 .env reads, 12 API key detections, 0 false positives

# Week 3: Enforce
# Edit ~/.kiro/cortex.toml: mode = "enforce"
```

---

## FAQ

**Q: Does Kiro Cortex slow down the agent?**
A: Negligibly. Guard hooks run <1ms. MCP Proxy adds ~1-10ms per call. Memory capture <5ms.

**Q: What happens when a tool is blocked?**
A: The agent receives a message explaining why. It usually suggests an alternative. Or you can use `allow-once` to override.

**Q: Do custom secret rules block at PreToolUse?**
A: Yes. All rules block at PreToolUse. Config `action = "detect"` only affects PostToolUse/UserPromptSubmit.

**Q: Does memory store raw secrets?**
A: No. Guard redacts first, memory captures after. Memory only stores the redacted version.

**Q: Does audit mode write memory?**
A: No. Memory capture only runs in enforce mode. Audit mode does not create `.kiro/cortex-memory.db`.

---

## Project Structure

```
src/
├── main.rs               Entry point, CLI dispatch
├── cli.rs                Clap derive, all subcommands
├── config.rs             TOML config, defaults, merge, validation
├── hook_event.rs         HookEvent JSON parsing from STDIN
├── result.rs             HookResult, exit code contract
├── handlers.rs           All hook handlers + scan + init wiring
├── path_matcher.rs       Sensitive file denylist, shell parser, path extraction
├── secret_scanner.rs     26 built-in rules, entropy, allowlist, redaction
├── injection_scanner.rs  70 patterns, 8 categories, unicode normalization
├── audit.rs              JSON lines logger, rotation, finding_id
├── init.rs               Init/uninstall/check, idempotent
├── proxy.rs              MCP Proxy: JSON-RPC intercept, scan, redact, block
├── hitl.rs               allow-once, report feedback, session summary
├── tune.rs               Auto-tune: analyze feedback, suggest + apply config changes
└── memory.rs             SQLite storage, BM25 search, session lifecycle, KG

tests/test_cli.rs         23 E2E integration tests
benchmarks/               Internal + public + memory benchmarks
.kiro/steering/           12 steering files (Kiro auto-loads)
docs/                     Architecture diagrams, implementation plan, TDD plan
```

---

## License

MIT
