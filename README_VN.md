# Kiro Cortex

> Bảo vệ AI Agent khỏi Prompt Injection, rò rỉ dữ liệu nhạy cảm, và cung cấp persistent memory across sessions.

Kiro Cortex là một Rust CLI binary tích hợp vào [Kiro CLI](https://kiro.dev/cli/) và [Kiro IDE](https://kiro.dev/) qua hệ thống Hooks. Nó chạy tự động mỗi khi agent đọc file, chạy lệnh, nhận kết quả tool, hoặc khi bạn gửi prompt — không cần thay đổi workflow.

---

## How It Works

Kiro Cortex có 3 khối chính:

| Khối | Vai trò |
|---|---|
| `Guard` | Block, warn, detect qua Kiro Hooks |
| `Proxy` | Scan và sanitize MCP responses trước khi agent nhận |
| `Memory` | Store, search, inject context across sessions |

### Hook lifecycle

```text
AgentSpawn
  -> inject defense instructions
  -> inject memory L0/L1

UserPromptSubmit
  -> scan prompt for secrets
  -> context mode: inject protective context
  -> warn mode: show warning to user

PreToolUse
  -> check sensitive paths
  -> scan tool_input for secrets
  -> block / warn / allow

PostToolUse
  -> scan tool_response for secrets + injection
  -> warn + audit log
  -> store sanitized memory (if enabled)

Stop
  -> write session summary
  -> flush session state
```

### PreToolUse enforcement

```text
PreToolUse input
  -> extra_allow?
     -> yes: skip path checks
     -> no: sensitive path matched?
        -> block rule: exit 2
        -> warn rule: exit 1, continue
        -> no match: scan tool_input content
           -> secret found: exit 2
           -> clean: exit 0
```

### MCP proxy sanitize flow

```text
MCP response
  -> secret scan
  -> injection scan
  -> redact secrets
  -> neutralize injection text
  -> risk >= critical: return MCP error
  -> otherwise: forward sanitized response
```

### Memory stack

```text
L0 Identity
  -> user preferences, project identity

L1 Essential Story
  -> key decisions and important context

L2 On-demand Recall
  -> semantic retrieval by current prompt

L3 Deep Search
  -> broader search via MCP / CLI
```

## Tính năng

### 🛡️ Chặn đọc file nhạy cảm

Kiro Cortex chặn agent đọc các file chứa secrets trước khi tool thực thi.

```
Bạn: "Đọc file .env để xem config"
⛔ Kiro Cortex: Blocked read — sensitive file detected
   Path: .env
   Rule: sf-dotenv (basename)
```

~30 patterns mặc định: `.env`, `*.pem`, `*.key`, `id_rsa`, `.aws/credentials`, `kubeconfig`, `terraform.tfvars`, `secrets.yaml`...

### 🔑 Phát hiện secrets trong mọi tool input

Scan tất cả string values trong tool input — không chỉ file paths.

```
⛔ Kiro Cortex: Blocked shell — secret detected in tool input
   Rule: [openai-api-key] sk-p****c123
   Field: command
```

Bắt được: `curl -H 'Bearer sk-...'`, `OPENAI_API_KEY=sk-... python`, `write("f", "AKIA...")`.

~40 rules: AWS, GCP, Azure, OpenAI, Anthropic, GitHub, GitLab, Stripe, Slack, JWT, private keys, database URIs...

### 🔍 Phát hiện Prompt Injection

70 regex patterns, 8 categories. Scan tool responses cho injection attempts.

```
⚠ Kiro Cortex [gmail_get_message]: 2 finding(s)
  Injection:
    - body: [ignore_previous] risk=high
    - subject: [role_assumption] risk=medium
```

### 🔐 Bảo vệ secrets trong prompt

Khi bạn paste API key vào prompt:
- **Mode "context"** (mặc định): LLM nhận instruction không lặp lại secret
- **Mode "warn"**: Bạn thấy cảnh báo + redacted preview

### 🔄 MCP Proxy — Scan + Redact MCP Responses

**Vấn đề**: PostToolUse hooks chỉ có thể cảnh báo về secrets/injection trong tool response — không thể sửa hay chặn response. Agent vẫn thấy raw secrets từ MCP tools (Gmail, GitHub, Slack, databases...).

**Giải pháp**: MCP Proxy đứng giữa agent và MCP server, chặn response trước khi agent nhận.

```
Không có Proxy:                     Có Proxy:
Agent → MCP Server → raw response   Agent → Kiro Cortex Proxy → MCP Server
         ↓                                        ↓
  Agent thấy raw secrets ❌            Scan → Redact → Neutralize
                                               ↓
                                    Agent thấy clean response ✅
```

**Proxy làm gì**:
- **Redact secrets**: `"API key: sk-proj-FAKE00"` → `"API key: [REDACTED by Kiro Cortex]"`
- **Neutralize injection**: Xóa `SYSTEM:`, `[INST]`, và text injection đã phát hiện
- **Block critical risk**: Trả MCP error thay vì response nguy hiểm

**Khi nào cần dùng**: Khi agent dùng MCP tools truy cập nội dung bên ngoài (email, chat, documents, PRs, databases). Không có proxy, secrets và injection trong MCP response sẽ bypass guard protection.

**Setup**:

```bash
# Tự động: wrap tất cả MCP servers trong .kiro/settings.json
kiro-cortex init --proxy

# Nó làm gì với config:
# Trước: { "mcpServers": { "gmail": { "command": "npx", "args": ["@gmail/mcp"] } } }
# Sau:   { "mcpServers": { "gmail": { "command": "kiro-cortex", "args": ["proxy", "--target", "npx @gmail/mcp"] } } }

# Kiểm tra
kiro-cortex check

# Gỡ proxy (khôi phục MCP server commands gốc)
kiro-cortex uninstall --proxy
```

**Setup thủ công** (1 MCP server):

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
risk_threshold = "high"        # Block ở mức "high" hoặc "critical"
redact_secrets = true           # Thay secrets bằng [REDACTED]
neutralize_injection = true     # Xóa/neutralize injection patterns
```

### 🔓 Interactive Override

```
⛔ Kiro Cortex: Blocked read — sf-dotenv
   To override: kiro-cortex allow-once sf-dotenv --session abc-123
```

Override cho session hiện tại. Ghi vào audit log. Không ảnh hưởng session khác.

### 📝 User Feedback + Auto-Tune

Báo cáo false positive để tích lũy feedback:

```bash
kiro-cortex report a1b2c3d4 false-positive --rule sf-dotenv-wildcard --note "Test fixture"
```

Sau đó auto-tune rules dựa trên feedback:

```bash
# Xem gợi ý (dry-run, không thay đổi gì)
kiro-cortex tune

# Áp dụng vào config (tạo backup + audit trail)
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

Guardrails: dry-run mặc định, backup config trước khi sửa, audit trail, regex an toàn, yêu cầu đủ sample size.

### 🧠 Persistent Memory

Kiro Cortex nhớ context across sessions — agent không mất kiến thức khi session mới bắt đầu.

```
Session 1: Bạn setup Docker + PostgreSQL cho project
Session 2: Agent tự biết project dùng Docker + PostgreSQL
            (Kiro Cortex inject memory context tự động)
```

**Knowledge Graph**: Track entities + relationships với temporal validity.

**Embedding Retrieval** (tùy chọn): Để tăng recall cho semantic queries, bật embedding search:

```bash
# Build với embedding support
cargo build --release --features embedding

# Tải model lần đầu (~22MB, lưu vào ~/.kiro/models/)
kiro-cortex memory init
```

Mặc định search dùng BM25 (keyword matching, không cần model). Với `--features embedding`, search dùng hybrid BM25 + vector similarity cho ~98% recall.

> **Lưu ý**: Khi build với `--features embedding` và chạy `kiro-cortex memory init`, memory retrieval có thể đạt **Recall@5 = 1.000** trên benchmark nội bộ nhờ hybrid BM25 + vector search. Đổi lại, latency tăng khoảng `~250ms` mỗi truy vấn search.

**Reindex memory có sẵn:**

Sau khi bật embedding trên project đã có memory chunks, chạy reindex để sinh vectors cho dữ liệu cũ:

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

Chạy `memory reindex` khi:
- Sau `memory init` (bật embedding lần đầu trên dữ liệu có sẵn)
- Sau khi đổi embedding model
- Sau `memory import` lớn nếu muốn hybrid search coverage đầy đủ

### 📊 Audit Logging

JSON lines log. `matched_text` **không bao giờ** được ghi. Chỉ `redacted_preview`.

### 🔇 Audit Mode

Zero behavior change. Không chặn, không cảnh báo, không inject. Chỉ ghi log.

```toml
mode = "audit"  # Opt-in. Mặc định là "enforce".
```

---

## Cài đặt & Setup

### Cách 1: Tải binary có sẵn (khuyến nghị)

Không cần cài Rust. Tải binary cho OS của bạn từ [GitHub Releases](../../releases/latest):

**Standard** (~7MB) — Guard + Proxy + Memory với BM25 search:

| OS | File |
|---|---|
| Linux x64 | `kiro-cortex-linux-x64` |
| Linux ARM64 | `kiro-cortex-linux-arm64` |
| macOS Intel | `kiro-cortex-macos-x64` |
| macOS Apple Silicon | `kiro-cortex-macos-arm64` |
| Windows x64 | `kiro-cortex-windows-x64.exe` |

**With Embedding** (~33MB) — thêm hybrid BM25 + vector semantic search:

| OS | File |
|---|---|
| Linux x64 | `kiro-cortex-embedding-linux-x64` |
| macOS Apple Silicon | `kiro-cortex-embedding-macos-arm64` |

> Windows / macOS Intel: build từ source với `cargo build --release --features embedding`

```bash
# Linux / macOS
chmod +x kiro-cortex-*
sudo mv kiro-cortex-* /usr/local/bin/kiro-cortex

# Nếu dùng bản embedding:
# sudo mv kiro-cortex-embedding-* /usr/local/bin/kiro-cortex
# kiro-cortex memory init  # tải model (~22MB)

# Windows: copy vào thư mục trong PATH, đổi tên thành kiro-cortex.exe
```

Kiểm tra:
```bash
kiro-cortex --help
```

Sau đó nhảy tới **Bước 4: Setup cho project**.

---

### Cách 2: Build từ source

### Bước 1: Cài Rust (nếu chưa có)

Kiro Cortex viết bằng Rust. Cần cài Rust toolchain trước khi build:

**Linux / macOS:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
# Verify
cargo --version
```

**Windows:**
- Tải và chạy [rustup-init.exe](https://rustup.rs)
- Khi hỏi, chọn "1) Proceed with standard installation"
- Cần có [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (chọn "Desktop development with C++")
- Mở terminal mới sau khi cài

### Bước 2: Build binary

```bash
git clone <repo>
cd KiroCortex

cargo build --release
# Lần đầu sẽ tải dependencies (~2 phút)
# Binary tạo ra: target/release/kiro-cortex (6.8MB)

# Tùy chọn: build với embedding support cho semantic memory search
cargo build --release --features embedding
# Binary: target/release/kiro-cortex (~29MB, bao gồm ONNX Runtime)
```

### Bước 3: Thêm vào PATH

**Linux:**
```bash
cp target/release/kiro-cortex ~/.local/bin/
# Nếu ~/.local/bin chưa trong PATH:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**macOS:**
```bash
cp target/release/kiro-cortex /usr/local/bin/
# Hoặc nếu không có quyền sudo:
mkdir -p ~/.local/bin
cp target/release/kiro-cortex ~/.local/bin/
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**Windows (PowerShell):**
```powershell
# Copy vào thư mục đã có trong PATH
copy target\release\kiro-cortex.exe $env:USERPROFILE\.cargo\bin\

# Hoặc thêm thư mục tùy chọn vào PATH:
mkdir -Force "$env:USERPROFILE\.local\bin"
copy target\release\kiro-cortex.exe "$env:USERPROFILE\.local\bin\"
# Thêm vào PATH: Settings → System → About → Advanced → Environment Variables
# Thêm %USERPROFILE%\.local\bin vào Path
```

Kiểm tra:
```bash
kiro-cortex --help
# → "Kiro Cortex — Guard + Proxy + Memory for AI Agents"
```

### Bước 4: Setup cho project

Có 3 cách, chọn 1:

```bash
# Cách A: cd vào project rồi init
cd ~/projects/my-app
kiro-cortex init

# Cách B: chỉ định path (không cần cd)
kiro-cortex init --path ~/projects/my-app

# Cách C: global — apply cho MỌI project, setup 1 lần
kiro-cortex init --global
```

| Cách | Tạo file ở đâu | Apply cho |
|---|---|---|
| `kiro-cortex init` | `<project>/.kiro/` | Chỉ project này |
| `kiro-cortex init --path <dir>` | `<dir>/.kiro/` | Chỉ project đó |
| `kiro-cortex init --global` | `~/.kiro/` | Mọi project |

Global + project dùng chung được. Project config override global.

### Bước 5: Kiểm tra

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

### Bước 6 (tùy chọn): Bật enforce

Mặc định là `enforce` mode (bảo vệ chủ động). Đổi sang `audit` để chỉ quan sát:

```bash
# Sửa config
# mode = "audit"  →  mode = "enforce"
```

### Gỡ cài đặt

```bash
kiro-cortex uninstall                            # Gỡ hooks project hiện tại
kiro-cortex uninstall --path ~/projects/my-app   # Gỡ hooks project cụ thể
kiro-cortex uninstall --global                   # Gỡ hooks global
```

---

### Setup thủ công (Kiro CLI)

Nếu không muốn dùng `kiro-cortex init`, thêm trực tiếp vào `.kiro/agents/default.json`:

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

### Setup thủ công (Kiro IDE)

1. `Cmd+Shift+P` → "Kiro: Open Kiro Hook UI"
2. Tạo 5 hooks:

| # | Event | Command |
|---|---|---|
| 1 | Agent Spawn | `kiro-cortex hook spawn` |
| 2 | Prompt Submit | `kiro-cortex hook prompt` |
| 3 | Pre Tool Use (`*`) | `kiro-cortex hook pre-tool` |
| 4 | Post Tool Use (`*`) | `kiro-cortex hook post-tool` |
| 5 | Agent Stop | `kiro-cortex hook stop` |

---

## Config

File: `.kiro/cortex.toml` (project) hoặc `~/.kiro/cortex.toml` (global).

Project config ưu tiên hơn global. Scalars: project wins. Lists (secret_rules, extra_deny, allowlist): append cả hai.

```bash
kiro-cortex init --global                      # Tạo ~/.kiro/cortex.toml + ~/.kiro/agents/default.json
kiro-cortex init --path ./Document/SourceA     # Tạo ./Document/SourceA/.kiro/cortex.toml (override global)
kiro-cortex init                               # Tạo .kiro/cortex.toml trong CWD (override global)
```

```toml
mode = "enforce"  # "enforce" (mặc định) | "audit"

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
regexes = ['AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY']
stopwords = ["test", "dummy", "sample"]

[proxy]
enabled = true
risk_threshold = "high"
redact_secrets = true
neutralize_injection = true

[memory]
enabled = true
scope = "project"              # "project" | "global"
max_context_tokens = 2000
auto_inject = true
```

---

## CLI Commands

| Command | Mô tả |
|---|---|
| `kiro-cortex init [--force] [--proxy] [--global] [--path <dir>]` | Setup tự động |
| `kiro-cortex uninstall [--proxy] [--global] [--path <dir>]` | Gỡ hooks |
| `kiro-cortex check [--global] [--path <dir>]` | Kiểm tra setup |
| `kiro-cortex scan <path>` | Scan file/thư mục |
| `kiro-cortex audit summary [--since 7d]` | Tóm tắt audit log |
| `kiro-cortex allow-once <rule> --session <id>` | Override block |
| `kiro-cortex report <id> <verdict> [--rule <rule-id>] [--note "..."]` | Báo cáo finding |
| `kiro-cortex proxy --target <cmd>` | MCP Proxy |
| `kiro-cortex memory search <query>` | Search memory |
| `kiro-cortex memory stats` | Memory statistics |
| `kiro-cortex memory import <path>` | Import conversations |
| `kiro-cortex memory forget --before <date>` | Delete old memories |
| `kiro-cortex memory reindex` | Backfill/rebuild vectors cho tất cả chunks |
| `kiro-cortex tune` | Auto-tune: gợi ý thay đổi config từ feedback (dry-run) |
| `kiro-cortex tune --apply` | Áp dụng gợi ý tune vào config (có backup) |

---

## Benchmark

Repo hiện có 3 entrypoint benchmark:

| Script | Mục tiêu |
|---|---|
| `benchmarks/run.sh` | Regression benchmark nội bộ cho hooks, path blocking, content scan, audit mode |
| `benchmarks/public_benchmark.py` | Benchmark public cho prompt injection và secret detection |
| `benchmarks/memory_benchmark.py` | Benchmark memory: retrieval, storage, injection, import CLI |

### Kết quả hiện tại

**1. Internal regression suite**

- `./benchmarks/run.sh`
- Kết quả hiện tại: **34/34 pass**

**2. Public prompt injection benchmark**

Nguồn public dùng để đo:
- `Giskard-AI/prompt-injections`
- `WAInjectBench` text-only subset: `popup`, `wasp`, `email_msg`, `comment_issue`

Kết quả hiện tại trên binary hiện có:

| Metric | Value |
|---|---|
| Cases | `155` |
| True Positive | `34` |
| True Negative | `40` |
| False Positive | `0` |
| False Negative | `81` |
| Precision | `1.0000` |
| Recall | `0.2957` |
| False Positive Rate | `0.0000` |
| Avg latency | `69.3ms` |
| P95 latency | `84.8ms` |

Diễn giải:
- detector hiện rất bảo thủ: gần như không false positive trên benign subset đã chạy
- nhưng recall cho prompt injection vẫn thấp, đặc biệt trên WAInjectBench
- đây là baseline tốt để tune thêm rules hoặc thêm Tier 2 model sau này

**3. Public secret detection benchmark**

Nguồn public dùng để đo:
- curated test vectors từ `Yelp/detect-secrets` plugin tests
- gồm các mẫu OpenAI, AWS, GitHub token, Stripe, private key

Kết quả hiện tại:

| Metric | Value |
|---|---|
| Cases | `18` |
| True Positive | `10` |
| True Negative | `6` |
| False Positive | `1` |
| False Negative | `1` |
| Precision | `0.9091` |
| Recall | `0.9091` |
| False Positive Rate | `0.1429` |
| Avg latency | `70.8ms` |
| P95 latency | `77.0ms` |

Các miss hiện tại tập trung ở một số biến thể AWS/public test vectors; đây là nơi nên ưu tiên tune tiếp.

**4. Memory benchmark**

Memory hiện được benchmark theo 4 nhóm:
- **retrieval quality** trên corpus/query mẫu có ground truth
- **storage / lifecycle** trên synthetic corpus lớn hơn
- **session injection quality** cho `AgentSpawn` và `UserPromptSubmit`
- **CLI import throughput** cho `kiro-cortex memory import`

Nguồn dữ liệu benchmark nằm ngay trong repo:
- `benchmarks/data/memory_corpus.json`
- `benchmarks/data/memory_queries.json`

Kết quả hiện tại:

**Retrieval quality**

| Metric | Value |
|---|---|
| Docs | `12` |
| Queries | `10` |
| Recall@1 | `0.9000` |
| Recall@5 | `0.9000` |
| MRR@5 | `0.9000` |
| Ingest avg | `75.4ms/doc` |
| Search avg | `28.7ms/query` |
| Search P95 | `30.3ms` |
| DB size | `73,728 bytes` |

**Storage / lifecycle**

| Metric | Value |
|---|---|
| Stored chunks | `500` |
| Throughput | `14.2 chunks/s` |
| Ingest avg | `70.4ms/chunk` |
| Search avg | `30.3ms/query` |
| Forget latency | `54.7ms` |
| DB size | `442,368 bytes` |

**Session injection quality**

| Metric | Value |
|---|---|
| Spawn latency | `49.7ms` |
| Spawn contains security context | `true` |
| Spawn contains memory context | `true` |
| Known doc IDs injected at spawn | `10` |
| Prompt hit rate | `0.9000` |
| Prompt avg latency | `46.5ms` |

**CLI import throughput**

| Metric | Value |
|---|---|
| Import docs | `200` |
| Import latency | `958.8ms` |
| Throughput | `208.6 docs/s` |
| DB size | `151,552 bytes` |

Diễn giải:
- memory hiện dùng **SQLite + FTS5 BM25**, chưa phải embedding retrieval
- vì vậy benchmark này đo đúng năng lực hiện tại của memory engine
- Recall còn thấp trên query mẫu hiện tại, nên đây là baseline tốt để so sánh khi bạn cải thiện chunking, indexing, hoặc chuyển sang embedding retrieval
- `memory import` đang nhanh hơn đường ingest qua hooks vì nó chunk file trực tiếp thay vì đi qua full `post-tool` path

### Cách tự chạy lại

**Bước 1: build binary**

```bash
cargo build --release
```

Binary mặc định sẽ nằm ở `./target/release/kiro-cortex`.

**Bước 2: chạy benchmark nội bộ**

```bash
./benchmarks/run.sh
```

Nếu binary ở path khác:

```bash
CORTEX_BIN=/path/to/kiro-cortex ./benchmarks/run.sh
```

**Bước 3: chạy benchmark public**

```bash
python3 benchmarks/public_benchmark.py --mode all
```

Chỉ chạy prompt injection:

```bash
python3 benchmarks/public_benchmark.py --mode injection
```

Chỉ chạy secret detection:

```bash
python3 benchmarks/public_benchmark.py --mode secrets
```

Xuất JSON report:

```bash
python3 benchmarks/public_benchmark.py \
  --mode all \
  --json-out ./benchmarks/latest-public-benchmark.json
```

**Chạy memory benchmark**

```bash
python3 benchmarks/memory_benchmark.py \
  --json-out ./benchmarks/latest-memory-benchmark.json
```

Tăng kích thước storage benchmark:

```bash
python3 benchmarks/memory_benchmark.py \
  --storage-count 1000 \
  --json-out ./benchmarks/latest-memory-benchmark.json
```

**Chạy toàn bộ benchmark một lượt**

```bash
bash benchmarks/all.sh
```

Hoặc chỉ định binary:

```bash
CORTEX_BIN=./target/release/kiro-cortex bash benchmarks/all.sh
```

### Benchmark cache

- Lần chạy đầu, `benchmarks/public_benchmark.py` sẽ tải corpora public và cache vào `benchmarks/.cache/`
- Những lần sau có thể chạy lại từ cache
- Nếu môi trường không có mạng, hãy chạy trước một lần ở môi trường online hoặc pre-seed các file trong `benchmarks/.cache/`

### Benchmark đang đo cái gì

- prompt injection benchmark hiện đo `PostToolUse` detection path
- secret benchmark hiện đo secret scanner trên public test vectors nhỏ, không phải full repo scan benchmark
- memory benchmark hiện đo:
  - retrieval quality của `memory search` trên corpus/query mẫu
  - storage throughput của `post-tool -> memory store`
  - session injection quality của `hook spawn` và `hook prompt`
  - CLI import throughput của `memory import`
  - lifecycle latency của `memory stats` và `memory forget`
- vì vậy các số này nên được xem là **detector benchmark**, không phải benchmark end-to-end của toàn bộ Kiro Cortex

---

## Ví dụ thực tế

### Agent cố đọc .env

```
Bạn: "Xem biến môi trường trong .env"

⛔ Kiro Cortex: Blocked read — sensitive file detected
   Path: .env
   Rule: sf-dotenv (basename)

Agent: "Tôi không thể đọc file .env vì nó chứa thông tin nhạy cảm."
```

### MCP Proxy redact email chứa secret

```
Agent đọc email qua Gmail MCP...

Không có proxy:
  Agent nhận: "Here's the API key: sk-proj-FAKE00000000"
  → LLM thấy raw key → có thể lặp lại

Có proxy:
  Agent nhận: "Here's the API key: [REDACTED by Kiro Cortex]"
  → LLM không thấy key → an toàn
```

### Memory across sessions

```
Session 1 (tuần trước):
  Bạn: "Setup PostgreSQL với Docker Compose"
  Agent: [thực hiện setup, tạo docker-compose.yml]
  → Kiro Cortex lưu: files modified, decisions, context

Session 2 (hôm nay):
  Bạn: "Thêm Redis vào stack"
  Agent: [đã biết project dùng Docker Compose + PostgreSQL]
        [thêm Redis service vào docker-compose.yml có sẵn]
  → Không cần giải thích lại context
```

### Audit → Enforce workflow

```bash
# Tuần 1: Quan sát
echo 'mode = "audit"' > .kiro/cortex.toml
# Agent hoạt động bình thường, Kiro Cortex chỉ ghi log

# Tuần 2: Review
kiro-cortex audit summary --since 7d
# → 23 lần đọc .env, 12 lần detect API key, 0 false positive

# Tuần 3: Bật enforce
sed -i 's/audit/enforce/' .kiro/cortex.toml
# → Giờ mới chặn thật
```

---

## FAQ

**Q: Kiro Cortex có làm chậm agent không?**
A: Không đáng kể. Guard hooks chạy <1ms. MCP Proxy thêm ~1-10ms per call. Memory capture <5ms.

**Q: Agent bị chặn thì sao?**
A: Agent nhận message giải thích lý do. Thường sẽ đề xuất cách khác. Hoặc bạn dùng `allow-once` để override.

**Q: Custom secret rules có chặn ở PreToolUse không?**
A: Có. Tất cả rules đều chặn ở PreToolUse. Config `action = "detect"` chỉ ảnh hưởng PostToolUse/UserPromptSubmit.

**Q: Memory có lưu raw secrets không?**
A: Không. Guard redact trước, memory capture sau. Memory chỉ lưu redacted version.

**Q: Audit mode có ảnh hưởng gì không?**
A: Zero behavior change. Không chặn, không cảnh báo, không inject context, không ghi memory. Chỉ ghi audit log.

**Q: Audit mode có ghi memory không?**
A: Không. Memory capture chỉ hoạt động ở enforce mode. Audit mode không tạo `.kiro/cortex-memory.db`.

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
├── secret_scanner.rs     24 built-in rules, entropy, allowlist, redaction
├── injection_scanner.rs  55 patterns, 8 categories, unicode normalization
├── audit.rs              JSON lines logger, rotation, finding_id
├── init.rs               Init/uninstall/check, idempotent
├── proxy.rs              MCP Proxy: JSON-RPC intercept, scan, redact, block
├── hitl.rs               allow-once, report feedback, session summary
├── tune.rs               Auto-tune: phân tích feedback, gợi ý + áp dụng config
└── memory.rs             SQLite storage, BM25 search, session lifecycle, KG

docs/
├── README.md             User-facing docs (mirror of this file)
├── how-it-works.md       Architecture diagrams
├── IMPLEMENTATION_PLAN.md  Full plan (v5, 20 tasks)
└── TDD_PLAN.md           Test-driven development plan

.kiro/steering/           12 steering files (Kiro auto-loads)
tests/test_cli.rs         23 E2E integration tests
```

---

## License

MIT
