.PHONY: build test bench bench-fast bench-summary bench-compare release clean

export PATH := $(HOME)/.cargo/bin:$(PATH)

BIN := ./target/release/kiro-cortex

# ── Build ──

build:
	cargo build --release

build-embedding:
	cargo build --release --features embedding

test:
	cargo test

# ── Benchmarks ──

bench: build ## Run all benchmarks + generate summary
	bash benchmarks/all.sh

bench-fast: build ## Run only internal + public benchmarks (skip slow public datasets)
	SKIP_PUBLIC=1 bash benchmarks/all.sh

bench-summary: ## Generate Markdown summary from existing reports
	python3 benchmarks/summary.py --out benchmarks/BENCHMARK_RESULTS.md
	@echo "→ benchmarks/BENCHMARK_RESULTS.md"

bench-compare: ## Compare two reports: make bench-compare BEFORE=a.json AFTER=b.json
	python3 benchmarks/compare.py $(BEFORE) $(AFTER)

# ── Setup ──

init: build ## Build + install globally
	$(BIN) init --global

init-project: build ## Build + install for current project
	$(BIN) init

check: ## Verify setup
	$(BIN) check

# ── Release ──

release: test ## Build release binary
	cargo build --release
	@ls -lh $(BIN)

release-embedding: test ## Build release with embedding
	cargo build --release --features embedding
	@ls -lh $(BIN)

clean:
	cargo clean

# ── Help ──

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
