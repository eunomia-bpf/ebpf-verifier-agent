# BPFix — Proof Trace Analysis for eBPF Verifier Failures
# Root-level Makefile providing one-command access to all key project operations.
#
# Usage:
#   make help          — list all targets with descriptions
#   make test          — run the full test suite
#   make eval-all      — run all non-LLM evaluations

SHELL := /bin/bash
CURDIR := $(shell pwd)

# ── Python ─────────────────────────────────────────────────────────────────────
PYTHON := python3
PYTEST  := $(PYTHON) -m pytest

# ── Directories ────────────────────────────────────────────────────────────────
EVAL_DIR    := $(CURDIR)/eval
RESULTS_DIR := $(CURDIR)/eval/results
PAPER_DIR   := $(CURDIR)/docs/paper
TMP_DIR     := $(CURDIR)/docs/tmp

# ── llama-server (20B GPT-OSS model) ───────────────────────────────────────────
LLAMA_BIN_20B   := /home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/build/bin/llama-server
LLAMA_LIB_20B   := /home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/build/bin
MODEL_20B       := $(HOME)/.cache/llama.cpp/ggml-org_gpt-oss-20b-GGUF_gpt-oss-20b-mxfp4.gguf
PORT_20B        := 8080

# ── llama-server (Qwen3.5-122B) ────────────────────────────────────────────────
LLAMA_BIN_QWEN  := /home/yunwei37/workspace/llama.cpp-latest/build/bin/llama-server
LLAMA_LIB_QWEN  := /home/yunwei37/workspace/llama.cpp-latest/build/bin
MODEL_QWEN_HF   := unsloth/Qwen3.5-122B-A10B-GGUF:Q4_K_M
PORT_QWEN       := 8081

.DEFAULT_GOAL := help

# ──────────────────────────────────────────────────────────────────────────────
# help — list all targets
# ──────────────────────────────────────────────────────────────────────────────
.PHONY: help
help:
	@echo ""
	@echo "BPFix — eBPF Verifier Proof Trace Analyzer"
	@echo "============================================="
	@echo ""
	@echo "Testing"
	@echo "  make test              Run full pytest test suite"
	@echo "  make test-quick        Run tests, skip slow ones (no slow marker yet — same as test)"
	@echo ""
	@echo "Batch evaluations (no LLM needed)"
	@echo "  make eval-batch        Batch diagnostic eval on 302 cases → results/batch_diagnostic_results.json"
	@echo "  make eval-latency      Latency benchmark → results/latency_benchmark.json"
	@echo "  make eval-pv           PV vs BPFix comparison → results/pv_comparison_expanded.json"
	@echo "  make eval-language     Per-language breakdown → results/per_language_eval.json"
	@# eval-formal removed (formal_engine_comparison.py script deleted)
	@echo "  make eval-all          Run all non-LLM evaluations above"
	@echo ""
	@echo "A/B Repair experiment (requires local LLM server)"
	@echo "  make eval-repair       Run A/B repair experiment with GPT-OSS 20B (starts server automatically)"
	@echo "  make eval-repair-20b   Same as eval-repair (explicit alias)"
	@echo "  make eval-repair-qwen  Run with Qwen3.5-122B on port $(PORT_QWEN)"
	@echo ""
	@echo "Local LLM server management"
	@echo "  make serve-20b         Start llama-server with GPT-OSS 20B on port $(PORT_20B)"
	@echo "  make serve-qwen        Start llama-server with Qwen3.5-122B on port $(PORT_QWEN)"
	@echo ""
	@echo "Paper"
	@echo "  make paper             Compile LaTeX paper (pdflatex, single pass)"
	@echo "  make paper-full        Compile paper with bibliography (pdflatex × 2 + bibtex)"
	@echo "  make paper-clean       Remove LaTeX build artifacts"
	@echo ""
	@echo "Utilities"
	@echo "  make lint              Run flake8 linter on interface/ and eval/"
	@echo "  make loc               Count lines of code in interface/extractor/"
	@echo "  make clean             Remove generated result files and LaTeX artifacts"
	@echo ""

# ──────────────────────────────────────────────────────────────────────────────
# Testing
# ──────────────────────────────────────────────────────────────────────────────
.PHONY: test
test:
	@echo "[test] Running full pytest suite…"
	cd $(CURDIR) && $(PYTEST) tests/ -v

.PHONY: test-quick
test-quick:
	@echo "[test-quick] Running pytest (no slow-marker filtering configured yet)…"
	cd $(CURDIR) && $(PYTEST) tests/ -v

# ──────────────────────────────────────────────────────────────────────────────
# Batch diagnostic evaluation (no LLM)
# ──────────────────────────────────────────────────────────────────────────────
.PHONY: eval-batch
eval-batch:
	@echo "[eval-batch] Running batch diagnostic evaluation on 302 cases…"
	cd $(CURDIR) && $(PYTHON) $(EVAL_DIR)/batch_diagnostic_eval.py \
		--results-path $(RESULTS_DIR)/batch_diagnostic_results.json

.PHONY: eval-latency
eval-latency:
	@echo "[eval-latency] Running latency benchmark…"
	cd $(CURDIR) && $(PYTHON) $(EVAL_DIR)/latency_benchmark.py \
		--results-path $(RESULTS_DIR)/latency_benchmark.json

.PHONY: eval-pv
eval-pv:
	@echo "[eval-pv] Running Pretty Verifier vs BPFix comparison…"
	cd $(CURDIR) && $(PYTHON) $(EVAL_DIR)/pv_comparison_expanded.py \
		--output-json $(RESULTS_DIR)/pv_comparison_expanded.json \
		--output-md $(TMP_DIR)/pv-comparison-expanded.md

.PHONY: eval-language
eval-language:
	@echo "[eval-language] Running per-language breakdown evaluation…"
	cd $(CURDIR) && $(PYTHON) $(EVAL_DIR)/per_language_eval.py

# eval-formal target removed: formal_engine_comparison.py no longer exists.
# To add back: create eval/formal_engine_comparison.py and re-add the target.

.PHONY: eval-all
eval-all: eval-batch eval-latency eval-pv eval-language
	@echo ""
	@echo "[eval-all] All non-LLM evaluations complete."
	@echo "  Batch results:    $(RESULTS_DIR)/batch_diagnostic_results.json"
	@echo "  Latency results:  $(RESULTS_DIR)/latency_benchmark.json"
	@echo "  PV comparison:    $(RESULTS_DIR)/pv_comparison_expanded.json"
	@echo "  Language eval:    $(RESULTS_DIR)/per_language_eval.json"

# ──────────────────────────────────────────────────────────────────────────────
# A/B Repair experiment (requires local llama-server)
# ──────────────────────────────────────────────────────────────────────────────
.PHONY: eval-repair
eval-repair: eval-repair-20b

.PHONY: eval-repair-20b
eval-repair-20b:
	@echo "[eval-repair-20b] Running A/B repair experiment with GPT-OSS 20B model…"
	@echo "  Model:  $(MODEL_20B)"
	@echo "  Port:   $(PORT_20B)"
	@echo "  Server will be started automatically by the script."
	cd $(CURDIR) && LD_LIBRARY_PATH=$(LLAMA_LIB_20B):$$LD_LIBRARY_PATH \
		$(PYTHON) $(EVAL_DIR)/repair_experiment_v3.py \
		--model $(MODEL_20B) \
		--port $(PORT_20B) \
		--results-path $(RESULTS_DIR)/repair_experiment_results_v3.json \
		--report-path $(TMP_DIR)/repair-experiment-v3-results.md

.PHONY: eval-repair-qwen
eval-repair-qwen:
	@echo "[eval-repair-qwen] Running A/B v4 repair experiment with Qwen3.5-122B…"
	@echo "  Model:  $(MODEL_QWEN_HF) (downloaded via HF)"
	@echo "  Port:   $(PORT_QWEN)"
	@echo "  Server will be started automatically by the script."
	cd $(CURDIR) && LD_LIBRARY_PATH=$(LLAMA_LIB_QWEN):$$LD_LIBRARY_PATH \
		$(PYTHON) $(EVAL_DIR)/repair_experiment_v4.py \
		--model-hf $(MODEL_QWEN_HF) \
		--port $(PORT_QWEN) \
		--results-path $(RESULTS_DIR)/repair_experiment_results_v4.json \
		--report-path $(TMP_DIR)/repair-experiment-v4-results.md

# ──────────────────────────────────────────────────────────────────────────────
# Local LLM server management
# ──────────────────────────────────────────────────────────────────────────────
.PHONY: serve-20b
serve-20b:
	@echo "[serve-20b] Starting llama-server with GPT-OSS 20B on port $(PORT_20B)…"
	@echo "  Binary: $(LLAMA_BIN_20B)"
	@echo "  Model:  $(MODEL_20B)"
	@echo "  Press Ctrl+C to stop."
	LD_LIBRARY_PATH=$(LLAMA_LIB_20B):$$LD_LIBRARY_PATH \
		$(LLAMA_BIN_20B) \
		--model $(MODEL_20B) \
		--port $(PORT_20B) \
		--ctx-size 8192

.PHONY: serve-qwen
serve-qwen:
	@echo "[serve-qwen] Starting llama-server with Qwen3.5-122B on port $(PORT_QWEN)…"
	@echo "  Binary: $(LLAMA_BIN_QWEN)"
	@echo "  Model:  $(MODEL_QWEN_HF) (HuggingFace pull)"
	@echo "  Press Ctrl+C to stop."
	LD_LIBRARY_PATH=$(LLAMA_LIB_QWEN):$$LD_LIBRARY_PATH \
		$(LLAMA_BIN_QWEN) \
		-hf $(MODEL_QWEN_HF) \
		--port $(PORT_QWEN) \
		--ctx-size 8192 \
		-ngl 20

# ──────────────────────────────────────────────────────────────────────────────
# Paper compilation
# ──────────────────────────────────────────────────────────────────────────────
.PHONY: paper
paper:
	@echo "[paper] Compiling LaTeX paper (single pass)…"
	cd $(PAPER_DIR) && pdflatex -interaction=nonstopmode main.tex
	@echo "[paper] Output: $(PAPER_DIR)/main.pdf"

.PHONY: paper-full
paper-full:
	@echo "[paper-full] Compiling paper with bibliography…"
	cd $(PAPER_DIR) && pdflatex -interaction=nonstopmode main.tex
	cd $(PAPER_DIR) && bibtex main || true
	cd $(PAPER_DIR) && pdflatex -interaction=nonstopmode main.tex
	cd $(PAPER_DIR) && pdflatex -interaction=nonstopmode main.tex
	@echo "[paper-full] Output: $(PAPER_DIR)/main.pdf"

.PHONY: paper-clean
paper-clean:
	@echo "[paper-clean] Removing LaTeX build artifacts…"
	cd $(PAPER_DIR) && rm -f *.aux *.bbl *.blg *.log *.out *.toc *.fls *.fdb_latexmk *.synctex.gz

# ──────────────────────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────────────────────
.PHONY: lint
lint:
	@echo "[lint] Running flake8 on interface/ and eval/…"
	$(PYTHON) -m flake8 \
		--max-line-length=120 \
		--extend-ignore=E203,W503 \
		$(CURDIR)/interface/ $(CURDIR)/eval/ $(CURDIR)/scripts/

.PHONY: loc
loc:
	@echo "[loc] Lines of code in interface/extractor/:"
	@wc -l $(CURDIR)/interface/extractor/*.py | sort -rn
	@echo ""
	@echo "[loc] Lines of code in eval/:"
	@wc -l $(CURDIR)/eval/*.py | sort -rn | tail -1

.PHONY: clean
clean: paper-clean
	@echo "[clean] Removing generated result files…"
	@rm -f $(RESULTS_DIR)/batch_diagnostic_results.json
	@rm -f $(RESULTS_DIR)/latency_benchmark.json
	@rm -f $(RESULTS_DIR)/pv_comparison_expanded.json
	@rm -f $(RESULTS_DIR)/per_language_eval.json
	@rm -f $(TMP_DIR)/pv-comparison-expanded.md
	@rm -f $(TMP_DIR)/batch-diagnostic-eval.md
	@echo "[clean] Done."
