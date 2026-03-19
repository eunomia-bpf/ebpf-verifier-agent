# How to Use Local LLM with llama.cpp

## Overview

All LLM-based evaluation (A/B repair experiments, classification, diagnostic evaluation, etc.)
should use a locally-served model via llama.cpp's OpenAI-compatible API server. This avoids
API costs and rate limits.

## Prerequisites

- llama.cpp CUDA build at: `/home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/build/bin/llama-server`
- GPU with CUDA support (build links against CUDA 12.9 + cuBLAS)
- Python packages: `openai`, `requests`

## Available Models

| Model | Path | Size | Notes |
|-------|------|------|-------|
| TinyLlama 1.1B (Q4_K_M) | `/home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf` | 638 MB | Quick smoke-testing only |
| GPT-OSS 20B (mxfp4) | `~/.cache/llama.cpp/ggml-org_gpt-oss-20b-GGUF_gpt-oss-20b-mxfp4.gguf` | 12 GB | **Default for production eval** |
| GPT-OSS 120B (mxfp4) | `~/.cache/llama.cpp/ggml-org_gpt-oss-120b-GGUF_gpt-oss-120b-mxfp4-00001-of-00003.gguf` | ~60 GB | Large-scale; requires UVM (see below) |

## Quick Start

### 1. Start the server

```bash
# Production model (20B, fits in single GPU VRAM)
/home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/build/bin/llama-server \
  -m ~/.cache/llama.cpp/ggml-org_gpt-oss-20b-GGUF_gpt-oss-20b-mxfp4.gguf \
  -c 8192 \
  -ngl 99 \
  --host 127.0.0.1 \
  --port 8080

# Quick smoke test with small model
/home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/build/bin/llama-server \
  -m /home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf \
  -c 4096 \
  -ngl 99 \
  --host 127.0.0.1 \
  --port 8080
```

Key flags:
- `-m`: model path
- `-c`: context size in tokens
- `-ngl 99`: offload all layers to GPU
- `--host 127.0.0.1`: bind to localhost only
- `--port`: API port (default 8080)

### 2. Check server health

```bash
curl http://127.0.0.1:8080/health
# Returns: {"status":"ok"} when ready
# Returns: {"status":"loading model"} while loading
```

### 3. Use the OpenAI-compatible API

The server exposes an OpenAI-compatible endpoint at `http://127.0.0.1:8080/v1/chat/completions`.

Using the `openai` Python package (recommended):

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8080/v1", api_key="not-needed")
response = client.chat.completions.create(
    model="local",          # any string is accepted; server ignores this field
    messages=[
        {"role": "system", "content": "You are an eBPF expert."},
        {"role": "user", "content": "Fix this verifier error: ..."},
    ],
    temperature=0.0,
    max_tokens=1024,
)
print(response.choices[0].message.content)
```

Using `requests` directly:

```python
import requests

response = requests.post("http://127.0.0.1:8080/v1/chat/completions", json={
    "model": "local",
    "messages": [
        {"role": "system", "content": "You are an eBPF expert."},
        {"role": "user", "content": "Fix this verifier error: ..."},
    ],
    "temperature": 0.0,
    "max_tokens": 1024,
})
print(response.json()["choices"][0]["message"]["content"])
```

## Running BPFix Diagnostic Evaluation

Use `scripts/local_llm_eval.py` to run the full evaluation pipeline. The script:
- Optionally starts the llama-server subprocess automatically
- Waits for the health check to confirm readiness
- Loads cases from `eval/results/batch_diagnostic_results_v4.json`
- Sends each case's verifier log + BPFix diagnostic to the LLM
- Records classification, root-cause localization, and fix suggestions
- Saves results to `eval/results/local_llm_eval_results.json`
- Cleans up the server subprocess on exit (SIGINT/SIGTERM handled)

### Basic usage (server auto-started)

```bash
cd /home/yunwei37/workspace/ebpf-verifier-agent

python scripts/local_llm_eval.py \
  --model ~/.cache/llama.cpp/ggml-org_gpt-oss-20b-GGUF_gpt-oss-20b-mxfp4.gguf \
  --port 8080 \
  --ctx-size 8192 \
  --cases eval/results/batch_diagnostic_results_v4.json \
  --output eval/results/local_llm_eval_results.json
```

### Quick test with small model and 10 cases

```bash
python scripts/local_llm_eval.py \
  --model /home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf \
  --ctx-size 4096 \
  --max-cases 10 \
  --output eval/results/local_llm_eval_test.json
```

### When server is already running

```bash
python scripts/local_llm_eval.py \
  --no-start-server \
  --port 8080 \
  --cases eval/results/batch_diagnostic_results_v4.json \
  --output eval/results/local_llm_eval_results.json
```

### Ablation: raw log only (no BPFix diagnostic)

```bash
python scripts/local_llm_eval.py \
  --no-bpfix \
  --output eval/results/local_llm_eval_raw_log_only.json
```

### All CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--model` | GPT-OSS 20B path | Path to GGUF model file |
| `--port` | 8080 | llama-server port |
| `--ctx-size` | 8192 | Context size in tokens |
| `--cases` | `eval/results/batch_diagnostic_results_v4.json` | Input cases file |
| `--output` | `eval/results/local_llm_eval_results.json` | Output results file |
| `--max-cases` | (all) | Limit number of cases for testing |
| `--no-start-server` | false | Skip launching llama-server (use existing) |
| `--no-bpfix` | false | Ablation: send raw log only, no BPFix diagnostic |
| `--load-log-from-yaml` | false | Load verifier logs from YAML case files |
| `--max-tokens` | 1024 | Max tokens in LLM response |
| `--startup-timeout` | 120 | Seconds to wait for server ready |
| `--uvm` | false | Enable CUDA Unified Memory (for 120B model) |

## Oversubscribed Models (120B)

The 120B model exceeds single-GPU VRAM and requires CUDA Unified Memory:

```bash
# Start server manually with UVM
GGML_CUDA_ENABLE_UNIFIED_MEMORY=1 GGML_CUDA_DISABLE_GRAPHS=1 \
  /home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/build/bin/llama-server \
  -m ~/.cache/llama.cpp/ggml-org_gpt-oss-120b-GGUF_gpt-oss-120b-mxfp4-00001-of-00003.gguf \
  -c 8192 \
  -ngl 99 \
  --host 127.0.0.1 \
  --port 8080

# Or let the eval script handle it with --uvm flag
python scripts/local_llm_eval.py \
  --model ~/.cache/llama.cpp/ggml-org_gpt-oss-120b-GGUF_gpt-oss-120b-mxfp4-00001-of-00003.gguf \
  --uvm \
  --ctx-size 4096 \
  --output eval/results/local_llm_eval_120b.json
```

Note: UVM is slower than native VRAM and may require `--ctx-size` reduction to fit.

## Output Format

Results are saved to JSON with the following structure:

```json
{
  "generated_at": "2026-03-12T...",
  "config": { "model": "...", "include_bpfix": true, ... },
  "aggregates": {
    "total_cases": 302,
    "api_success": 300,
    "json_parsed": 298,
    "class_correct": 241,
    "class_evaluated": 280,
    "class_accuracy_pct": 86.1,
    "avg_latency_seconds": 4.2,
    "per_taxonomy": { "source_bug": {...}, ... }
  },
  "results": [
    {
      "case_id": "...",
      "taxonomy_class": "source_bug",
      "predicted_failure_class": "source_bug",
      "predicted_root_cause_location": "foo.c:42",
      "predicted_suggested_fix": "Add a null check before ...",
      "class_match": true,
      "latency_seconds": 3.8,
      ...
    }
  ]
}
```

## Convention

All future model evaluation in this project MUST use the local llama.cpp server instead of
external APIs (OpenAI, Anthropic, etc.). Use `--no-start-server` when the server is already
running in another terminal or as a background process.
