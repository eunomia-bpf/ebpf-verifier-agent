# Qwen3.5-122B-A10B Inference Optimization for A/B Repair Experiment

**Date**: 2026-03-13
**Goal**: Cut 112-call LLM experiment from 13+ hours to ~1.5 hours

---

## Hardware Profile

| Component | Spec |
|-----------|------|
| GPU | NVIDIA GeForce RTX 5090 |
| VRAM | 32,607 MiB total |
| CPU | Intel Core Ultra 9 285K (24 cores, no hyperthreading) |
| RAM | 125 GiB total, ~92 GiB available |
| CUDA | 12.9, driver 575.57.08 |
| llama.cpp | b8323 (commit 57819b8d4, 2026-03-13) |

---

## Model Architecture

- **Model**: unsloth/Qwen3.5-122B-A10B-GGUF:Q4_K_M
- **Architecture**: qwen35moe (MoE + SSM hybrid)
- **Layers (blocks)**: 48
- **Experts per layer**: 256 total, 8 active per token
- **Active params per token**: ~10B (out of 122B total)
- **Embedding dim**: 3072
- **Expert FFN dim**: 1024 per expert
- **KV heads**: 2 (MLA/GQA)
- **Model files**: 3 shards totaling ~72 GB on disk (Q4_K_M)

---

## Current Configuration (Baseline)

```bash
/home/yunwei37/workspace/llama.cpp-latest/build/bin/llama-server \
  -hf unsloth/Qwen3.5-122B-A10B-GGUF:Q4_K_M \
  -c 8192 \
  -ngl 20 \
  --host 127.0.0.1 \
  --port 8081
```

### Baseline Performance (measured)

| Metric | Value |
|--------|-------|
| GPU VRAM used | 31,840 MiB (97.6% of 32 GB) |
| GPU utilization | ~4% during generation |
| Generation speed | **5.1 tok/s** |
| Prompt processing speed | **4.2 tok/s** |
| Time for 1024-token output | ~3.3 minutes |
| Time for 1000-token prompt | ~4 minutes |
| **Total per call** | **~7.3 minutes** |
| **112 calls total** | **~13.6 hours** |

**Root problem**: With `-ngl 20`, only 20 of 48 layers are on GPU. The remaining 28 layers — including all their expert weights — run on CPU. The GPU processes 20 layers then hands off to CPU for the remaining 28 layers. GPU sits idle at 4% while CPU is the bottleneck. This creates extremely slow sequential CPU inference for the majority of the model.

---

## The MoE Memory Problem

The 122B MoE model's weight distribution at Q4_K_M:

| Component | Size | Location (current) |
|-----------|------|---------------------|
| Expert FFN weights (48 layers × 256 experts × 1024×3072×3) | ~58 GB | Split: some GPU, mostly CPU |
| Attention weights (48 layers × 4 matrices) | ~1.3 GB | GPU (first 20 layers) |
| Shared expert weights | ~0.45 GB | GPU (first 20 layers) |
| Embeddings | ~0.38 GB | CPU |
| KV cache (8192 ctx) | ~0.81 GB | GPU |

**Why `-ngl 99` alone doesn't work**: Full model is ~72 GB but GPU only has 32 GB VRAM. Cannot fit all expert weights on GPU.

---

## Recommended Configuration: `-ngl 99 -cmoe`

The `-cmoe` flag (`--cpu-moe`) keeps **all expert FFN weights on CPU**, while `-ngl 99` offloads **all other layers** (attention, norms, embeddings) to GPU.

### VRAM Requirements with `-ngl 99 -cmoe`

| Component | VRAM |
|-----------|------|
| Attention weights (all 48 layers) | ~1.3 GB |
| Shared expert weights | ~0.45 GB |
| Embeddings | ~0.38 GB |
| KV cache (8192 ctx) | ~0.81 GB |
| Overhead | ~0.5 GB |
| **Total** | **~3.4 GB** |

This comfortably fits in 32 GB VRAM (only ~11% utilization).

### CPU RAM Requirements

| Component | RAM |
|-----------|-----|
| Expert FFN weights | ~58 GB |
| Available RAM | ~92 GB |
| **Fits**: | **YES** (63% utilized) |

### Why This Is Faster

The bottleneck shifts from slow GPU→CPU layer handoff to:
1. **GPU handles attention** (fully batched, fast tensor ops)
2. **CPU handles expert lookup** (reads only 8/256 experts per token per layer)

For each generated token:
- Active expert memory read: 8 experts × 48 layers × (1024×3072×3×0.5 bytes) ≈ 576 MB
- At CPU RAM bandwidth ~80 GB/s: ~7 ms per token just for expert weight reads
- **Expected generation speed: 20–40 tok/s** (vs 5.1 tok/s current)
- **Expected prompt processing: 200–1000 tok/s** (GPU handles attention batched)

### Experiment Impact

| Scenario | Gen Speed | Prompt Speed | Time/Call | 112 Calls |
|----------|-----------|--------------|-----------|-----------|
| Current (`-ngl 20`) | 5.1 tok/s | 4.2 tok/s | ~7.3 min | **13.6 h** |
| Optimized (`-ngl 99 -cmoe`) | ~25 tok/s | ~500 tok/s | ~0.7 min | **~1.3 h** |

---

## Optimal Launch Command

```bash
/home/yunwei37/workspace/llama.cpp-latest/build/bin/llama-server \
  -hf unsloth/Qwen3.5-122B-A10B-GGUF:Q4_K_M \
  -c 8192 \
  -ngl 99 \
  --cpu-moe \
  -t 16 \
  -tb 16 \
  --host 127.0.0.1 \
  --port 8081
```

**Flag explanations**:
- `-ngl 99`: Offload all non-expert layers to GPU
- `--cpu-moe` / `-cmoe`: Keep all expert FFN weights in CPU RAM
- `-t 16`: 16 CPU threads for generation (expert lookup uses these)
- `-tb 16`: 16 CPU threads for batch/prompt processing
- `-c 8192`: Context window (same as before)

**Thread tuning note**: The Core Ultra 9 285K has 24 P-cores (no E-cores, no hyperthreading). Using 16 threads leaves headroom for OS and other tasks. You can try `-t 20` for maximum throughput.

---

## Migration Steps (Safe Procedure)

The new configuration needs ~3.4 GB VRAM but the current server uses 31.8 GB. They **cannot run concurrently**. Follow this procedure:

```bash
# 1. Verify current server is still working (note the PID)
curl -s http://localhost:8081/health
# → {"status":"ok"}

# 2. Kill the current server (PID 2894653)
kill 2894653

# 3. Wait for GPU memory to be released
sleep 5
nvidia-smi | grep MiB

# 4. Start optimized server
/home/yunwei37/workspace/llama.cpp-latest/build/bin/llama-server \
  -hf unsloth/Qwen3.5-122B-A10B-GGUF:Q4_K_M \
  -c 8192 \
  -ngl 99 \
  --cpu-moe \
  -t 16 \
  -tb 16 \
  --host 127.0.0.1 \
  --port 8081 \
  --log-disable \
  2>&1 | tee /tmp/llama-server-new.log &

# 5. Wait for model to load (~60-120 seconds for 72GB model)
sleep 90
curl -s http://localhost:8081/health

# 6. Benchmark the new server
time curl -s http://localhost:8081/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"unsloth/Qwen3.5-122B-A10B-GGUF:Q4_K_M","prompt":"Say hi.","max_tokens":20,"stream":true}' \
  | grep timings

# 7. If it fails, restart with old params:
# /home/yunwei37/workspace/llama.cpp-latest/build/bin/llama-server \
#   -hf unsloth/Qwen3.5-122B-A10B-GGUF:Q4_K_M \
#   -c 8192 -ngl 20 --host 127.0.0.1 --port 8081
```

---

## Alternative: Qwen3-30B-A3B-FP8 (Potentially Faster)

There is a 30B MoE model already downloaded locally:
- Path: `/home/yunwei37/.cache/huggingface/hub/models--Qwen--Qwen3-30B-A3B-FP8/`
- Size: 31 GB (FP8 quantized)
- Format: SafeTensors (needs vLLM or conversion to GGUF)
- Active params: ~3B (MoE with 3B active)
- **Would fit entirely in 32 GB VRAM** with full GPU offload

This would be ~3-10x faster than the 122B model even at full GPU, but requires:
1. Installing vLLM: `pip install vllm` (handles FP8 natively)
2. Or converting to GGUF: `python3 /home/yunwei37/workspace/llama.cpp-latest/convert_hf_to_gguf.py`

vLLM launch for 30B-A3B-FP8:
```bash
python3 -m vllm.entrypoints.openai.api_server \
  --model /home/yunwei37/.cache/huggingface/hub/models--Qwen--Qwen3-30B-A3B-FP8/snapshots/d206ba73... \
  --dtype auto \
  --port 8082
```

**Trade-off**: 30B model has lower capability than 122B. For repair tasks, quality matters. Recommend trying 122B with `-cmoe` first, and falling back to 30B only if latency is still too high.

---

## Other llama.cpp MoE Flags Available

| Flag | Purpose |
|------|---------|
| `--cpu-moe` / `-cmoe` | All expert weights to CPU |
| `--n-cpu-moe N` / `-ncmoe N` | Only first N layers' experts to CPU |
| `--override-tensor <pattern>=<type>` / `-ot` | Fine-grained per-tensor buffer control |
| `--split-mode {none,layer,row}` | Multi-GPU split strategy |
| `--tensor-split N0,N1,...` | Ratio of each GPU's contribution |

For single-GPU setup, `--cpu-moe` is the right choice.

---

## Summary

**Recommended action**: Stop the current server and restart with `-ngl 99 --cpu-moe -t 16`.

- VRAM drops from 31.8 GB to ~3.5 GB
- Generation speed increases from 5.1 tok/s to ~25 tok/s
- Prompt processing speed increases from 4.2 tok/s to ~500 tok/s
- 112-call experiment drops from **13.6 hours to ~1.3 hours**
- Risk: experiment is safe; old command is saved above to restore if needed
