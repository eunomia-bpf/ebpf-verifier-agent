#!/usr/bin/env python3
"""Local LLM evaluation using llama.cpp's OpenAI-compatible server.

Runs BPFix diagnostic evaluation on cases from batch_diagnostic_results.json by
sending the verifier log + BPFix diagnostic to a locally-served model and asking
it to classify the failure, identify the root cause, and suggest a fix.

Usage:
    python scripts/local_llm_eval.py \\
        --model ~/.cache/llama.cpp/ggml-org_gpt-oss-20b-GGUF_gpt-oss-20b-mxfp4.gguf \\
        --port 8080 \\
        --cases eval/results/batch_diagnostic_results.json \\
        --output eval/results/local_llm_eval_results.json \\
        --max-cases 10

    # When the server is already running externally:
    python scripts/local_llm_eval.py --no-start-server --model local \\
        --cases eval/results/batch_diagnostic_results.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from openai import OpenAI

LLAMA_SERVER_BINARY = (
    "/home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/build/bin/llama-server"
)
LLAMA_LIB_DIR = (
    "/home/yunwei37/workspace/gpu/gpu_ext/workloads/llama.cpp/build/bin"
)
DEFAULT_MODEL = (
    "~/.cache/llama.cpp/ggml-org_gpt-oss-20b-GGUF_gpt-oss-20b-mxfp4.gguf"
)
DEFAULT_PORT = 8080
DEFAULT_CTX_SIZE = 8192
DEFAULT_CASES = "eval/results/batch_diagnostic_results.json"
DEFAULT_OUTPUT = "eval/results/local_llm_eval_results.json"
SERVER_STARTUP_TIMEOUT = 120  # seconds
HEALTH_CHECK_INTERVAL = 2  # seconds
REQUEST_TIMEOUT = 120  # seconds per LLM call
INTER_REQUEST_DELAY = 0.5  # seconds between requests

ROOT = Path(__file__).resolve().parents[1]

SYSTEM_PROMPT = (
    "You are an expert in Linux eBPF programs and the kernel BPF verifier. "
    "Analyze verifier failures using both the raw verifier log and BPFix's "
    "structured diagnostic. Provide a concise, concrete analysis. "
    "Respond with valid JSON only."
)

RESPONSE_SCHEMA = (
    '{"failure_class":"<one of: lowering_artifact|source_bug|verifier_limit|env_mismatch>",'
    '"root_cause_location":"<file:line or function/statement where the root cause is>",'
    '"root_cause_explanation":"<one sentence explaining the root cause>",'
    '"suggested_fix":"<concrete fix description, 1-3 sentences>",'
    '"confidence":"<high|medium|low>"}'
)


@dataclass(slots=True)
class CaseEvalResult:
    case_id: str
    source: str
    taxonomy_class: str
    error_id: str | None
    verifier_log_chars: int
    has_diagnostic: bool
    diagnostic_text: str | None
    prompt: str
    raw_response: str
    parsed_response: dict[str, Any] | None
    api_error: str | None
    predicted_failure_class: str | None
    predicted_root_cause_location: str | None
    predicted_suggested_fix: str | None
    class_match: bool | None
    latency_seconds: float | None
    usage_output_tokens: int | None
    extra: dict[str, Any] = field(default_factory=dict)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def wait_for_server(port: int, timeout: int) -> bool:
    """Poll the health endpoint until the server is ready or timeout expires."""
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") in ("ok", "loading model"):
                    # "loading model" means it started, wait for "ok"
                    if data.get("status") == "ok":
                        print(f"  [health] Server ready after {attempt} checks.")
                        return True
                    print(f"  [health] Still loading model (attempt {attempt})...")
        except requests.exceptions.ConnectionError:
            pass
        except Exception as exc:
            print(f"  [health] Unexpected error: {exc}")
        time.sleep(HEALTH_CHECK_INTERVAL)
    return False


def start_llama_server(
    model_path: str,
    port: int,
    ctx_size: int,
    extra_env: dict[str, str] | None = None,
) -> subprocess.Popen[bytes]:
    """Start llama-server as a subprocess."""
    expanded = os.path.expanduser(model_path)
    cmd = [
        LLAMA_SERVER_BINARY,
        "-m", expanded,
        "-c", str(ctx_size),
        "-ngl", "99",
        "--host", "127.0.0.1",
        "--port", str(port),
    ]
    env = os.environ.copy()
    # Ensure the llama.cpp shared libraries (libggml-cuda.so, etc.) are findable
    existing_ldpath = env.get("LD_LIBRARY_PATH", "")
    if LLAMA_LIB_DIR not in existing_ldpath:
        env["LD_LIBRARY_PATH"] = (
            f"{LLAMA_LIB_DIR}:{existing_ldpath}" if existing_ldpath else LLAMA_LIB_DIR
        )
    if extra_env:
        env.update(extra_env)

    print(f"[server] Starting llama-server: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,  # capture stderr so we can surface errors on failure
        env=env,
    )
    return proc


def load_cases(cases_path: Path, max_cases: int | None) -> list[dict[str, Any]]:
    """Load cases from batch_diagnostic_results.json format."""
    with cases_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        results = data.get("results", [])
    elif isinstance(data, list):
        results = data
    else:
        raise ValueError(f"Unexpected format in {cases_path}: {type(data)}")

    # Filter to cases that have a verifier log (verifier_log_chars > 0)
    # and were successfully diagnosed (not skipped, success=True or at least have diagnostic_text)
    eligible = [
        r for r in results
        if r.get("verifier_log_chars", 0) > 0 and not r.get("skipped", False)
    ]

    print(f"[cases] {len(results)} total cases, {len(eligible)} with verifier logs")
    if max_cases is not None:
        eligible = eligible[:max_cases]
        print(f"[cases] Limited to {len(eligible)} cases (--max-cases {max_cases})")

    return eligible


def build_prompt(case: dict[str, Any], include_bpfix: bool = True) -> str:
    """Build the evaluation prompt for a single case."""
    verifier_log = case.get("verifier_log", "") or ""
    # If the verifier_log is not in the diagnostic results JSON, note it
    if not verifier_log:
        verifier_log = f"[verifier log not embedded; case has {case.get('verifier_log_chars', 0)} chars]"

    diagnostic_text = case.get("diagnostic_text") or ""

    lines: list[str] = [
        "Analyze this eBPF verifier failure.",
        "",
        "## Verifier Log",
        "```text",
        verifier_log,
        "```",
    ]

    if include_bpfix and diagnostic_text:
        lines.extend([
            "",
            "## BPFix Diagnostic Analysis",
            "```text",
            diagnostic_text,
            "```",
        ])

    lines.extend([
        "",
        "Respond with JSON only using this schema:",
        RESPONSE_SCHEMA,
    ])

    return "\n".join(lines)


def build_prompt_with_log_from_yaml(
    case: dict[str, Any],
    include_bpfix: bool = True,
) -> tuple[str, str]:
    """Build prompt by loading the verifier log from the YAML case file."""
    case_path = case.get("case_path", "")
    verifier_log = ""
    log_source = "not_found"

    if case_path:
        # case_path may point to a directory; look for YAML files there
        case_dir = Path(case_path)
        yaml_files: list[Path] = []
        if case_dir.is_dir():
            yaml_files = sorted(p for p in case_dir.glob("*.yaml") if p.name != "index.yaml")
        elif case_dir.suffix == ".yaml" and case_dir.exists():
            yaml_files = [case_dir]

        for yaml_file in yaml_files:
            try:
                import yaml
                with yaml_file.open("r", encoding="utf-8") as f:
                    case_data = yaml.safe_load(f) or {}
                log = _extract_verifier_log_from_case(case_data)
                if log:
                    verifier_log = log
                    log_source = str(yaml_file)
                    break
            except Exception:
                continue

    if not verifier_log:
        # Fall back to placeholder
        verifier_log = f"[verifier log not available; {case.get('verifier_log_chars', 0)} chars in original]"
        log_source = "placeholder"

    diagnostic_text = case.get("diagnostic_text") or ""

    lines: list[str] = [
        "Analyze this eBPF verifier failure.",
        "",
        "## Verifier Log",
        "```text",
        verifier_log,
        "```",
    ]

    if include_bpfix and diagnostic_text:
        lines.extend([
            "",
            "## BPFix Diagnostic Analysis",
            "```text",
            diagnostic_text,
            "```",
        ])

    lines.extend([
        "",
        "Respond with JSON only using this schema:",
        RESPONSE_SCHEMA,
    ])

    return "\n".join(lines), log_source


def _extract_verifier_log_from_case(case_data: dict[str, Any]) -> str:
    """Extract verifier log text from YAML case data (mirrors repair_experiment.py logic)."""
    verifier_log = case_data.get("verifier_log")
    if isinstance(verifier_log, dict):
        combined = verifier_log.get("combined")
        if isinstance(combined, str) and combined.strip():
            return combined.strip()
        blocks = verifier_log.get("blocks") or []
        if isinstance(blocks, list):
            joined = "\n\n".join(str(b).strip() for b in blocks if str(b).strip())
            return joined.strip()
    if isinstance(verifier_log, str) and verifier_log.strip():
        return verifier_log.strip()

    verifier_logs = case_data.get("verifier_logs")
    if isinstance(verifier_logs, list):
        joined = "\n\n".join(str(b).strip() for b in verifier_logs if str(b).strip())
        return joined.strip()
    if isinstance(verifier_logs, dict):
        combined = verifier_logs.get("combined")
        if isinstance(combined, str) and combined.strip():
            return combined.strip()
    return ""


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Extract first JSON object from LLM response text."""
    candidate = text.strip()
    if candidate.startswith("```"):
        fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", candidate, flags=re.DOTALL)
        if fence_match:
            candidate = fence_match.group(1)
    try:
        payload = json.loads(candidate)
        return payload if isinstance(payload, dict) else None
    except json.JSONDecodeError:
        pass

    for match in re.finditer(r"\{.*?\}", candidate, flags=re.DOTALL):
        snippet = match.group(0)
        try:
            payload = json.loads(snippet)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def call_local_llm(
    *,
    client: OpenAI,
    prompt: str,
    model_name: str = "local",
    temperature: float = 0.0,
    max_tokens: int = 1024,
    timeout: int = REQUEST_TIMEOUT,
) -> tuple[str, dict[str, Any] | None, str | None, int | None]:
    """Send a request to the local llama-server and return (text, parsed, error, output_tokens)."""
    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
        )
        text = response.choices[0].message.content or ""
        output_tokens: int | None = None
        if response.usage:
            output_tokens = response.usage.completion_tokens
        parsed = extract_json_object(text)
        return text, parsed, None, output_tokens
    except Exception as exc:
        return "", None, f"{type(exc).__name__}: {exc}", None


def evaluate_case(
    *,
    case: dict[str, Any],
    client: OpenAI,
    model_name: str,
    include_bpfix: bool,
    load_log_from_yaml: bool,
    max_tokens: int,
) -> CaseEvalResult:
    """Run LLM evaluation on a single case and return a structured result."""
    case_id = case.get("case_id", "unknown")

    # Build prompt
    log_source = "diagnostic_json"
    if load_log_from_yaml:
        prompt, log_source = build_prompt_with_log_from_yaml(case, include_bpfix=include_bpfix)
    else:
        prompt = build_prompt(case, include_bpfix=include_bpfix)

    t0 = time.monotonic()
    raw_response, parsed, api_error, output_tokens = call_local_llm(
        client=client,
        prompt=prompt,
        model_name=model_name,
        max_tokens=max_tokens,
    )
    latency = time.monotonic() - t0

    predicted_class = None
    predicted_location = None
    predicted_fix = None
    if parsed:
        predicted_class = parsed.get("failure_class")
        predicted_location = parsed.get("root_cause_location")
        predicted_fix = parsed.get("suggested_fix")

    # Check classification match (if ground truth taxonomy is available)
    expected_class = case.get("taxonomy_class")
    class_match: bool | None = None
    if expected_class and predicted_class:
        class_match = predicted_class == expected_class

    return CaseEvalResult(
        case_id=case_id,
        source=case.get("source", ""),
        taxonomy_class=expected_class or "",
        error_id=case.get("error_id"),
        verifier_log_chars=case.get("verifier_log_chars", 0),
        has_diagnostic=bool(case.get("diagnostic_text")),
        diagnostic_text=case.get("diagnostic_text"),
        prompt=prompt,
        raw_response=raw_response,
        parsed_response=parsed,
        api_error=api_error,
        predicted_failure_class=predicted_class,
        predicted_root_cause_location=predicted_location,
        predicted_suggested_fix=predicted_fix,
        class_match=class_match,
        latency_seconds=round(latency, 3),
        usage_output_tokens=output_tokens,
        extra={"log_source": log_source},
    )


def compute_aggregates(results: list[CaseEvalResult]) -> dict[str, Any]:
    """Compute summary statistics over all evaluation results."""
    total = len(results)
    success = sum(1 for r in results if r.api_error is None)
    parsed_count = sum(1 for r in results if r.parsed_response is not None)
    class_evaluated = [r for r in results if r.class_match is not None]
    class_correct = sum(1 for r in class_evaluated if r.class_match)
    has_fix = sum(1 for r in results if r.predicted_suggested_fix)
    has_location = sum(1 for r in results if r.predicted_root_cause_location)
    latencies = [r.latency_seconds for r in results if r.latency_seconds is not None]
    avg_latency = sum(latencies) / len(latencies) if latencies else None

    # Per-taxonomy breakdown
    per_taxonomy: dict[str, dict[str, Any]] = {}
    for taxonomy in sorted({r.taxonomy_class for r in results if r.taxonomy_class}):
        bucket = [r for r in results if r.taxonomy_class == taxonomy]
        bucket_classified = [r for r in bucket if r.class_match is not None]
        bucket_correct = sum(1 for r in bucket_classified if r.class_match)
        per_taxonomy[taxonomy] = {
            "cases": len(bucket),
            "class_correct": bucket_correct,
            "class_evaluated": len(bucket_classified),
            "class_accuracy_pct": (
                round(bucket_correct / len(bucket_classified) * 100, 1)
                if bucket_classified else None
            ),
        }

    return {
        "total_cases": total,
        "api_success": success,
        "json_parsed": parsed_count,
        "has_predicted_fix": has_fix,
        "has_predicted_location": has_location,
        "class_evaluated": len(class_evaluated),
        "class_correct": class_correct,
        "class_accuracy_pct": (
            round(class_correct / len(class_evaluated) * 100, 1)
            if class_evaluated else None
        ),
        "avg_latency_seconds": round(avg_latency, 3) if avg_latency is not None else None,
        "per_taxonomy": per_taxonomy,
    }


def save_results(
    output_path: Path,
    results: list[CaseEvalResult],
    aggregates: dict[str, Any],
    config: dict[str, Any],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": now_iso(),
        "config": config,
        "aggregates": aggregates,
        "results": [asdict(r) for r in results],
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[output] Saved {len(results)} results to {output_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run BPFix diagnostic evaluation using a local llama.cpp server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="Path to the GGUF model file (default: %(default)s)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Port for llama-server (default: %(default)s)",
    )
    parser.add_argument(
        "--ctx-size",
        type=int,
        default=DEFAULT_CTX_SIZE,
        help="Context size in tokens (default: %(default)s)",
    )
    parser.add_argument(
        "--cases",
        type=Path,
        default=ROOT / DEFAULT_CASES,
        help="Path to batch diagnostic results JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / DEFAULT_OUTPUT,
        help="Output path for results JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=None,
        help="Maximum number of cases to evaluate (default: all)",
    )
    parser.add_argument(
        "--no-start-server",
        action="store_true",
        help="Do not start a llama-server subprocess; assume one is already running",
    )
    parser.add_argument(
        "--no-bpfix",
        action="store_true",
        help="Send only the raw verifier log, without BPFix diagnostic (ablation condition)",
    )
    parser.add_argument(
        "--load-log-from-yaml",
        action="store_true",
        help="Load verifier logs from YAML case files instead of the diagnostic results JSON",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=1024,
        help="Maximum tokens in LLM response (default: %(default)s)",
    )
    parser.add_argument(
        "--startup-timeout",
        type=int,
        default=SERVER_STARTUP_TIMEOUT,
        help="Seconds to wait for server to be ready (default: %(default)s)",
    )
    parser.add_argument(
        "--uvm",
        action="store_true",
        help="Enable CUDA Unified Memory for oversubscribed models (120B)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    server_proc: subprocess.Popen[bytes] | None = None

    def cleanup(signum: int | None = None, frame: Any = None) -> None:
        if server_proc is not None and server_proc.poll() is None:
            print("\n[cleanup] Terminating llama-server...")
            server_proc.terminate()
            try:
                # communicate() drains stderr pipe and waits, preventing pipe deadlock
                server_proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.communicate()
            print("[cleanup] Server stopped.")

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Start server if needed
    if not args.no_start_server:
        extra_env: dict[str, str] = {}
        if args.uvm:
            extra_env["GGML_CUDA_ENABLE_UNIFIED_MEMORY"] = "1"
            extra_env["GGML_CUDA_DISABLE_GRAPHS"] = "1"
            print("[server] UVM mode enabled for large model.")

        server_proc = start_llama_server(
            model_path=args.model,
            port=args.port,
            ctx_size=args.ctx_size,
            extra_env=extra_env if extra_env else None,
        )

        print(f"[server] Waiting up to {args.startup_timeout}s for server to be ready...")
        ready = wait_for_server(args.port, args.startup_timeout)
        if not ready:
            # Surface stderr from the server process to help diagnose failures
            if server_proc is not None and server_proc.poll() is not None:
                stderr_output = b""
                if server_proc.stderr:
                    stderr_output = server_proc.stderr.read()
                print("[error] Server process exited prematurely.")
                if stderr_output:
                    print("[server stderr]", stderr_output.decode("utf-8", errors="replace")[-2000:])
            else:
                print("[error] Server did not become ready within the timeout.")
            cleanup()
            return 1
    else:
        print(f"[server] Skipping server startup (--no-start-server). Expecting server at port {args.port}.")
        # Quick health check to confirm server is available
        try:
            resp = requests.get(f"http://127.0.0.1:{args.port}/health", timeout=5)
            if resp.status_code != 200:
                print(f"[warn] Health check returned {resp.status_code}, proceeding anyway.")
            else:
                print(f"[server] Health check OK: {resp.json()}")
        except Exception as exc:
            print(f"[error] Cannot reach server at port {args.port}: {exc}")
            return 1

    # Set up OpenAI client pointing to local server
    client = OpenAI(
        base_url=f"http://127.0.0.1:{args.port}/v1",
        api_key="not-needed",
    )

    # Determine model name to pass in API requests
    # llama-server accepts any string as the model field
    model_name = "local"

    # Load cases
    cases_path = args.cases
    if not cases_path.is_absolute():
        cases_path = ROOT / cases_path
    cases = load_cases(cases_path, args.max_cases)

    if not cases:
        print("[error] No eligible cases found.")
        cleanup()
        return 1

    include_bpfix = not args.no_bpfix
    condition_label = "bpfix" if include_bpfix else "raw_log_only"
    print(f"[eval] Condition: {condition_label}")
    print(f"[eval] Evaluating {len(cases)} cases...")

    results: list[CaseEvalResult] = []
    for idx, case in enumerate(cases, start=1):
        case_id = case.get("case_id", f"case_{idx}")
        print(f"  [{idx}/{len(cases)}] {case_id}", end="", flush=True)

        result = evaluate_case(
            case=case,
            client=client,
            model_name=model_name,
            include_bpfix=include_bpfix,
            load_log_from_yaml=args.load_log_from_yaml,
            max_tokens=args.max_tokens,
        )
        results.append(result)

        status = "ok" if result.api_error is None else f"ERR:{result.api_error[:40]}"
        match_str = ""
        if result.class_match is not None:
            match_str = " class=MATCH" if result.class_match else " class=MISS"
        print(f"  [{status}]{match_str} ({result.latency_seconds:.1f}s)")

        if idx < len(cases):
            time.sleep(INTER_REQUEST_DELAY)

    # Compute and display aggregates
    aggregates = compute_aggregates(results)
    print("\n[aggregates]")
    print(f"  Total cases:        {aggregates['total_cases']}")
    print(f"  API success:        {aggregates['api_success']}/{aggregates['total_cases']}")
    print(f"  JSON parsed:        {aggregates['json_parsed']}/{aggregates['total_cases']}")
    if aggregates.get("class_accuracy_pct") is not None:
        print(
            f"  Classification:     {aggregates['class_correct']}/{aggregates['class_evaluated']} "
            f"({aggregates['class_accuracy_pct']:.1f}%)"
        )
    if aggregates.get("avg_latency_seconds") is not None:
        print(f"  Avg latency:        {aggregates['avg_latency_seconds']:.1f}s")

    # Save results
    config: dict[str, Any] = {
        "model": args.model,
        "port": args.port,
        "ctx_size": args.ctx_size,
        "cases_path": str(cases_path),
        "max_cases": args.max_cases,
        "include_bpfix": include_bpfix,
        "condition_label": condition_label,
        "load_log_from_yaml": args.load_log_from_yaml,
        "max_tokens": args.max_tokens,
        "started_server": not args.no_start_server,
    }
    output_path = args.output
    if not output_path.is_absolute():
        output_path = ROOT / output_path

    save_results(output_path, results, aggregates, config)

    cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
