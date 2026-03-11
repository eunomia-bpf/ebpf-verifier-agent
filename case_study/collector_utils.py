#!/usr/bin/env python3
from __future__ import annotations

import ast
import html
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

try:
    import requests
except ImportError as exc:  # pragma: no cover - import error is fatal at runtime
    raise SystemExit("Missing dependency: requests. Install it with `pip install requests`.") from exc

try:
    import yaml
except ImportError as exc:  # pragma: no cover - import error is fatal at runtime
    raise SystemExit("Missing dependency: pyyaml. Install it with `pip install pyyaml`.") from exc


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_USER_AGENT = "OBLIGE benchmark collector/0.1"
FIX_KEYWORDS = (
    "fix",
    "fixed",
    "workaround",
    "resolved",
    "solution",
    "solved",
    "root cause",
    "upgrade",
    "downgrade",
    "use ",
    "need to",
    "must ",
    "should ",
    "because",
)
VERIFIER_SIGNAL_PATTERNS = [
    r"\bR\d+\s+invalid\b",
    r"\bR\d+\s+type=",
    r"invalid mem access",
    r"invalid access to",
    r"invalid indirect read from stack",
    r"\bback-edge\b",
    r"\bunreachable\b",
    r"infinite loop detected",
    r"program is too large",
    r"too many states",
    r"helper call",
    r"misaligned stack access",
    r"read_ok",
    r"unreleased reference",
    r"jump out of range",
    r"expected=fp",
    r"Reference may already be released",
    r"leaks addr into map",
    r"cannot write into",
    r"At program exit the register R\d+",
    r"math between .* pointer and register",
]
VERIFIER_SIGNAL_REGEXES = [re.compile(pattern, re.IGNORECASE) for pattern in VERIFIER_SIGNAL_PATTERNS]
FAILURE_LANGUAGE_RE = re.compile(
    r"(?:\berror\b|\bfail(?:ed|s|ing|ure)?\b|\breject(?:ed|s|ing)?\b|permission denied|too large|too complex|"
    r"outside of|unbounded|back-edge|truncated|invalid access|expected=|not allowed|exceeds)",
    re.IGNORECASE,
)
E_BPF_CONTEXT_RE = re.compile(r"\b(?:ebpf|eBPF|bpf|xdp|tc|libbpf)\b")
STACKTRACE_RE = re.compile(r"^\d+:\s+\([0-9a-f]{2}\)", re.IGNORECASE)
FENCED_BLOCK_RE = re.compile(r"```[^\n`]*\n(.*?)```", re.DOTALL)
INDENTED_CODE_RE = re.compile(r"(?m)(?:^(?: {4}|\t).*(?:\n|$))+")
HTML_CODE_RE = re.compile(r"<pre><code>(.*?)</code></pre>", re.IGNORECASE | re.DOTALL)
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
IMAGE_RE = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")
INLINE_CODE_RE = re.compile(r"`([^`]+)`")
TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"[ \t]+")
BLANK_LINES_RE = re.compile(r"\n{3,}")


class HtmlTextExtractor(HTMLParser):
    BLOCK_TAGS = {"br", "p", "div", "li", "pre", "blockquote", "ul", "ol", "h1", "h2", "h3", "h4", "h5"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def get_text(self) -> str:
        return normalize_plain_text("".join(self.parts))


@dataclass
class ProgressLogger:
    quiet: bool = False

    def info(self, message: str) -> None:
        if not self.quiet:
            self._emit("INFO", message)

    def warn(self, message: str) -> None:
        self._emit("WARN", message)

    def error(self, message: str) -> None:
        self._emit("ERROR", message)

    def _emit(self, level: str, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}", file=sys.stderr, flush=True)


class HttpClient:
    def __init__(
        self,
        *,
        user_agent: str = DEFAULT_USER_AGENT,
        min_interval_seconds: float = 1.0,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = 4,
        max_rate_limit_wait_seconds: int = 300,
        logger: ProgressLogger | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent, "Accept": "application/json"})
        if extra_headers:
            self.session.headers.update(extra_headers)
        self.min_interval_seconds = min_interval_seconds
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.max_rate_limit_wait_seconds = max_rate_limit_wait_seconds
        self.logger = logger or ProgressLogger()
        self._last_request_monotonic = 0.0

    def close(self) -> None:
        self.session.close()

    def get_json(self, url: str, *, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> tuple[Any, requests.Response]:
        response = self._request("GET", url, params=params, headers=headers)
        try:
            return response.json(), response
        except ValueError as exc:
            raise RuntimeError(f"Invalid JSON response from {url}: {exc}") from exc

    def download_file(self, url: str, destination: Path, *, headers: dict[str, str] | None = None) -> None:
        response = self._request("GET", url, headers=headers, stream=True)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    handle.write(chunk)

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        stream: bool = False,
    ) -> requests.Response:
        for attempt in range(self.max_retries + 1):
            self._respect_min_interval()
            try:
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout_seconds,
                    stream=stream,
                )
            except requests.RequestException as exc:
                if attempt >= self.max_retries:
                    raise RuntimeError(f"HTTP request failed for {url}: {exc}") from exc
                sleep_seconds = min(2**attempt, 30)
                self.logger.warn(f"Request failed for {url}: {exc}; retrying in {sleep_seconds}s")
                time.sleep(sleep_seconds)
                continue

            self._last_request_monotonic = time.monotonic()
            if self._should_retry(response):
                if attempt >= self.max_retries:
                    self._raise_http_error(response)
                sleep_seconds = self._retry_delay_seconds(response, attempt)
                self.logger.warn(
                    f"Transient HTTP {response.status_code} for {url}; retrying in {sleep_seconds}s"
                )
                time.sleep(sleep_seconds)
                continue

            if not response.ok:
                self._raise_http_error(response)
            return response

        raise RuntimeError(f"Exhausted retries for {url}")

    def _respect_min_interval(self) -> None:
        elapsed = time.monotonic() - self._last_request_monotonic
        if elapsed < self.min_interval_seconds:
            time.sleep(self.min_interval_seconds - elapsed)

    def _should_retry(self, response: requests.Response) -> bool:
        if response.status_code in {429, 500, 502, 503, 504}:
            return True
        return response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0"

    def _retry_delay_seconds(self, response: requests.Response, attempt: int) -> int:
        retry_after = response.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            return int(retry_after)

        remaining = response.headers.get("X-RateLimit-Remaining")
        reset_at = response.headers.get("X-RateLimit-Reset")
        if remaining == "0" and reset_at:
            wait_seconds = max(1, int(reset_at) - int(time.time()) + 1)
            if wait_seconds > self.max_rate_limit_wait_seconds:
                raise RuntimeError(
                    f"Rate limit exhausted; retry after {wait_seconds}s exceeds configured cap "
                    f"({self.max_rate_limit_wait_seconds}s)."
                )
            return wait_seconds

        return min(2**attempt, 60)

    def _raise_http_error(self, response: requests.Response) -> None:
        body = response.text[:500].strip()
        raise RuntimeError(f"HTTP {response.status_code} for {response.url}: {body}")


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def repo_relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT_DIR))
    except ValueError:
        return str(resolved)


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_yaml(path: Path, payload: Any) -> None:
    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(payload, handle, sort_keys=False, allow_unicode=False, width=1000)


def normalize_multiline(text: str) -> str:
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").splitlines()]
    text = "\n".join(lines).strip("\n")
    return BLANK_LINES_RE.sub("\n\n", text).strip()


def normalize_plain_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [WHITESPACE_RE.sub(" ", line).strip() for line in text.splitlines()]
    compact = "\n".join(line for line in lines if line)
    return BLANK_LINES_RE.sub("\n\n", compact).strip()


def dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def slugify(text: str, *, fallback: str = "case", max_length: int = 80) -> str:
    ascii_text = text.encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_text).strip("-")
    if not slug:
        slug = fallback
    return slug[:max_length].rstrip("-") or fallback


def truncate_text(text: str, limit: int) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def strip_html(html_text: str) -> str:
    parser = HtmlTextExtractor()
    parser.feed(html_text or "")
    parser.close()
    return parser.get_text()


def extract_html_code_blocks(html_text: str) -> list[str]:
    blocks = [
        normalize_multiline(html.unescape(match.group(1)))
        for match in HTML_CODE_RE.finditer(html_text or "")
    ]
    return dedupe_preserve_order(blocks)


def strip_markdown(markdown_text: str) -> str:
    text = markdown_text or ""
    text = FENCED_BLOCK_RE.sub("\n", text)
    text = INDENTED_CODE_RE.sub("\n", text)
    text = IMAGE_RE.sub("", text)
    text = LINK_RE.sub(lambda match: match.group(1), text)
    text = INLINE_CODE_RE.sub(lambda match: match.group(1), text)
    text = re.sub(r"(?m)^>\s?", "", text)
    text = re.sub(r"(?m)^#{1,6}\s*", "", text)
    text = re.sub(r"(?m)^[-*+]\s+", "", text)
    text = re.sub(r"(?m)^\d+\.\s+", "", text)
    text = TAG_RE.sub("", text)
    return normalize_plain_text(html.unescape(text))


def extract_markdown_code_blocks(markdown_text: str) -> list[str]:
    blocks = [normalize_multiline(match.group(1)) for match in FENCED_BLOCK_RE.finditer(markdown_text or "")]
    for match in INDENTED_CODE_RE.finditer(markdown_text or ""):
        raw = match.group(0)
        lines = []
        for line in raw.splitlines():
            if line.startswith("\t"):
                lines.append(line[1:])
            elif line.startswith("    "):
                lines.append(line[4:])
            else:
                lines.append(line)
        candidate = normalize_multiline("\n".join(lines))
        if candidate and len(candidate.splitlines()) >= 2:
            blocks.append(candidate)
    return dedupe_preserve_order(blocks)


def contains_verifier_signal(text: str) -> bool:
    haystack = text or ""
    return any(regex.search(haystack) for regex in VERIFIER_SIGNAL_REGEXES)


def contains_ebpf_context(text: str, tags: list[str] | None = None) -> bool:
    if tags and any(tag.lower() in {"ebpf", "bpf", "xdp", "libbpf"} for tag in tags):
        return True
    return bool(E_BPF_CONTEXT_RE.search(text or ""))


def contains_failure_language(text: str) -> bool:
    return bool(FAILURE_LANGUAGE_RE.search(text or ""))


def score_verifier_log(block: str) -> int:
    score = 0
    lower = block.lower()
    for regex in VERIFIER_SIGNAL_REGEXES:
        if regex.search(block):
            score += 3
    if re.search(r"\bR\d+\b", block):
        score += 1
    if STACKTRACE_RE.search(block):
        score += 2
    if "processed " in lower and " insns" in lower:
        score += 2
    if any(token in lower for token in ("verification time", "max_states_per_insn", "mark_read", "caller passes invalid")):
        score += 2
    if lower.count("invalid") >= 2:
        score += 1
    return score


def score_source_code(block: str) -> int:
    score = 0
    patterns = ("#include", "SEC(\"", "return ", "struct ", "asm volatile", "bpf_", "__u", "if ", "for ", "while ")
    for token in patterns:
        if token in block:
            score += 1
    if "{" in block and "}" in block:
        score += 1
    if ";" in block:
        score += 1
    return score


def classify_code_block(block: str) -> str:
    log_score = score_verifier_log(block)
    source_score = score_source_code(block)
    if log_score >= 3 and log_score >= source_score:
        return "verifier_log"
    if source_score >= 2:
        return "source"
    if log_score >= 1:
        return "verifier_log"
    return "other"


def partition_code_blocks(blocks: list[str]) -> tuple[list[str], list[str]]:
    verifier_logs: list[str] = []
    source_snippets: list[str] = []
    for block in blocks:
        kind = classify_code_block(block)
        if kind == "verifier_log":
            verifier_logs.append(block)
        elif kind == "source":
            source_snippets.append(block)
    return dedupe_preserve_order(verifier_logs), dedupe_preserve_order(source_snippets)


def c_string_unescape(raw: str) -> str:
    try:
        return ast.literal_eval(f'"{raw}"')
    except (ValueError, SyntaxError):
        return raw.replace(r"\"", '"')


def summarize_fix_description(text: str, *, max_sentences: int = 3, max_chars: int = 600) -> str:
    plain = normalize_plain_text(text)
    if not plain:
        return ""

    lines = [line.strip(" -*") for line in plain.splitlines() if line.strip()]
    preferred = [line for line in lines if any(keyword in line.lower() for keyword in FIX_KEYWORDS)]
    candidates = preferred or lines
    chosen: list[str] = []
    for candidate in candidates:
        if contains_verifier_signal(candidate) and len(candidate.split()) < 8:
            continue
        chosen.append(candidate)
        if len(chosen) >= max_sentences:
            break
    if not chosen:
        chosen = candidates[:max_sentences]
    return truncate_text(" ".join(chosen), max_chars)


def stackexchange_backoff_seconds(payload: dict[str, Any]) -> int:
    backoff = payload.get("backoff")
    if isinstance(backoff, int) and backoff > 0:
        return backoff
    return 0


def compact_case_index(
    *,
    source_name: str,
    script_name: str,
    output_dir: Path,
    cases: list[dict[str, Any]],
    source_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "source": source_name,
        "generated_at": utc_now(),
        "generator": script_name,
        "case_count": len(cases),
        "output_dir": repo_relative(output_dir),
        "source_details": source_details or {},
        "cases": cases,
    }
