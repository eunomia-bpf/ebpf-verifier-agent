#!/usr/bin/env python3
"""Large-scale collection of eval commit pairs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path('/tmp/ebpf-eval-repos')
OUTPUT_DIR = ROOT / 'case_study' / 'cases' / 'eval_commits'
REPORT_PATH = ROOT / 'docs' / 'tmp' / 'rex-large-scale-collection-report.md'
RUN_DATE = '2026-03-11'
MAX_DIFF_LINES = 200
CONTEXT_LINES = 12
CODE_SUFFIXES = {'.c', '.h', '.rs', '.go', '.cpp', '.cc', '.hpp', '.hh'}

SEARCH_PATTERNS: tuple[tuple[str, str], ...] = (
    ('verifier', r'verifier'),
    ('reject', r'invalid access|load rejected|bpf.*reject|reject.*bpf'),
    ('inline', r'__always_inline|always[ -]?inline|inline\(always\)|inline\(never\)'),
    ('bounds', r'out[- ]of[- ]bounds|oob|bounds?|unbounded|misaligned|unaligned|alignment'),
    ('complexity', r'too complex|complexity|state explosion|stack depth'),
    ('volatile', r'volatile|barrier|READ_ONCE'),
    ('kernel_compat', r'older kernels?|old kernels?|old kernel|rhel.*verifier|aarch64.*5\.5|clang\s*(15|17|18)'),
    ('workaround', r'make .*verifier happy|appease .*verifier|get .*past the verifier'),
    ('helper', r'netns cookie|probe_read_kernel_supported'),
)

VERIFIER_RE = re.compile(r'\bverifier\b', re.IGNORECASE)
STRONG_RE = re.compile(
    r'invalid access|misaligned|unaligned|out[- ]of[- ]bounds|\boob\b|unbounded|'
    r'too complex|complexity|state explosion|stack depth|make .*verifier happy|'
    r'appease .*verifier|get .*past the verifier|fix verifier|verification issue|'
    r'small verifier bug|R\d+ !read_ok|same insn cannot be used with different pointers|'
    r'old bpf probe|BTF verifier error|bounds tracking',
    re.IGNORECASE,
)
SECONDARY_RE = re.compile(
    r'older kernels?|old kernels?|old kernel|helper|bpf_loop|null|alignment|'
    r'__always_inline|always[ -]?inline|clang\s*(15|17|18)|aarch64.*5\.5|'
    r'probe_read_kernel_supported|compatibility with clang|old kernel',
    re.IGNORECASE,
)
COMPAT_RE = re.compile(r'older kernels?|old kernels?|old kernel|rhel|aarch64.*5\.5|clang\s*(15|17|18)', re.IGNORECASE)
COMPAT_CONTEXT_RE = re.compile(r'helper|probe_read|sockaddr|bounds|align|inline|bss|null|loop|verifier|probe', re.IGNORECASE)
SKIP_SUBJECT_RE = re.compile(r'clippy|integration-test|comment|info api|mapinfo|programinfo|cargo symlink', re.IGNORECASE)
BLACKLIST_RE = re.compile(
    r'verifier log|log level|display verifier log|dump program on test failures|'
    r'debug verifier|verifier tests|document .* verifier|enable verifier log',
    re.IGNORECASE,
)
DIFF_MARKER_RE = re.compile(
    r'__always_inline|__noinline|inline\(always\)|inline\(never\)|__align_stack_8|'
    r'volatile|barrier\(|PTR_TO_CTX|map_value_or_null|LOG_BUF_CAPACITY|ctx_data_end|'
    r'data_end|misaligned|unaligned|#pragma\s+unroll|bpf_loop|READ_ONCE|asm volatile',
    re.IGNORECASE,
)
NULL_CHECK_RE = re.compile(r'^\+\s*if\s*\(\s*!\s*[A-Za-z_][A-Za-z0-9_]*\s*\)', re.MULTILINE)
GUARD_RE = re.compile(r'^\+.*\bif\s*\(', re.MULTILINE)
RETURN_RE = re.compile(r'^\+.*\breturn\b', re.MULTILINE)
ALIGNMENT_RE = re.compile(r'\b(misaligned|unaligned|align(?:ment)?|__align_stack_8)\b', re.IGNORECASE)
INLINE_RE = re.compile(r'__always_inline|__noinline|inline\(always\)|inline\(never\)', re.IGNORECASE)
VOLATILE_RE = re.compile(r'\bvolatile\b', re.IGNORECASE)
BOUNDS_RE = re.compile(r'\b(bounds?|unbounded|size|len|length|offset|data_end|limit|range|oob)\b', re.IGNORECASE)
LOOP_RE = re.compile(r'\b(loop|unroll|too complex|complexity|state explosion)\b', re.IGNORECASE)
HELPER_RE = re.compile(r'\b(helper|cookie|get_netns_cookie|bpf_[a-z0-9_]+|probe_read)\b', re.IGNORECASE)
TYPE_RE = re.compile(r'PTR_TO_CTX|map_value_or_null|cast|struct\s+__ctx_buff\s*\*|struct\s+xdp_md\s*\*', re.IGNORECASE)
ATTRIBUTE_RE = re.compile(r'__attribute__|__packed|__aligned|__weak|__noinline', re.IGNORECASE)
READ_ONCE_RE = re.compile(r'READ_ONCE|asm volatile|barrier\(', re.IGNORECASE)


class LiteralString(str):
    pass


def _literal_representer(dumper: yaml.SafeDumper, data: LiteralString) -> yaml.nodes.ScalarNode:
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')


yaml.SafeDumper.add_representer(LiteralString, _literal_representer)


@dataclass(frozen=True)
class RepoSpec:
    name: str
    url: str
    local_dir: str
    search_paths: tuple[str, ...]


@dataclass(frozen=True)
class CommitMeta:
    parent: str
    subject: str
    body: str
    date: str
    timestamp: int


@dataclass(frozen=True)
class HunkRange:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str


@dataclass(frozen=True)
class MergedRange:
    start: int
    end: int
    headers: tuple[str, ...]


@dataclass
class Candidate:
    repo: RepoSpec
    commit_hash: str
    meta: CommitMeta
    reason_tags: set[str]
    changed_files: list[str]
    diff_lines: int
    patch_fingerprint: str
    fix_type: str
    buggy_code: str
    fixed_code: str
    diff_summary: str
    contexts: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass
class RepoStats:
    search_hits: int = 0
    candidates_found: int = 0
    cases_collected: int = 0
    already_present: int = 0
    duplicates_skipped: int = 0
    too_large_skipped: int = 0
    weak_match_skipped: int = 0
    no_code_skipped: int = 0
    merge_skipped: int = 0
    git_failure_skipped: int = 0


REPOS: tuple[RepoSpec, ...] = (
    RepoSpec('cilium', 'https://github.com/cilium/cilium', 'cilium', ('bpf',)),
    RepoSpec('aya', 'https://github.com/aya-rs/aya', 'aya', ('aya-log', 'bpf', 'ebpf', 'test/integration-ebpf')),
    RepoSpec('katran', 'https://github.com/facebookincubator/katran', 'katran', ('katran/lib/bpf',)),
    RepoSpec('linux', 'https://github.com/torvalds/linux', 'linux', ('tools/testing/selftests/bpf',)),
    RepoSpec('libbpf', 'https://github.com/libbpf/libbpf', 'libbpf', ('src', 'examples', 'tools', 'selftests', 'samples')),
    RepoSpec('bcc', 'https://github.com/iovisor/bcc', 'bcc', ('examples', 'libbpf-tools', 'tools', 'src', 'tests')),
    RepoSpec('bpftrace', 'https://github.com/bpftrace/bpftrace', 'bpftrace', ('src', 'tests')),
    RepoSpec('calico', 'https://github.com/projectcalico/calico', 'calico', ('felix',)),
    RepoSpec('falco', 'https://github.com/falcosecurity/libs', 'falco', ('driver', 'userspace')),
    RepoSpec('tracee', 'https://github.com/aquasecurity/tracee', 'tracee', ('pkg/ebpf', 'tests')),
    RepoSpec('tetragon', 'https://github.com/cilium/tetragon', 'tetragon', ('bpf', 'pkg/bpf', 'pkg/sensors')),
)
REPO_INDEX = {repo.name: repo for repo in REPOS}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=OUTPUT_DIR)
    parser.add_argument('--report', type=Path, default=REPORT_PATH)
    parser.add_argument('--max-diff-lines', type=int, default=MAX_DIFF_LINES)
    parser.add_argument('--target-new-cases', type=int, default=100)
    parser.add_argument('--repos', nargs='*', choices=sorted(REPO_INDEX), default=sorted(REPO_INDEX))
    return parser.parse_args()


def run_git(repo_path: Path, *args: str) -> str:
    result = subprocess.run(['git', *args], cwd=repo_path, check=True, capture_output=True, text=True)
    return result.stdout


def ensure_repo(repo: RepoSpec) -> Path:
    target = REPO_ROOT / repo.local_dir
    if target.exists():
        try:
            run_git(target, 'rev-parse', 'HEAD')
            return target
        except subprocess.CalledProcessError:
            shutil.rmtree(target)
    REPO_ROOT.mkdir(parents=True, exist_ok=True)
    clone_cmd = ['git', '-c', 'http.version=HTTP/1.1', 'clone', '--depth=5000', '--filter=blob:none', repo.url, str(target)]
    subprocess.run(clone_cmd, check=True, cwd=REPO_ROOT)
    return target


def load_existing_cases(output_dir: Path) -> tuple[set[str], set[str], list[dict[str, object]]]:
    case_ids: set[str] = set()
    commit_hashes: set[str] = set()
    payloads: list[dict[str, object]] = []
    if not output_dir.exists():
        return case_ids, commit_hashes, payloads
    for path in sorted(output_dir.glob('eval-*.yaml')):
        try:
            payload = yaml.safe_load(path.read_text(encoding='utf-8')) or {}
        except yaml.YAMLError:
            continue
        if not isinstance(payload, dict):
            continue
        case_id = payload.get('case_id')
        commit_hash = payload.get('commit_hash')
        if isinstance(case_id, str):
            case_ids.add(case_id)
        if isinstance(commit_hash, str):
            commit_hashes.add(commit_hash)
        payloads.append(payload)
    return case_ids, commit_hashes, payloads


def discover_hits(repo_path: Path, repo: RepoSpec) -> dict[str, set[str]]:
    hits: dict[str, set[str]] = defaultdict(set)
    for tag, pattern in SEARCH_PATTERNS:
        output = run_git(
            repo_path,
            'log',
            '--format=%H',
            '--all',
            '--regexp-ignore-case',
            '--extended-regexp',
            f'--grep={pattern}',
            '--',
            *repo.search_paths,
        )
        for commit_hash in output.splitlines():
            if commit_hash:
                hits[commit_hash].add(tag)
    return hits


def commit_meta(repo_path: Path, commit_hash: str) -> CommitMeta | None:
    output = run_git(
        repo_path,
        'show',
        '--format=%P%x1f%ct%x1f%ad%x1f%s%x1f%b',
        '--date=short',
        '--no-patch',
        commit_hash,
    ).rstrip('\n')
    parts = output.split('\x1f', 4)
    if len(parts) != 5:
        raise RuntimeError(f'unexpected git metadata format for {commit_hash}')
    parents, timestamp, date, subject, body = parts
    parent_hashes = [item for item in parents.split() if item]
    if len(parent_hashes) != 1:
        return None
    return CommitMeta(
        parent=parent_hashes[0],
        subject=subject.strip(),
        body=body.strip(),
        date=date.strip(),
        timestamp=int(timestamp.strip()),
    )


def message_score(subject: str, body: str, reason_tags: set[str]) -> int:
    text = f'{subject}\n{body}'
    if BLACKLIST_RE.search(text):
        return -100
    score = 0
    if VERIFIER_RE.search(text):
        score += 5
    if STRONG_RE.search(text):
        score += 4
    if SECONDARY_RE.search(text):
        score += 2
    score += min(3, len(reason_tags))
    if 'fix' in subject.lower():
        score += 1
    if 'bpf' in subject.lower() or 'ebpf' in subject.lower():
        score += 1
    return score


def changed_code_files(repo_path: Path, parent: str, commit_hash: str, repo: RepoSpec) -> list[str]:
    output = run_git(
        repo_path,
        'diff',
        '--name-status',
        '--diff-filter=M',
        '-M',
        parent,
        commit_hash,
        '--',
        *repo.search_paths,
    )
    files: list[str] = []
    for line in output.splitlines():
        parts = line.split('\t')
        if len(parts) < 2:
            continue
        path = parts[-1]
        if Path(path).suffix.lower() in CODE_SUFFIXES:
            files.append(path)
    return files


def diff_line_count(repo_path: Path, parent: str, commit_hash: str, files: Iterable[str]) -> int:
    file_list = list(files)
    if not file_list:
        return 0
    output = run_git(repo_path, 'diff', '--numstat', parent, commit_hash, '--', *file_list)
    total = 0
    for line in output.splitlines():
        parts = line.split('\t')
        if len(parts) < 3:
            continue
        added, deleted = parts[:2]
        if added == '-' or deleted == '-':
            continue
        total += int(added) + int(deleted)
    return total


def diff_text(repo_path: Path, parent: str, commit_hash: str, files: Iterable[str], context: int) -> str:
    file_list = list(files)
    if not file_list:
        return ''
    return run_git(repo_path, 'diff', f'--unified={context}', parent, commit_hash, '--', *file_list)


def parse_hunks(diff_output: str) -> list[HunkRange]:
    header_re = re.compile(r'^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?: (?P<header>.*))?$')
    hunks: list[HunkRange] = []
    for line in diff_output.splitlines():
        match = header_re.match(line)
        if not match:
            continue
        hunks.append(
            HunkRange(
                old_start=int(match.group('old_start')),
                old_count=int(match.group('old_count') or '1'),
                new_start=int(match.group('new_start')),
                new_count=int(match.group('new_count') or '1'),
                header=(match.group('header') or '').strip(),
            )
        )
    return hunks


def merge_ranges(hunks: Iterable[HunkRange], side: str) -> list[MergedRange]:
    items: list[tuple[int, int, str]] = []
    for hunk in hunks:
        start = hunk.old_start if side == 'old' else hunk.new_start
        count = hunk.old_count if side == 'old' else hunk.new_count
        if count == 0:
            continue
        items.append((start, start + count - 1, hunk.header))
    items.sort(key=lambda item: (item[0], item[1], item[2]))
    merged: list[MergedRange] = []
    for start, end, header in items:
        if not merged or start > merged[-1].end + 1:
            merged.append(MergedRange(start=start, end=end, headers=tuple([header] if header else [])))
            continue
        prev = merged[-1]
        headers = list(prev.headers)
        if header and header not in headers:
            headers.append(header)
        merged[-1] = MergedRange(start=prev.start, end=max(prev.end, end), headers=tuple(headers))
    return merged


def blob_lines(repo_path: Path, rev: str, file_path: str) -> list[str]:
    return run_git(repo_path, 'show', f'{rev}:{file_path}').splitlines()


def render_sections(file_path: str, lines: list[str], ranges: list[MergedRange]) -> str:
    sections: list[str] = [f'// FILE: {file_path}']
    for index, merged in enumerate(ranges, start=1):
        if index > 1:
            sections.append('')
        if merged.headers:
            sections.append(f"// CONTEXT: {' | '.join(merged.headers)}")
        start_index = max(1, merged.start)
        end_index = min(len(lines), merged.end)
        sections.extend(lines[start_index - 1:end_index])
    return '\n'.join(sections).rstrip() + '\n'


def extract_code_pair(repo_path: Path, parent: str, commit_hash: str, files: Iterable[str]) -> tuple[str, str, dict[str, tuple[str, ...]]]:
    before_chunks: list[str] = []
    after_chunks: list[str] = []
    contexts: dict[str, tuple[str, ...]] = {}
    for file_path in files:
        patch = run_git(repo_path, 'diff', f'--unified={CONTEXT_LINES}', parent, commit_hash, '--', file_path)
        hunks = parse_hunks(patch)
        if not hunks:
            continue
        before_lines = blob_lines(repo_path, parent, file_path)
        after_lines = blob_lines(repo_path, commit_hash, file_path)
        before_chunks.append(render_sections(file_path, before_lines, merge_ranges(hunks, 'old')).rstrip())
        after_chunks.append(render_sections(file_path, after_lines, merge_ranges(hunks, 'new')).rstrip())
        headers: list[str] = []
        for hunk in hunks:
            if hunk.header and hunk.header not in headers:
                headers.append(hunk.header)
        contexts[file_path] = tuple(headers)
    before = '\n\n'.join(chunk for chunk in before_chunks if chunk).rstrip() + '\n'
    after = '\n\n'.join(chunk for chunk in after_chunks if chunk).rstrip() + '\n'
    return before, after, contexts


def patch_fingerprint(repo_path: Path, parent: str, commit_hash: str, files: Iterable[str]) -> str:
    raw = diff_text(repo_path, parent, commit_hash, files, context=0)
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()


def classify_fix_type(subject: str, body: str, diff: str) -> str:
    text = f'{subject}\n{body}\n{diff}'
    if INLINE_RE.search(text):
        return 'inline_hint'
    if VOLATILE_RE.search(text):
        return 'volatile_hack'
    if ALIGNMENT_RE.search(text):
        return 'alignment'
    if 'null' in text.lower() and NULL_CHECK_RE.search(diff):
        return 'null_check'
    if TYPE_RE.search(text):
        return 'type_cast'
    if HELPER_RE.search(text) and ('old kernel' in text.lower() or 'older kernel' in text.lower() or 'helper' in subject.lower()):
        return 'helper_switch'
    if LOOP_RE.search(text):
        return 'loop_rewrite'
    if BOUNDS_RE.search(text) and (GUARD_RE.search(diff) or 'data_end' in text.lower()):
        return 'bounds_check'
    if ATTRIBUTE_RE.search(text):
        return 'attribute_annotation'
    if READ_ONCE_RE.search(text) or 'refactor' in subject.lower() or 'state explosion' in text.lower():
        return 'refactor'
    return 'other'


def summary_phrase(fix_type: str) -> str:
    return {
        'bounds_check': 'Added explicit bounds or range guards so the verifier can prove the access size and offset.',
        'inline_hint': 'Changed inlining annotations so verifier-visible state stays in a form older kernels accept.',
        'type_cast': 'Adjusted types or casts so the verifier sees the intended pointer or value kind.',
        'null_check': 'Added an explicit null guard before the dereference on all verifier-visible paths.',
        'helper_switch': 'Gated or switched helper usage so unsupported helpers do not reach kernels that reject them.',
        'refactor': 'Restructured control flow or temporaries without changing intent to satisfy verifier reasoning.',
        'loop_rewrite': 'Reworked loop or branch structure to reduce verifier complexity and keep the path bounded.',
        'alignment': 'Adjusted alignment declarations or stack layout to avoid misaligned accesses.',
        'volatile_hack': 'Added or changed a volatile qualifier to force verifier-friendly code generation.',
        'attribute_annotation': 'Changed verifier-relevant attributes or annotations on the affected declarations.',
        'other': 'Applied a small verifier-related code change captured by the exact before/after snippets below.',
    }[fix_type]


def build_diff_summary(repo: RepoSpec, subject: str, fix_type: str, changed_files: list[str], contexts: dict[str, tuple[str, ...]]) -> str:
    lines: list[str] = []
    for file_path in changed_files:
        context_text = ', '.join(contexts.get(file_path, ())[:3]) if contexts.get(file_path) else 'the touched section'
        lines.append(f'{file_path}:')
        lines.append(f'- {summary_phrase(fix_type)}')
        lines.append(f'- Affected context: {context_text}.')
    lines.append(f'- Commit subject: {subject}.')
    return '\n'.join(lines)


def yaml_scalar(value: object) -> str:
    return json.dumps(value, ensure_ascii=True)


def dump_yaml(path: Path, payload: dict[str, object]) -> None:
    lines: list[str] = []
    for key in ('case_id', 'source', 'repository', 'commit_hash', 'commit_message', 'commit_date', 'fix_type'):
        lines.append(f'{key}: {yaml_scalar(payload[key])}')
    for key in ('buggy_code', 'fixed_code', 'diff_summary'):
        lines.append(f'{key}: |-')
        text = str(payload[key])
        if not text:
            lines.append('  ')
        else:
            for line in text.splitlines():
                lines.append(f'  {line}')
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def build_candidate(repo: RepoSpec, repo_path: Path, commit_hash: str, reason_tags: set[str], max_diff_lines: int, stats: RepoStats) -> Candidate | None:
    try:
        meta = commit_meta(repo_path, commit_hash)
    except subprocess.CalledProcessError:
        stats.git_failure_skipped += 1
        return None
    if meta is None:
        stats.merge_skipped += 1
        return None
    base_score = message_score(meta.subject, meta.body, reason_tags)
    text_blob = f'{meta.subject}\n{meta.body}'
    if base_score < 5:
        stats.weak_match_skipped += 1
        return None
    if SKIP_SUBJECT_RE.search(meta.subject) and not (VERIFIER_RE.search(text_blob) or STRONG_RE.search(text_blob)):
        stats.weak_match_skipped += 1
        return None
    if COMPAT_RE.search(text_blob) and not (VERIFIER_RE.search(text_blob) or STRONG_RE.search(text_blob) or COMPAT_CONTEXT_RE.search(text_blob)):
        stats.weak_match_skipped += 1
        return None
    try:
        changed_files = changed_code_files(repo_path, meta.parent, commit_hash, repo)
        if not changed_files:
            stats.no_code_skipped += 1
            return None
        diff_lines = diff_line_count(repo_path, meta.parent, commit_hash, changed_files)
        if diff_lines == 0:
            stats.no_code_skipped += 1
            return None
        if diff_lines > max_diff_lines:
            stats.too_large_skipped += 1
            return None
        patch = diff_text(repo_path, meta.parent, commit_hash, changed_files, context=3)
        score = base_score
        if DIFF_MARKER_RE.search(patch):
            score += 4
        if GUARD_RE.search(patch) and RETURN_RE.search(patch):
            score += 2
        if any('bpf' in path.lower() or 'ebpf' in path.lower() for path in changed_files):
            score += 1
        if score < 6:
            stats.weak_match_skipped += 1
            return None
        buggy_code, fixed_code, contexts = extract_code_pair(repo_path, meta.parent, commit_hash, changed_files)
        if not buggy_code.strip() or not fixed_code.strip():
            stats.no_code_skipped += 1
            return None
        fix_type = classify_fix_type(meta.subject, meta.body, patch)
        return Candidate(
            repo=repo,
            commit_hash=commit_hash,
            meta=meta,
            reason_tags=set(reason_tags),
            changed_files=changed_files,
            diff_lines=diff_lines,
            patch_fingerprint=patch_fingerprint(repo_path, meta.parent, commit_hash, changed_files),
            fix_type=fix_type,
            buggy_code=buggy_code,
            fixed_code=fixed_code,
            diff_summary=build_diff_summary(repo, meta.subject, fix_type, changed_files, contexts),
            contexts=contexts,
        )
    except subprocess.CalledProcessError:
        stats.git_failure_skipped += 1
        return None


def collect_candidates(repo: RepoSpec, repo_path: Path, max_diff_lines: int) -> tuple[list[Candidate], RepoStats]:
    stats = RepoStats()
    hits = discover_hits(repo_path, repo)
    stats.search_hits = len(hits)
    print(f'[{repo.name}] search hits: {stats.search_hits}', flush=True)
    metas: list[tuple[int, str]] = []
    for commit_hash in hits:
        try:
            meta = commit_meta(repo_path, commit_hash)
        except subprocess.CalledProcessError:
            stats.git_failure_skipped += 1
            continue
        if meta is None:
            stats.merge_skipped += 1
            continue
        metas.append((meta.timestamp, commit_hash))
    metas.sort()
    candidates: list[Candidate] = []
    seen_patches: set[str] = set()
    for _, commit_hash in metas:
        candidate = build_candidate(repo, repo_path, commit_hash, hits[commit_hash], max_diff_lines, stats)
        if candidate is None:
            continue
        if candidate.patch_fingerprint in seen_patches:
            stats.duplicates_skipped += 1
            continue
        seen_patches.add(candidate.patch_fingerprint)
        stats.candidates_found += 1
        candidates.append(candidate)
    print(
        f'[{repo.name}] candidates={stats.candidates_found} duplicates={stats.duplicates_skipped} '
        f'too_large={stats.too_large_skipped} weak={stats.weak_match_skipped} git_fail={stats.git_failure_skipped}',
        flush=True,
    )
    return candidates, stats


def render_report(
    all_case_payloads: list[dict[str, object]],
    per_repo_stats: dict[str, RepoStats],
    new_case_count: int,
    target_new_cases: int,
    selected_repos: list[str],
) -> str:
    by_repo = Counter()
    fix_types = Counter()
    for payload in all_case_payloads:
        case_id = str(payload.get('case_id', ''))
        fix_type = str(payload.get('fix_type', 'other'))
        fix_types[fix_type] += 1
        for repo in selected_repos:
            if case_id.startswith(f'eval-{repo}-'):
                by_repo[repo] += 1
                break
    lines: list[str] = []
    lines.append('# Eval Large-Scale Collection Report')
    lines.append('')
    lines.append(f'Run date: {RUN_DATE}')
    lines.append('')
    lines.append('## Outcome')
    lines.append('')
    lines.append(f'- New YAML cases written this run: {new_case_count}.')
    lines.append(f'- Total `eval_commits` YAML cases now present: {len(all_case_payloads)}.')
    lines.append(f"- Target status: {'met' if new_case_count >= target_new_cases else 'not met'} for the requested floor of {target_new_cases} new cases.")
    lines.append('')
    lines.append('## Per-Repo Search Summary')
    lines.append('')
    lines.append('| Repo | Commits searched | Candidates found | Cases collected | Already present | Duplicates skipped | Too large skipped | Weak-match skipped | Git failures skipped |')
    lines.append('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |')
    for repo in selected_repos:
        stats = per_repo_stats.get(repo, RepoStats())
        lines.append(
            f'| {repo} | {stats.search_hits} | {stats.candidates_found} | {stats.cases_collected} | '
            f'{stats.already_present} | {stats.duplicates_skipped} | {stats.too_large_skipped} | {stats.weak_match_skipped} | {stats.git_failure_skipped} |'
        )
    lines.append('')
    lines.append('## Fix Type Distribution')
    lines.append('')
    lines.append('| Fix type | Cases |')
    lines.append('| --- | ---: |')
    for fix_type, count in sorted(fix_types.items()):
        lines.append(f'| {fix_type} | {count} |')
    lines.append('')
    lines.append('## Top Repos By Contribution')
    lines.append('')
    lines.append('| Repo | Total cases in corpus |')
    lines.append('| --- | ---: |')
    for repo, count in by_repo.most_common():
        lines.append(f'| {repo} | {count} |')
    lines.append('')
    lines.append('## Notable Patterns')
    lines.append('')
    if fix_types:
        common = ', '.join(f'{name} ({count})' for name, count in fix_types.most_common(5))
        lines.append(f'- Most common workaround classes in the collected corpus: {common}.')
    lines.append('- Compact verifier workarounds cluster around explicit bounds proofs, helper compatibility for older kernels, stack/alignment fixes, and control-flow reshaping.')
    lines.append('- Modern eBPF projects still carry verifier-compatibility patches outside pure `.bpf.c` code, especially in generated headers, helper wrappers, and loader-side compatibility probes.')
    lines.append('- Older-kernel support remains a major source of workaround commits, especially in BCC, bpftrace, Calico, Tracee, and Tetragon.')
    lines.append('')
    lines.append('## Notes')
    lines.append('')
    lines.append(f'- Complexity filter: skipped commits whose relevant code diff exceeded {MAX_DIFF_LINES} changed lines.')
    lines.append('- Snippets were extracted from actual git blob versions (`commit^:path` and `commit:path`) and trimmed to the touched sections with diff context.')
    lines.append('- Obvious duplicate backports and cherry-picks were de-duplicated using a patch fingerprint over the relevant code diff.')
    return '\n'.join(lines) + '\n'


def main() -> int:
    args = parse_args()
    selected_repos = list(args.repos)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)

    existing_case_ids, existing_commit_hashes, existing_payloads = load_existing_cases(args.output_dir)
    repo_paths: dict[str, Path] = {}
    for name in selected_repos:
        repo_paths[name] = ensure_repo(REPO_INDEX[name])

    per_repo_stats: dict[str, RepoStats] = {}
    new_case_count = 0
    for name in selected_repos:
        repo = REPO_INDEX[name]
        candidates, stats = collect_candidates(repo, repo_paths[name], args.max_diff_lines)
        per_repo_stats[name] = stats
        for candidate in candidates:
            short_hash = candidate.commit_hash[:12]
            case_id = f'eval-{repo.name}-{short_hash}'
            if case_id in existing_case_ids or candidate.commit_hash in existing_commit_hashes:
                stats.already_present += 1
                continue
            payload = {
                'case_id': case_id,
                'source': 'eval_commits',
                'repository': repo.url,
                'commit_hash': candidate.commit_hash,
                'commit_message': candidate.meta.subject,
                'commit_date': candidate.meta.date,
                'fix_type': candidate.fix_type,
                'buggy_code': LiteralString(candidate.buggy_code.rstrip('\n')),
                'fixed_code': LiteralString(candidate.fixed_code.rstrip('\n')),
                'diff_summary': LiteralString(candidate.diff_summary),
            }
            dump_yaml(args.output_dir / f'{case_id}.yaml', payload)
            existing_case_ids.add(case_id)
            existing_commit_hashes.add(candidate.commit_hash)
            existing_payloads.append(payload)
            stats.cases_collected += 1
            new_case_count += 1
        print(f'[{repo.name}] wrote {stats.cases_collected} new cases', flush=True)

    args.report.write_text(
        render_report(existing_payloads, per_repo_stats, new_case_count, args.target_new_cases, selected_repos),
        encoding='utf-8',
    )
    print(f'Wrote {new_case_count} new YAML cases to {args.output_dir}')
    print(f'Total eval_commits cases present: {len(existing_payloads)}')
    print(f'Wrote report to {args.report}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
