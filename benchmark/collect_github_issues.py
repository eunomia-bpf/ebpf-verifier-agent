#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from collector_utils import (
    HttpClient,
    ProgressLogger,
    compact_case_index,
    contains_verifier_signal,
    dedupe_preserve_order,
    ensure_directory,
    extract_markdown_code_blocks,
    partition_code_blocks,
    repo_relative,
    strip_markdown,
    summarize_fix_description,
    truncate_text,
    utc_now,
    write_yaml,
)


GITHUB_API = "https://api.github.com"
DEFAULT_REPOSITORIES = ["cilium/cilium", "aya-rs/aya", "facebookincubator/katran"]
DEFAULT_QUERY = "verifier"
MAINTAINER_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
ACTIONABLE_FIX_MARKERS = (
    "fix",
    "fixed",
    "workaround",
    "resolved",
    "solution",
    "solved",
    "upgrade",
    "downgrade",
    "need to",
    "needs to",
    "must ",
    "should ",
    "you are not",
    "drop the returned",
    "consume the logs",
    "consuming the logs",
    "hold on to",
    "leading to",
    "caused by",
    "broken until",
)
LOW_SIGNAL_MARKERS = (
    "please provide more complete information",
    "i am confused",
    "where do i see",
    "what i tried",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect eBPF verifier failure cases from GitHub issues.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("benchmark/cases/github_issues"),
        help="Directory where YAML case files and index.yaml are written.",
    )
    parser.add_argument(
        "--repository",
        action="append",
        default=[],
        help="Repository to search, e.g. owner/name. May be passed multiple times.",
    )
    parser.add_argument(
        "--query",
        action="append",
        default=[],
        help="Additional GitHub search query expression. May be passed multiple times.",
    )
    parser.add_argument(
        "--max-issues",
        type=int,
        default=50,
        help="Maximum number of relevant issues to save.",
    )
    parser.add_argument(
        "--pagesize",
        type=int,
        default=20,
        help="GitHub API page size (max 100).",
    )
    parser.add_argument(
        "--max-pages-per-query",
        type=int,
        default=2,
        help="Maximum pages to fetch per repository/query pair.",
    )
    parser.add_argument(
        "--max-comments",
        type=int,
        default=100,
        help="Maximum number of issue comments to fetch per issue.",
    )
    parser.add_argument(
        "--github-token",
        default=os.environ.get("GITHUB_TOKEN", ""),
        help="GitHub token. Defaults to GITHUB_TOKEN when set.",
    )
    parser.add_argument(
        "--min-interval-seconds",
        type=float,
        default=2.0,
        help="Minimum delay between GitHub API requests.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Increase progress output. Accepted for CLI parity; logging is verbose by default.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce progress output.",
    )
    args = parser.parse_args()
    if args.verbose:
        args.quiet = False
    return args


class GitHubIssuesCollector:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = ProgressLogger(quiet=args.quiet)
        self.comments_disabled_reason = ""
        headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
        if args.github_token:
            headers["Authorization"] = f"Bearer {args.github_token}"
        self.client = HttpClient(
            min_interval_seconds=args.min_interval_seconds,
            logger=self.logger,
            user_agent="OBLIGE github collector/0.1",
            extra_headers=headers,
        )

    def run(self) -> int:
        ensure_directory(self.args.output_dir)
        repositories = dedupe_preserve_order(DEFAULT_REPOSITORIES + self.args.repository)
        query_expressions = dedupe_preserve_order([DEFAULT_QUERY, *self.args.query])
        self.logger.info(f"Searching {len(repositories)} repositories across {len(query_expressions)} query expressions")

        candidates = self._search_candidates(repositories, query_expressions)
        self.logger.info(f"Fetched {len(candidates)} unique GitHub issue candidates")

        case_summaries: list[dict[str, Any]] = []
        saved = 0
        for candidate in candidates:
            if saved >= self.args.max_issues:
                break
            try:
                case_payload = self._build_case(candidate)
            except Exception as exc:  # pragma: no cover - API variability
                self.logger.warn(f"Skipping {candidate['repository']}#{candidate['number']}: {exc}")
                continue
            if case_payload is None:
                continue

            owner, repo = candidate["repository"].split("/", 1)
            case_path = self.args.output_dir / f"github-{owner}-{repo}-{candidate['number']}.yaml"
            write_yaml(case_path, case_payload)
            case_summaries.append(
                {
                    "case_id": case_payload["case_id"],
                    "path": repo_relative(case_path),
                    "repository": candidate["repository"],
                    "issue_number": candidate["number"],
                    "title": case_payload["issue"]["title"],
                    "url": case_payload["issue"]["url"],
                    "labels": case_payload["issue"]["labels"],
                    "has_fix_summary": bool(case_payload["fix"].get("summary")),
                    "verifier_log_blocks": len(case_payload["verifier_log"]["blocks"]),
                    "source_snippet_count": len(case_payload["source_snippets"]),
                }
            )
            saved += 1
            self.logger.info(
                f"Saved GitHub issue case {saved}/{self.args.max_issues}: "
                f"{candidate['repository']}#{candidate['number']}"
            )

        index_payload = compact_case_index(
            source_name="github_issues",
            script_name="benchmark/collect_github_issues.py",
            output_dir=self.args.output_dir,
            cases=case_summaries,
            source_details={"repositories": repositories, "queries": query_expressions},
        )
        write_yaml(self.args.output_dir / "index.yaml", index_payload)
        self.logger.info(f"Wrote {saved} GitHub issue case files to {self.args.output_dir}")
        return 0

    def _search_candidates(self, repositories: list[str], query_expressions: list[str]) -> list[dict[str, Any]]:
        deduped: dict[tuple[str, int], dict[str, Any]] = {}
        candidate_budget = max(self.args.max_issues * 3, self.args.max_issues + 10)
        for repository in repositories:
            for expression in query_expressions:
                for page in range(1, self.args.max_pages_per_query + 1):
                    params = {
                        "q": f"repo:{repository} is:issue {expression}",
                        "per_page": min(self.args.pagesize, 100),
                        "page": page,
                        "sort": "updated",
                        "order": "desc",
                    }
                    payload, _response = self.client.get_json(f"{GITHUB_API}/search/issues", params=params)
                    items = payload.get("items", [])
                    self.logger.info(f"{repository} page {page}: {len(items)} search hits")
                    for item in items:
                        if item.get("pull_request"):
                            continue
                        key = (repository, int(item["number"]))
                        deduped.setdefault(
                            key,
                            {
                                "repository": repository,
                                "number": int(item["number"]),
                                "title": item.get("title", ""),
                                "html_url": item.get("html_url", ""),
                                "search_issue": item,
                            },
                        )
                    if len(deduped) >= candidate_budget or len(items) < min(self.args.pagesize, 100):
                        break
                if len(deduped) >= candidate_budget:
                    break
            if len(deduped) >= candidate_budget:
                break
        return sorted(
            deduped.values(),
            key=lambda item: (
                item.get("search_issue", {}).get("updated_at", ""),
                item.get("repository", ""),
                item.get("number", 0),
            ),
            reverse=True,
        )

    def _build_case(self, candidate: dict[str, Any]) -> dict[str, Any] | None:
        issue = dict(candidate.get("search_issue") or self._fetch_issue(candidate["repository"], candidate["number"]))

        issue_body = issue.get("body", "") or ""
        issue_code_blocks = extract_markdown_code_blocks(issue_body)
        verifier_logs, source_snippets = partition_code_blocks(issue_code_blocks)
        issue_text = "\n".join([issue.get("title", ""), strip_markdown(issue_body)])
        if not (contains_verifier_signal(issue_text) or verifier_logs):
            return None

        comments = self._fetch_comments(candidate["repository"], candidate["number"], issue)
        bodies = [issue_body]
        bodies.extend(comment.get("body", "") or "" for comment in comments)
        if comments:
            comment_code_blocks: list[str] = []
            for body in bodies[1:]:
                comment_code_blocks.extend(extract_markdown_code_blocks(body))
            comment_verifier_logs, comment_source_snippets = partition_code_blocks(comment_code_blocks)
            verifier_logs = dedupe_preserve_order(verifier_logs + comment_verifier_logs)
            source_snippets = dedupe_preserve_order(source_snippets + comment_source_snippets)

        combined_text = "\n".join([issue.get("title", ""), *(strip_markdown(body) for body in bodies)])
        fix_payload = self._select_fix_payload(issue, comments)
        owner, repo = candidate["repository"].split("/", 1)
        return {
            "case_id": f"github-{owner}-{repo}-{candidate['number']}",
            "source": "github_issues",
            "collected_at": utc_now(),
            "issue": {
                "repository": candidate["repository"],
                "number": candidate["number"],
                "title": issue.get("title", ""),
                "url": issue.get("html_url", ""),
                "state": issue.get("state", ""),
                "state_reason": issue.get("state_reason"),
                "labels": [label["name"] for label in issue.get("labels", [])],
                "created_at": issue.get("created_at"),
                "updated_at": issue.get("updated_at"),
                "author": issue.get("user", {}).get("login"),
            },
            "verifier_log": {
                "blocks": dedupe_preserve_order(verifier_logs),
                "combined": "\n\n".join(dedupe_preserve_order(verifier_logs)),
            },
            "source_snippets": dedupe_preserve_order(source_snippets),
            "issue_body_text": strip_markdown(issue.get("body", "") or ""),
            "fix": fix_payload,
        }

    def _fetch_issue(self, repository: str, issue_number: int) -> dict[str, Any]:
        payload, _response = self.client.get_json(f"{GITHUB_API}/repos/{repository}/issues/{issue_number}")
        return payload

    def _fetch_comments(self, repository: str, issue_number: int, issue: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        if self.comments_disabled_reason:
            return []
        if issue and int(issue.get("comments", 0) or 0) <= 0:
            return []
        comments: list[dict[str, Any]] = []
        remaining = self.args.max_comments
        page = 1
        while remaining > 0:
            page_size = min(remaining, 100)
            try:
                payload, _response = self.client.get_json(
                    f"{GITHUB_API}/repos/{repository}/issues/{issue_number}/comments",
                    params={"per_page": page_size, "page": page, "sort": "created", "direction": "asc"},
                )
            except RuntimeError as exc:
                if "Rate limit exhausted" in str(exc):
                    self.comments_disabled_reason = str(exc)
                    self.logger.warn(
                        "Disabling GitHub comment fetches for the rest of the run: "
                        f"{self.comments_disabled_reason}"
                    )
                    return comments
                raise
            if not payload:
                break
            comments.extend(payload)
            if len(payload) < page_size:
                break
            remaining -= len(payload)
            page += 1
        return comments

    def _select_fix_payload(self, issue: dict[str, Any], comments: list[dict[str, Any]]) -> dict[str, Any]:
        candidates: list[dict[str, Any]] = []
        if issue.get("body"):
            candidates.append(
                {
                    "kind": "issue_body",
                    "url": issue.get("html_url", ""),
                    "author": issue.get("user", {}).get("login"),
                    "author_association": issue.get("author_association"),
                    "body": issue.get("body", ""),
                }
            )
        for comment in comments:
            candidates.append(
                {
                    "kind": "comment",
                    "url": comment.get("html_url", ""),
                    "author": comment.get("user", {}).get("login"),
                    "author_association": comment.get("author_association"),
                    "body": comment.get("body", ""),
                }
            )

        def score(candidate: dict[str, Any]) -> tuple[int, int]:
            body_text = strip_markdown(candidate["body"])
            lower = body_text.lower()
            numeric_score = 0
            actionable_hits = sum(1 for keyword in ACTIONABLE_FIX_MARKERS if keyword in lower)
            numeric_score += min(actionable_hits, 3) * 3
            if candidate.get("author_association") in MAINTAINER_ASSOCIATIONS:
                numeric_score += 5
            if any(keyword in lower for keyword in ("because", "root cause", "for posterity", "this is because")):
                numeric_score += 1
            if "```" in candidate["body"] or "`" in candidate["body"]:
                numeric_score += 1
            if lower.count("?") >= 1 and actionable_hits == 0:
                numeric_score -= 2
            if any(marker in lower for marker in LOW_SIGNAL_MARKERS):
                numeric_score -= 3
            return numeric_score, len(body_text)

        if not candidates:
            return {}
        selected = max(candidates, key=score)
        selected_score, _selected_length = score(selected)
        if selected_score < 4:
            return {}
        selected_text = strip_markdown(selected["body"])
        return {
            "summary": summarize_fix_description(selected_text),
            "selected_comment": {
                "kind": selected["kind"],
                "url": selected["url"],
                "author": selected["author"],
                "author_association": selected.get("author_association"),
                "body_text": truncate_text(selected_text, 4000),
            },
        }


def main() -> int:
    args = parse_args()
    collector = GitHubIssuesCollector(args)
    try:
        return collector.run()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    finally:
        collector.client.close()


if __name__ == "__main__":
    raise SystemExit(main())
