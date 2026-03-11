#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

from collector_utils import (
    HttpClient,
    ProgressLogger,
    compact_case_index,
    contains_ebpf_context,
    contains_failure_language,
    contains_verifier_signal,
    dedupe_preserve_order,
    ensure_directory,
    extract_html_code_blocks,
    partition_code_blocks,
    repo_relative,
    stackexchange_backoff_seconds,
    strip_html,
    summarize_fix_description,
    truncate_text,
    utc_now,
    write_yaml,
)


STACKEXCHANGE_API = "https://api.stackexchange.com/2.3"
DEFAULT_QUERIES = [
    "ebpf verifier",
    "bpf verifier",
    "xdp verifier",
    "ebpf invalid mem access",
    "ebpf R0 invalid",
    "ebpf back-edge",
    "ebpf helper call",
    "\"BPF program is too large\" ebpf",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect eBPF verifier failure cases from Stack Overflow.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("benchmark/cases/stackoverflow"),
        help="Directory where YAML case files and index.yaml are written.",
    )
    parser.add_argument(
        "--max-questions",
        type=int,
        default=50,
        help="Maximum number of relevant questions to save.",
    )
    parser.add_argument(
        "--pagesize",
        type=int,
        default=30,
        help="Stack Exchange page size (max 100).",
    )
    parser.add_argument(
        "--max-pages-per-query",
        type=int,
        default=2,
        help="Maximum pages to fetch for each query seed.",
    )
    parser.add_argument(
        "--query",
        action="append",
        default=[],
        help="Additional search query. May be passed multiple times.",
    )
    parser.add_argument(
        "--site",
        default="stackoverflow",
        help="Stack Exchange site name. Defaults to stackoverflow.",
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="Optional Stack Exchange API key to increase quota.",
    )
    parser.add_argument(
        "--min-interval-seconds",
        type=float,
        default=0.5,
        help="Minimum delay between API requests.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce progress output.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Accepted for CLI compatibility; verbose progress output is already the default.",
    )
    return parser.parse_args()


class StackOverflowCollector:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = ProgressLogger(quiet=args.quiet)
        self.client = HttpClient(
            min_interval_seconds=args.min_interval_seconds,
            logger=self.logger,
            user_agent="OBLIGE stackoverflow collector/0.1",
        )

    def run(self) -> int:
        ensure_directory(self.args.output_dir)
        queries = dedupe_preserve_order(DEFAULT_QUERIES + self.args.query)
        self.logger.info(f"Searching Stack Overflow with {len(queries)} query seeds")
        candidates = self._search_candidates(queries)
        self.logger.info(f"Fetched {len(candidates)} unique candidate questions")

        case_summaries: list[dict[str, Any]] = []
        saved = 0
        for question in candidates:
            if saved >= self.args.max_questions:
                break
            try:
                case_payload = self._build_case(question)
            except Exception as exc:  # pragma: no cover - network/data variability
                self.logger.warn(f"Skipping question {question['question_id']}: {exc}")
                continue
            if case_payload is None:
                continue

            case_path = self.args.output_dir / f"stackoverflow-{question['question_id']}.yaml"
            write_yaml(case_path, case_payload)
            case_summaries.append(
                {
                    "case_id": case_payload["case_id"],
                    "path": repo_relative(case_path),
                    "question_id": question["question_id"],
                    "title": question["title"],
                    "url": question["link"],
                    "tags": question.get("tags", []),
                    "has_selected_answer": bool(case_payload.get("selected_answer", {}).get("answer_id")),
                    "verifier_log_blocks": len(case_payload["verifier_log"]["blocks"]),
                    "source_snippet_count": len(case_payload["source_snippets"]),
                }
            )
            saved += 1
            self.logger.info(f"Saved Stack Overflow case {saved}/{self.args.max_questions}: {question['title']}")

        index_payload = compact_case_index(
            source_name="stackoverflow",
            script_name="benchmark/collect_stackoverflow.py",
            output_dir=self.args.output_dir,
            cases=case_summaries,
            source_details={"site": self.args.site, "queries": queries},
        )
        write_yaml(self.args.output_dir / "index.yaml", index_payload)
        self.logger.info(f"Wrote {saved} Stack Overflow case files to {self.args.output_dir}")
        return 0

    def _search_candidates(self, queries: list[str]) -> list[dict[str, Any]]:
        deduped: dict[int, dict[str, Any]] = {}
        candidate_budget = max(self.args.max_questions * 4, self.args.max_questions + 10)
        for query in queries:
            for page in range(1, self.args.max_pages_per_query + 1):
                params = {
                    "site": self.args.site,
                    "page": page,
                    "pagesize": min(self.args.pagesize, 100),
                    "order": "desc",
                    "sort": "relevance",
                    "q": query,
                    "filter": "withbody",
                }
                if self.args.api_key:
                    params["key"] = self.args.api_key
                payload, _response = self.client.get_json(f"{STACKEXCHANGE_API}/search/advanced", params=params)
                items = payload.get("items", [])
                self.logger.info(f"Query {query!r} page {page}: {len(items)} results")
                for item in items:
                    question_id = item.get("question_id")
                    if not question_id or question_id in deduped:
                        continue
                    deduped[question_id] = item
                backoff_seconds = stackexchange_backoff_seconds(payload)
                if backoff_seconds:
                    self.logger.warn(f"Stack Exchange requested backoff; sleeping for {backoff_seconds}s")
                    time.sleep(backoff_seconds)
                if len(deduped) >= candidate_budget or not payload.get("has_more"):
                    break
            if len(deduped) >= candidate_budget:
                break
        return sorted(
            deduped.values(),
            key=lambda item: (
                -int(item.get("score", 0)),
                -int(item.get("answer_count", 0)),
                item.get("creation_date", 0),
            ),
        )

    def _build_case(self, question: dict[str, Any]) -> dict[str, Any] | None:
        question_body_html = question.get("body", "") or ""
        question_text = strip_html(question_body_html)
        tags = question.get("tags", []) or []
        code_blocks = extract_html_code_blocks(question_body_html)
        verifier_logs, source_snippets = partition_code_blocks(code_blocks)
        signal_text = "\n".join([question.get("title", ""), question_text, *code_blocks])
        if not contains_ebpf_context(signal_text, tags) or not (contains_verifier_signal(signal_text) or verifier_logs):
            return None

        answers = self._fetch_answers(question["question_id"])
        selected_answer = self._select_answer(question, answers)
        if selected_answer:
            answer_blocks = extract_html_code_blocks(selected_answer.get("body", "") or "")
            answer_logs, answer_sources = partition_code_blocks(answer_blocks)
            verifier_logs = dedupe_preserve_order(verifier_logs + answer_logs)
            if not source_snippets:
                source_snippets = answer_sources

        # Skip explanatory discussion threads that mention verifier concepts but do not
        # present a concrete failure report or include a verifier log snippet.
        if not verifier_logs and not contains_failure_language("\n".join([question.get("title", ""), question_text])):
            return None

        case_id = f"stackoverflow-{question['question_id']}"
        combined_log = "\n\n".join(verifier_logs)
        selected_answer_payload: dict[str, Any] = {}
        if selected_answer:
            selected_answer_text = strip_html(selected_answer.get("body", "") or "")
            selected_answer_payload = {
                "answer_id": selected_answer.get("answer_id"),
                "url": f"{question['link']}#{selected_answer.get('answer_id')}",
                "is_accepted": bool(selected_answer.get("is_accepted")),
                "score": selected_answer.get("score", 0),
                "body_text": selected_answer_text,
                "fix_description": summarize_fix_description(selected_answer_text),
            }

        return {
            "case_id": case_id,
            "source": "stackoverflow",
            "collected_at": utc_now(),
            "question": {
                "question_id": question["question_id"],
                "title": question.get("title", ""),
                "url": question.get("link", ""),
                "tags": tags,
                "score": question.get("score", 0),
                "answer_count": question.get("answer_count", 0),
                "is_answered": bool(question.get("is_answered")),
            },
            "verifier_log": {
                "blocks": verifier_logs,
                "combined": combined_log,
            },
            "source_snippets": source_snippets,
            "question_body_text": question_text,
            "selected_answer": selected_answer_payload,
        }

    def _fetch_answers(self, question_id: int) -> list[dict[str, Any]]:
        params = {
            "site": self.args.site,
            "pagesize": 20,
            "order": "desc",
            "sort": "votes",
            "filter": "withbody",
        }
        if self.args.api_key:
            params["key"] = self.args.api_key
        payload, _response = self.client.get_json(f"{STACKEXCHANGE_API}/questions/{question_id}/answers", params=params)
        backoff_seconds = stackexchange_backoff_seconds(payload)
        if backoff_seconds:
            self.logger.warn(f"Stack Exchange requested backoff; sleeping for {backoff_seconds}s")
            time.sleep(backoff_seconds)
        return payload.get("items", [])

    def _select_answer(self, question: dict[str, Any], answers: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not answers:
            return None
        accepted_answer_id = question.get("accepted_answer_id")
        if accepted_answer_id:
            for answer in answers:
                if answer.get("answer_id") == accepted_answer_id:
                    return answer
        return max(answers, key=lambda answer: int(answer.get("score", 0)))


def main() -> int:
    args = parse_args()
    collector = StackOverflowCollector(args)
    try:
        return collector.run()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    finally:
        collector.client.close()


if __name__ == "__main__":
    raise SystemExit(main())
