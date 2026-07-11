"""Evaluate a Vyper Guard JSON report against a team policy."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from guardian.team_policy import append_history, evaluate_team_policy, render_pr_markdown


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--result", type=Path, default=Path("vyper-guard-policy.json"))
    parser.add_argument("--markdown", type=Path, default=Path("vyper-guard-pr.md"))
    parser.add_argument("--history", type=Path)
    args = parser.parse_args()

    result = evaluate_team_policy(args.report, args.policy)
    args.result.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    args.markdown.write_text(render_pr_markdown(result), encoding="utf-8")
    if args.history:
        append_history(
            result,
            args.history,
            {
                "repository": os.getenv("GITHUB_REPOSITORY", "local"),
                "commit": os.getenv("GITHUB_SHA", "local"),
                "run_id": os.getenv("GITHUB_RUN_ID", "local"),
            },
        )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
