from __future__ import annotations

import argparse
from pathlib import Path

from guardian.verification_bundle import generate_verification_bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = generate_verification_bundle(args.report, args.output)
    print(f"generated {len(manifest['candidates'])} verification candidate(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
