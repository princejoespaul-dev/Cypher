#!/usr/bin/env python3
"""Verify an exported Cypher experiment's stored manifest and result hashes."""
from __future__ import annotations

import argparse
import sys

from cypher.experiments.runner import verify_export


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("export", help="path to JSON experiment export")
    args = parser.parse_args()
    if not verify_export(args.export):
        print("REPRODUCE FAILED: manifest or result hash mismatch", file=sys.stderr)
        return 1
    print("REPRODUCE OK: manifest and results hashes verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
