"""Export and sanity-check the main FastAPI OpenAPI contract."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cypher.api.app import app

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "docs" / "api" / "openapi.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if committed OpenAPI differs")
    args = parser.parse_args()
    document = app.openapi()
    if document.get("openapi") is None or not isinstance(document.get("paths"), dict):
        raise SystemExit("OpenAPI document is incomplete")
    content = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not DEST.exists() or DEST.read_text(encoding="utf-8") != content:
            raise SystemExit("docs/api/openapi.json is stale; run `make openapi`")
    else:
        DEST.parent.mkdir(parents=True, exist_ok=True)
        DEST.write_text(content, encoding="utf-8")
    print(f"OpenAPI valid: {len(document['paths'])} paths, {sum(len(methods) for methods in document['paths'].values())} operations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
