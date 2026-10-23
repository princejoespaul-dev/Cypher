"""Export the standalone Phase 5 OpenAPI fragment to docs/api/phase5-openapi.json."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi import FastAPI  # noqa: E402

from cypher.api.phase5_router import install_phase5_exception_handler, router  # noqa: E402


app = FastAPI(
    title="CYPHER Phase 5 API fragment",
    version="phase5-overlay-0.1.0",
    description="Findings, fix verification, regression recurrence, and append-only re-adjudication endpoints.",
)
app.include_router(router)
install_phase5_exception_handler(app)

out = ROOT / "docs" / "api" / "phase5-openapi.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"Wrote {out.relative_to(ROOT)}")
