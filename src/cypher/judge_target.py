"""Container entry point for one isolated judge-demo API variant."""
from __future__ import annotations

import os

from cypher.judge_demo import _target_app

app = _target_app(fixed=os.environ.get("DEMO_FIXED", "false").strip().lower() == "true")
