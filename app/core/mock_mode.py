from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

SCENARIOS = {
    "easy",
    "capture-partial",
    "capture-valid",
    "dictionary-exhausted",
    "recovered",
    "gpu-missing",
    "adapter-missing",
}


def enabled() -> bool:
    return os.environ.get("WIFI_LAB_MOCK") == "1"


@lru_cache(maxsize=8)
def scenario(name: str | None = None) -> dict[str, Any]:
    selected = name or os.environ.get("WIFI_LAB_MOCK_SCENARIO", "easy")
    if selected not in SCENARIOS:
        raise ValueError(f"Unknown mock scenario: {selected}")
    path = Path(__file__).parents[2] / "fixtures" / "mock_scenarios.json"
    scenarios = json.loads(path.read_text(encoding="utf-8"))
    item = dict(scenarios[selected])
    if parent := item.pop("extends", None):
        return {**scenario(parent), **item}
    return item
