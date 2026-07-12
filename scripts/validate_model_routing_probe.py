#!/usr/bin/env python3
"""Validate the checked-in Hermes routing-probe result manifest."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "website/static/evals/model-routing-probe-2026-07-11.json"
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    methodology = data["methodology"]
    assert methodology["exact_prompt"]
    assert methodology["regeneration_command_template"]
    assert methodology["validation_command"]
    expected = methodology["expected"]
    assert expected == {
        "classification": "low_risk_read",
        "net_total": 7,
        "active_invoice_ids": ["B"],
        "plan_length": 3,
        "fix": "active = [u for u in users if u.enabled and not u.deleted]",
    }
    results = data["results"]
    assert results
    required = {
        "model",
        "provider",
        "effort",
        "elapsed_seconds",
        "substance_correct",
        "strict_json",
    }
    for result in results:
        assert required <= result.keys(), result
        assert result["elapsed_seconds"] > 0
    print(f"validated {len(results)} routing-probe observations in {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())