"""Validate provider usage before it enters a budget or canonical artifact."""

from __future__ import annotations

import math


def token_count(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def cost_minor_units(value: object) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        amount = float(value)
    except OverflowError:
        return None
    return amount if math.isfinite(amount) and amount >= 0 else None


def canonical_cost(value: float | None) -> str | None:
    # Canonical JSON intentionally rejects floating-point values.
    return str(value) if value is not None else None
