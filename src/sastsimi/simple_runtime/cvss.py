"""CVSS v3.1 base score from the metrics the CWE Labeling Agent chose.

The model picks each metric and says why; the arithmetic is done here, by the
specification's own formulas, because a hand-computed score is easy to get
wrong - one saleor draft put Scope Changed C:L/I:L at 7.1 when it is 6.4.
"""

from __future__ import annotations

import math
from collections.abc import Mapping

METRICS: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("H", "L", "N"),
    "I": ("H", "L", "N"),
    "A": ("H", "L", "N"),
}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def vector(metrics: Mapping[str, str]) -> str:
    return "CVSS:3.1/" + "/".join(f"{name}:{metrics[name]}" for name in METRICS)


def base_score(metrics: Mapping[str, str]) -> float:
    changed = metrics["S"] == "C"
    iss = 1 - (
        (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    )
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = (
        8.22
        * _AV[metrics["AV"]]
        * _AC[metrics["AC"]]
        * _PR["C" if changed else "U"][metrics["PR"]]
        * _UI[metrics["UI"]]
    )
    total = impact + exploitability
    return _roundup(min(1.08 * total if changed else total, 10))


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def _roundup(value: float) -> float:
    # The specification's Roundup, which avoids float error such as 4.000001.
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000
    return (math.floor(scaled / 10000) + 1) / 10


__all__ = ["METRICS", "base_score", "severity", "vector"]
