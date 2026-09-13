"""Public safe failure shared by analysis applications and command adapters."""

import re


class ProductionAnalyzeUnavailable(RuntimeError):
    """Fail-closed production unavailability with one safe public reason code."""

    def __init__(self, reason_code: str = "PRODUCTION_ANALYZE_UNAVAILABLE") -> None:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", reason_code) is None:
            reason_code = "PRODUCTION_ANALYZE_UNAVAILABLE"
        self.reason_code = reason_code
        super().__init__(reason_code)
