"""Closed, non-sensitive reason codes shared by surface proof consumers."""

SURFACE_REASON_CODE_PREFIX = "REASON_CODE_"
SURFACE_REASON_CODES = frozenset(
    {
        "CHILD_PENDING",
        "CHILD_ERROR",
        "CHILD_HOLD",
        "CHILD_STALE",
        "SURFACE_PART_PENDING",
        "SURFACE_EVIDENCE_INSUFFICIENT",
        "SURFACE_SOURCE_UNAVAILABLE",
        "CONNECTED_ROLE_PROOF_MISSING",
        "PRIOR_SURFACE_UNCOVERED",
        "OTHER",
    }
)
