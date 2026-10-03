"""Compatibility re-export for the shared shell PoC validation contract."""

from __future__ import annotations

from sastsimi.contracts.poc_candidate import PoCCandidateRejected, validate_candidate

__all__ = ["PoCCandidateRejected", "validate_candidate"]
