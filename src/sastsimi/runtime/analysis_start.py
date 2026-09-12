"""Validate the explicit program before any analysis or work can be created."""

import re
from typing import Protocol

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.ports.program_resolver import ProgramResolverPort


class RepositoryInputNormalizer(Protocol):
    def __call__(self, submitted: str) -> str: ...


class AnalysisStartService:
    def __init__(
        self,
        programs: ProgramResolverPort,
        normalize_repository: RepositoryInputNormalizer,
    ) -> None:
        self.programs = programs
        self._normalize_repository = normalize_repository

    def validate(
        self,
        *,
        repository_ref: str,
        requested_git_ref: str,
        program_id: str,
        purpose: str,
    ) -> AnalysisStartRequest:
        if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", requested_git_ref):
            raise ValueError("INPUT_ERROR: commit must be an exact object ID")
        repository_ref = self._normalize_repository(repository_ref)
        request = AnalysisStartRequest.model_validate_json(
            canonical_bytes(
                dict(
                    repository_ref=repository_ref,
                    requested_git_ref=requested_git_ref.lower(),
                    program_id=program_id,
                    purpose=purpose,
                )
            )
        )
        if self.programs.resolve(request.program_id) != (request.program_id,):
            raise ValueError(
                "INPUT_ERROR: program must resolve to exactly one usable entry"
            )
        return request
