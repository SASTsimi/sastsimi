"""Verification composition boundary; contracts and trusted runtime own mutation."""

from .completion import VerificationCompletion, VerificationCompletionCoordinator
from .debate_service import AuthorizedLLMCall, DebateResult, DebateService
from .fake_assembly import (
    FakeVerificationAssembly,
    build_initial_assessment,
    build_verification_result,
)
from .fake_child_registration import register_verification_children
from .revision_workflow import RevisionWorkflow
from .service import VerificationService
from .verdict_router import VerdictRoute, VerdictRouter

__all__ = [
    "FakeVerificationAssembly",
    "build_initial_assessment",
    "build_verification_result",
    "register_verification_children",
    "AuthorizedLLMCall",
    "DebateResult",
    "DebateService",
    "VerificationCompletion",
    "VerificationCompletionCoordinator",
    "RevisionWorkflow",
    "VerificationService",
    "VerdictRoute",
    "VerdictRouter",
]
