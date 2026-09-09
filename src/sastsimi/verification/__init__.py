"""Verification composition boundary; contracts and trusted runtime own mutation."""

from .fake_assembly import (
    FakeVerificationAssembly,
    build_initial_assessment,
    build_verification_result,
)
from .fake_child_registration import register_verification_children

__all__ = [
    "FakeVerificationAssembly",
    "build_initial_assessment",
    "build_verification_result",
    "register_verification_children",
]
