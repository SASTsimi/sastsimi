"""Primitive admission and chaining composition boundary."""

from .fake_runtime import no_match_result
from .publication import RuntimeChainingResultPublisher
from .service import (
    ChainingCallResolver,
    ChainingWorkflowOutcome,
    ChainingWorkflowService,
    chaining_input_hash,
)
from .work_handlers import (
    ChainingWorkHandler,
    HypothesisProposalHandler,
    PrimitiveUpdateHandler,
)

__all__ = [
    "ChainingWorkflowOutcome",
    "ChainingWorkflowService",
    "ChainingCallResolver",
    "ChainingWorkHandler",
    "HypothesisProposalHandler",
    "PrimitiveUpdateHandler",
    "RuntimeChainingResultPublisher",
    "chaining_input_hash",
    "no_match_result",
]
