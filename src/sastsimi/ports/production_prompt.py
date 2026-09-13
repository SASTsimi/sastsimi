"""Credential-free route and prepared-call values shared across workflows."""

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.llm import LLMCallSpec, LLMRole, PromptPayload
from sastsimi.contracts.refs import StoredDataRef


class ProductionRoute(Protocol):
    """Structural view of one ``ProductionProfile.llm_routes`` item."""

    role: LLMRole
    task_kind: str
    provider_profile_key: str
    model: str
    prompt_key: str


class ProductionPromptApproval(ContractModel):
    """Operator-provided exact R8 quality approval; never a credential value."""

    evaluation_prompt_ref: StoredDataRef
    quality_evaluation_ref: StoredDataRef
    provider_profile_ref: StoredDataRef


class ApprovedProductionRoute(ProductionPromptApproval):
    active_prompt_ref: StoredDataRef


@dataclass(frozen=True)
class PreparedProductionCall:
    payload: PromptPayload
    payload_ref: StoredDataRef
    call_spec: LLMCallSpec
    call_spec_ref: StoredDataRef
