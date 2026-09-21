"""One official-client LOCAL_EVALUATION route, independent of which client it is.

The prompt graph needs the same four facts from every subscription client: the
experimental profile that was pinned, the client boundary it was pinned to, the
locally supported revision the live probe produced, and a way to rebuild that
validated binding when a resumed analysis restores the persisted route.  This
module is the only place those differences are named, so the prompt graph and the
preflight stay provider-neutral.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sastsimi.composition.local_claude_binding import LocalClaudeBindingRecords
from sastsimi.composition.local_codex_binding import LocalCodexBindingRecords
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.providers.claude_subscription import ApprovedClaudeExecutionBinding
from sastsimi.providers.codex_subscription import ApprovedCodexExecutionBinding
from sastsimi.providers.local_claude_validation import (
    LocalClaudeValidationResult,
    LocalValidatedClaudeExecutionBinding,
)
from sastsimi.providers.local_codex_validation import (
    LocalCodexValidationResult,
    LocalValidatedCodexExecutionBinding,
)

type LocalValidatedBinding = (
    LocalValidatedCodexExecutionBinding | LocalValidatedClaudeExecutionBinding
)
type LocalBindingRecords = LocalCodexBindingRecords | LocalClaudeBindingRecords
type LocalValidationResult = LocalCodexValidationResult | LocalClaudeValidationResult


@dataclass(frozen=True, slots=True)
class LocalSubscriptionRoute:
    """The provider-neutral view of one probed official-client route."""

    experimental: ProviderProfile
    client: ClientExecutionProfile
    validation_evidence: ProviderValidationEvidence
    supported: ProviderProfile
    evidence_ref: StoredDataRef
    binding: LocalValidatedBinding
    # Names the official client in every configuration record this route
    # publishes, so two clients never collide on one configuration key.
    configuration_key: str
    # Rebuilds the validated binding from records restored out of storage.  Only
    # the client knows how to reconstruct its own pinned execution boundary.
    rebind: Callable[
        [ProviderProfile, ClientExecutionProfile, ProviderProfile],
        LocalValidatedBinding,
    ]


def codex_route(
    *,
    records: LocalCodexBindingRecords,
    validation: LocalCodexValidationResult,
) -> LocalSubscriptionRoute:
    """Present a probed Codex route without changing how Codex is built."""

    pinned = records.binding

    def rebind(
        experimental: ProviderProfile,
        client: ClientExecutionProfile,
        supported: ProviderProfile,
    ) -> LocalValidatedBinding:
        return LocalValidatedCodexExecutionBinding(
            experimental_binding=ApprovedCodexExecutionBinding(
                provider_profile=experimental,
                client_execution_profile=client,
                executable=pinned.executable,
                codex_home=pinned.codex_home,
                runtime_environment=pinned.runtime_environment,
                provider_validation_evidence=None,
            ),
            provider_profile=supported,
            local_evidence_ref=validation.evidence_ref,
        )

    return LocalSubscriptionRoute(
        experimental=records.provider,
        client=records.client,
        validation_evidence=records.validation,
        supported=validation.provider,
        evidence_ref=validation.evidence_ref,
        binding=validation.binding,
        configuration_key="local-evaluation-codex-v1",
        rebind=rebind,
    )


def claude_route(
    *,
    records: LocalClaudeBindingRecords,
    validation: LocalClaudeValidationResult,
) -> LocalSubscriptionRoute:
    """Present a probed Claude Code route through the same neutral view."""

    pinned = records.binding

    def rebind(
        experimental: ProviderProfile,
        client: ClientExecutionProfile,
        supported: ProviderProfile,
    ) -> LocalValidatedBinding:
        return LocalValidatedClaudeExecutionBinding(
            experimental_binding=ApprovedClaudeExecutionBinding(
                provider_profile=experimental,
                client_execution_profile=client,
                executable=pinned.executable,
                claude_config_dir=pinned.claude_config_dir,
                runtime_environment=pinned.runtime_environment,
                provider_validation_evidence=None,
            ),
            provider_profile=supported,
            local_evidence_ref=validation.evidence_ref,
        )

    return LocalSubscriptionRoute(
        experimental=records.provider,
        client=records.client,
        validation_evidence=records.validation,
        supported=validation.provider,
        evidence_ref=validation.evidence_ref,
        binding=validation.binding,
        configuration_key="local-evaluation-claude-v1",
        rebind=rebind,
    )


def restored_result(
    route: LocalSubscriptionRoute, binding: LocalValidatedBinding
) -> LocalValidationResult:
    """Pair a restored binding with its supported revision and probe receipt."""

    if isinstance(binding, LocalValidatedClaudeExecutionBinding):
        return LocalClaudeValidationResult(
            provider=route.supported,
            evidence_ref=route.evidence_ref,
            binding=binding,
        )
    return LocalCodexValidationResult(
        provider=route.supported,
        evidence_ref=route.evidence_ref,
        binding=binding,
    )


__all__ = [
    "LocalBindingRecords",
    "LocalSubscriptionRoute",
    "LocalValidatedBinding",
    "LocalValidationResult",
    "claude_route",
    "codex_route",
    "restored_result",
]
