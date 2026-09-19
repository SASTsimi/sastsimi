"""Build the shipped explicit ``LOCAL_EVALUATION`` command entrypoint."""

from __future__ import annotations

from typing import cast


def build_local_evaluation_analyze() -> object:
    """Return the real local-evaluation service; never select a Fake adapter."""

    from sastsimi.composition.local_evaluation_composition import (
        ConcreteLocalEvaluationApplicationFactory,
    )
    from sastsimi.composition.local_evaluation_preflight import (
        ConcreteLocalEvaluationPreflight,
    )
    from sastsimi.config.local_evaluation_profile import (
        load_local_evaluation_profile,
    )
    from sastsimi.orchestration.local_evaluation_entrypoint import (
        LocalEvaluationAnalyzeService,
        LocalEvaluationApplicationFactory,
        LocalEvaluationApplicationPreflight,
    )
    from sastsimi.runtime.system_support import UUIDIds

    return LocalEvaluationAnalyzeService(
        ids=UUIDIds(),
        load_profile=load_local_evaluation_profile,
        factory=cast(
            LocalEvaluationApplicationFactory,
            ConcreteLocalEvaluationApplicationFactory(),
        ),
        preflight=cast(
            LocalEvaluationApplicationPreflight,
            ConcreteLocalEvaluationPreflight(),
        ),
    )


__all__ = ["build_local_evaluation_analyze"]
