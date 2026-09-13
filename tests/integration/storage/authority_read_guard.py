"""Fail immediately if a fresh-process authority reader activates side effects."""

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from unittest.mock import patch


@contextmanager
def readonly_authority_guard() -> Iterator[None]:
    targets = (
        "sastsimi.runtime.system_support.UUIDIds.new",
        "sastsimi.storage.database.Database.write",
        "sastsimi.orchestration.production_operator_profiles."
        "ProductionOperatorProfiles.__init__",
        "sastsimi.providers.openai_composition.EnvironmentSecretResolver.resolve",
        "sastsimi.composition.production_provider_builder."
        "build_production_adapter_feature",
        "sastsimi.runtime.recovery_service.RecoveryService.recover",
        "sastsimi.storage.recovery_service.RecoveryService.recover",
        "sastsimi.runtime.worker_pool.WorkerPool.drain",
        "socket.socket.connect",
        "subprocess.Popen",
        "os.system",
    )
    with ExitStack() as stack:
        for target in targets:
            stack.enter_context(patch(target, side_effect=AssertionError(target)))
        yield
