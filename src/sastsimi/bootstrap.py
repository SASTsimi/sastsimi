"""The composition root for configuration, logging and injected local runtime."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from sastsimi.config.loader import ConfigError as ConfigError
from sastsimi.config.loader import load_config
from sastsimi.config.models import AppConfig
from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.logging import SafeJsonHandler, safe_event
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.trusted_evidence import TrustedEvidencePort
from sastsimi.runtime.services import RuntimeServices
from sastsimi.storage.schema_version import MigrationRequired as MigrationRequired

if TYPE_CHECKING:
    from sastsimi.contracts.evaluation import AnalysisRunResult
    from sastsimi.contracts.reporting import ReportDraft
    from sastsimi.orchestration.fake_pipeline import FakePipeline


def build_config(
    config_path: Path | None, overrides: Mapping[str, object]
) -> AppConfig:
    return load_config(config_path=config_path, cli=overrides)


def build_diagnostic_logger(stream: TextIO, level: str) -> logging.Logger:
    logger = logging.Logger("sastsimi", level=level)
    handler = SafeJsonHandler(stream)
    logger.addHandler(handler)
    return logger


# Public safe event factory for interface diagnostics.
diagnostic_event = safe_event


def upgrade_database(data_dir: Path, revision: str = "head") -> None:
    from sastsimi.storage.database import Database
    from sastsimi.storage.migrations import upgrade

    upgrade(Database(RuntimePaths(data_dir).database), revision)


def database_command(data_dir: Path, command: str, revision: str | None) -> str:
    from sastsimi.storage.database import Database
    from sastsimi.storage.migrations import current, downgrade, upgrade

    database = Database(RuntimePaths(data_dir).database)
    if command == "current":
        return current(database)
    if command == "upgrade":
        upgrade(database, revision or "head")
    else:
        downgrade(database, revision or "base")
    return revision or "head"


def build_fake_pipeline(data_dir: Path) -> FakePipeline:
    """Compose the deterministic local fake vertical slice."""
    from sastsimi.orchestration.fake_pipeline import FakePipeline

    result, reports = _load_fake_outputs(data_dir)
    return FakePipeline(
        data_dir,
        build_runtime,
        upgrade_database,
        persisted_result=result,
        persisted_reports=reports,
    )


def _load_fake_outputs(
    data_dir: Path,
) -> tuple[AnalysisRunResult | None, tuple[ReportDraft, ...]]:
    from sastsimi.contracts.evaluation import AnalysisRunResult
    from sastsimi.contracts.reporting import ReportDraft
    from sastsimi.storage.database import Database
    from sastsimi.storage.queries import RuntimeQueries
    from sastsimi.storage.repositories import SQLiteRecordStore

    path = RuntimePaths(data_dir).database
    if not path.exists():
        return None, ()
    database = Database(path)
    database.check_ready()
    queries = RuntimeQueries(SQLiteRecordStore(database))
    results = tuple(
        item
        for item in queries.published_records("fake-analysis")
        if isinstance(item, AnalysisRunResult)
    )
    reports = tuple(
        item
        for item in queries.current_records("fake-analysis", "report_draft")
        if isinstance(item, ReportDraft)
    )
    return (results[-1] if results else None), reports


def build_runtime(
    data_dir: Path,
    workspace_id: WorkspaceId | None,
    commit_id: CommitId | None,
    clock: Clock,
    ids: IdGenerator,
    recovery_identity_ref: BudgetScopeRef | None = None,
    evidence: TrustedEvidencePort | None = None,
    context_service_identity_ref: BudgetScopeRef | None = None,
    finding_service_identity_ref: StoredDataRef | None = None,
    analysis_finalization_identity_ref: StoredDataRef | None = None,
) -> RuntimeServices:
    from sastsimi.runtime.action_validator import RuntimeValidator
    from sastsimi.runtime.analysis_finalization import AnalysisFinalizationService
    from sastsimi.runtime.attempt_service import AttemptService
    from sastsimi.runtime.budget_registry import BudgetProfileRegistry
    from sastsimi.runtime.budget_service import BudgetService
    from sastsimi.runtime.configuration_registry import ConfigurationRegistry
    from sastsimi.runtime.context_binding import ContextBindingService
    from sastsimi.runtime.dynamic_registration import DynamicRegistrationService
    from sastsimi.runtime.external_call_service import ExternalCallService
    from sastsimi.runtime.intermediate_publication import IntermediatePublicationService
    from sastsimi.runtime.queries import RuntimeQueries
    from sastsimi.runtime.recovery_service import RecoveryService
    from sastsimi.runtime.transition_service import TransitionService
    from sastsimi.runtime.verification_registration import (
        VerificationRegistrationService,
    )
    from sastsimi.runtime.work_service import WorkService
    from sastsimi.storage.action_validator import RuntimeValidator as SQLiteValidator
    from sastsimi.storage.analysis_finalization import (
        AnalysisFinalizationService as SQLiteAnalysisFinalization,
    )
    from sastsimi.storage.artifact_store import LocalArtifactStore
    from sastsimi.storage.attempt_service import AttemptService as SQLiteAttempts
    from sastsimi.storage.budget_registry import BudgetProfileRegistry as SQLiteRegistry
    from sastsimi.storage.budget_service import BudgetService as SQLiteBudget
    from sastsimi.storage.configuration_registry import (
        ConfigurationRegistry as SQLiteConfigurationRegistry,
    )
    from sastsimi.storage.context_binding import ContextBindingService as SQLiteContext
    from sastsimi.storage.database import Database
    from sastsimi.storage.dynamic_registration import (
        DynamicRegistrationService as SQLiteDynamicRegistration,
    )
    from sastsimi.storage.intermediate_publication import (
        IntermediatePublicationService as SQLiteIntermediates,
    )
    from sastsimi.storage.queries import RuntimeQueries as SQLiteQueries
    from sastsimi.storage.recovery_service import RecoveryService as SQLiteRecovery
    from sastsimi.storage.repositories import SQLiteRecordStore
    from sastsimi.storage.transition_service import (
        TransitionService as SQLiteTransitions,
    )
    from sastsimi.storage.unit_of_work import SQLiteUnitOfWork
    from sastsimi.storage.verification_registration import (
        VerificationRegistrationService as SQLiteVerificationRegistration,
    )
    from sastsimi.storage.work_service import WorkService as SQLiteWorks

    paths = RuntimePaths(data_dir)
    database = Database(paths.database)
    database.check_ready()
    records = SQLiteRecordStore(database, evidence, finding_service_identity_ref)
    artifacts = LocalArtifactStore(paths.artifacts, workspace_id, commit_id)
    registry = SQLiteRegistry(records, clock, ids)
    budget = SQLiteBudget(records, registry, clock, ids)
    authorization = SQLiteValidator(records, budget, clock, ids)
    works = SQLiteWorks(records, authorization, clock, ids)
    transitions = SQLiteTransitions(works, artifacts)
    unit = SQLiteUnitOfWork(records, artifacts, transitions)
    recovery = RecoveryService(SQLiteRecovery(transitions, recovery_identity_ref))
    recovery.recover()
    validator = RuntimeValidator(authorization)
    return RuntimeServices(
        WorkService(works),
        AttemptService(SQLiteAttempts(works)),
        validator,
        BudgetProfileRegistry(registry),
        BudgetService(budget),
        TransitionService(records),
        ExternalCallService(validator),
        recovery,
        unit,
        IntermediatePublicationService(SQLiteIntermediates(transitions)),
        ContextBindingService(SQLiteContext(transitions, context_service_identity_ref)),
        VerificationRegistrationService(SQLiteVerificationRegistration(transitions)),
        RuntimeQueries(SQLiteQueries(records)),
        DynamicRegistrationService(SQLiteDynamicRegistration(transitions)),
        ConfigurationRegistry(SQLiteConfigurationRegistry(records)),
        AnalysisFinalizationService(
            SQLiteAnalysisFinalization(
                records, clock, ids, analysis_finalization_identity_ref
            )
        ),
    )
