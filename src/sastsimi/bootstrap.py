"""Public facade for the concrete application composition root."""

from sastsimi.composition.codeql_operator import (
    inspect_database as inspect_database,
)
from sastsimi.composition.codeql_operator import (
    provision_database as provision_database,
)
from sastsimi.composition.codeql_operator import (
    register_database as register_database,
)
from sastsimi.composition.codeql_operator import (
    resolve_operator_executable as resolve_operator_executable,
)
from sastsimi.composition.local_evaluation_entrypoint import (
    build_local_evaluation_analyze as build_local_evaluation_analyze,
)
from sastsimi.composition.production_control import (
    ProductionResumeUnavailable as ProductionResumeUnavailable,
)
from sastsimi.composition.production_control import (
    inspect_production_resume as inspect_production_resume,
)
from sastsimi.composition.production_control import (
    request_production_cancel as request_production_cancel,
)
from sastsimi.composition.production_entrypoint import (
    ProductionProfileError as ProductionProfileError,
)
from sastsimi.composition.production_entrypoint import (
    build_production_analyze as build_production_analyze,
)
from sastsimi.composition.production_entrypoint import (
    builtin_resource_root as builtin_resource_root,
)
from sastsimi.composition.runtime import ConfigError as ConfigError
from sastsimi.composition.runtime import (
    CurrentProcessResolver as CurrentProcessResolver,
)
from sastsimi.composition.runtime import DynamicExecutor as DynamicExecutor
from sastsimi.composition.runtime import MigrationRequired as MigrationRequired
from sastsimi.composition.runtime import OwnedResourceRecovery as OwnedResourceRecovery
from sastsimi.composition.runtime import RealStaticSlice as RealStaticSlice
from sastsimi.composition.runtime import T10Services as T10Services
from sastsimi.composition.runtime import T11Services as T11Services
from sastsimi.composition.runtime import T12Services as T12Services
from sastsimi.composition.runtime import (
    T13ProductionInstallation as T13ProductionInstallation,
)
from sastsimi.composition.runtime import T13Services as T13Services
from sastsimi.composition.runtime import (
    build_and_install_t13_application as build_and_install_t13_application,
)
from sastsimi.composition.runtime import build_config as build_config
from sastsimi.composition.runtime import (
    build_diagnostic_logger as build_diagnostic_logger,
)
from sastsimi.composition.runtime import build_fake_pipeline as build_fake_pipeline
from sastsimi.composition.runtime import (
    build_production_query as build_production_query,
)
from sastsimi.composition.runtime import (
    build_real_static_slice as build_real_static_slice,
)
from sastsimi.composition.runtime import (
    build_report_markdown_service as build_report_markdown_service,
)
from sastsimi.composition.runtime import build_runtime as build_runtime
from sastsimi.composition.runtime import build_t10_services as build_t10_services
from sastsimi.composition.runtime import build_t11_services as build_t11_services
from sastsimi.composition.runtime import build_t12_services as build_t12_services
from sastsimi.composition.runtime import build_t13_services as build_t13_services
from sastsimi.composition.runtime import database_command as database_command
from sastsimi.composition.runtime import diagnostic_event as diagnostic_event
from sastsimi.composition.runtime import install_t13_services as install_t13_services
from sastsimi.composition.runtime import load_fake_progress as load_fake_progress
from sastsimi.composition.runtime import upgrade_database as upgrade_database

# Compatibility alias for existing integration callers. New code should use
# ``build_real_static_slice`` from this facade.
_build_real_static_slice = build_real_static_slice
