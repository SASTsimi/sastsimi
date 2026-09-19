"""Wire the production command from approved capability bundles."""

from pathlib import Path
from typing import cast

from sastsimi.config.package_resources import builtin_package_root
from sastsimi.config.production_profile import (
    ProductionProfileError as ProductionProfileError,
)


def builtin_resource_root() -> Path:
    """Return the installed package root that owns prompts and AST workers."""

    return builtin_package_root()


def build_production_analyze(capability_bundle_loader: object | None = None) -> object:
    """Build the real production command entrypoint; never select FakePipeline."""

    from sastsimi.composition.production_bootstrap_runtime import (
        build_production_bootstrap_assembler,
    )
    from sastsimi.composition.production_composition import (
        ConcreteProductionApplicationFactory,
    )
    from sastsimi.composition.production_filesystem_provisioner import (
        FilesystemAnalysisCapabilityProvisioner,
    )
    from sastsimi.config.production_profile import load_production_profile
    from sastsimi.orchestration.production_capabilities import (
        ProductionCapabilityBundleLoader,
        ProfileBackedProductionCapabilityResolver,
    )
    from sastsimi.orchestration.production_entrypoint import ProductionAnalyzeService
    from sastsimi.orchestration.production_onboarding import (
        OnboardedProductionCapabilityBundleLoader,
    )
    from sastsimi.runtime.system_support import SystemClock, UUIDIds

    if capability_bundle_loader is None:
        repository_root = builtin_resource_root()
        feature_assembler = build_production_bootstrap_assembler(
            repository_root=repository_root
        )
        capability_bundle_loader = OnboardedProductionCapabilityBundleLoader(
            repository_root=repository_root,
            clock=SystemClock().now,
            provision=FilesystemAnalysisCapabilityProvisioner(feature_assembler),
        )

    capability_resolver = ProfileBackedProductionCapabilityResolver(
        cast(ProductionCapabilityBundleLoader, capability_bundle_loader)
    )
    return ProductionAnalyzeService(
        ids=UUIDIds(),
        load_profile=load_production_profile,
        factory=ConcreteProductionApplicationFactory(capability_resolver),
    )
