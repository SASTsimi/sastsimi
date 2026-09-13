import hashlib
from pathlib import Path

import sastsimi
from sastsimi.config.package_resources import (
    builtin_package_root,
    resolve_builtin_resource,
)
from sastsimi.orchestration.production_onboarding import read_builtin_prompt
from sastsimi.prompts.loader import PromptLoader
from sastsimi.prompts.production import REQUIRED_PRODUCTION_PROMPT_ROUTES


def test_builtin_resources_resolve_from_installed_package_layout() -> None:
    package_root = Path(sastsimi.__file__).resolve().parent
    assert builtin_package_root() == package_root

    required = REQUIRED_PRODUCTION_PROMPT_ROUTES[0]
    template = read_builtin_prompt(package_root, required.template_path)
    assert template
    assert (
        PromptLoader(package_root).load_template(
            required.template_path,
            hashlib.sha256(template).hexdigest(),
        )
        == template
    )

    worker = resolve_builtin_resource(
        package_root,
        Path("src/sastsimi/static_analysis/python_ast_worker.py"),
    )
    assert worker.is_file()
    assert worker.parent.name == "static_analysis"


def test_builtin_resource_resolver_rejects_paths_outside_package() -> None:
    package_root = builtin_package_root()
    for unsafe in (Path("../secret"), Path("prompts/templates/x.md"), Path("C:/x")):
        try:
            resolve_builtin_resource(package_root, unsafe)
        except ValueError as error:
            assert str(error) == "BUILTIN_RESOURCE_PATH_DENIED"
        else:
            raise AssertionError(f"unsafe path accepted: {unsafe}")
