from __future__ import annotations

from pathlib import Path

from sastsimi.simple_runtime.facts import extract_flows

# romm's own shape: a decorator factory that takes the actual route
# registrar (`router.get`) as its own first positional argument, rather
# than being named after the HTTP verb itself. The verb and router both
# live one level down, on that argument - 263 of romm's 279 route
# decorators used this exact pattern, and all of them were invisible to
# entry-point detection before this was handled.
_SOURCE = """
from fastapi import APIRouter

router = APIRouter()


def protected_route(method, path, scopes=None, **kwargs):
    def decorator(func):
        return method(path, **kwargs)(func)

    return decorator


@protected_route(router.get, "/{id}/installs", ["devices:read"])
async def get_rom_installs(request, id):
    return id


@protected_route(router.post, "/{id}/approve")
async def approve_install(request, id):
    return id


@mock.patch(router.get, "/not/a/route")
def not_a_route(request):
    return request
"""


def test_a_registrar_passed_as_the_wrapper_decorators_own_argument_is_found(
    tmp_path: Path,
) -> None:
    (tmp_path / "service.py").write_text(_SOURCE, encoding="utf-8")

    result = extract_flows(tmp_path, ["service.py"])

    by_handler = {entry["handler"]: entry["routes"][0] for entry in result["entry_points"]}
    assert by_handler["get_rom_installs"] == {
        "verb": "get",
        "path": "/{id}/installs",
        "methods": ["GET"],
        "router": "router",
    }
    assert by_handler["approve_install"] == {
        "verb": "post",
        "path": "/{id}/approve",
        "methods": ["POST"],
        "router": "router",
    }
    assert "not_a_route" not in by_handler
