"""Deterministic bytes for declared prompt fields, without source instructions."""

from collections.abc import Mapping

from pydantic import BaseModel

from .canonical_json import canonical_bytes


def project_prompt_value(value: object, field_paths: tuple[str, ...]) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump()
    if field_paths == ("$",):
        return canonical_bytes(value)
    projected: dict[str, object] = {}
    for path in field_paths:
        if not path.startswith("$.") or path in projected:
            raise ValueError("PROMPT_FIELD_PATH_INVALID")
        selected = value
        for name in path[2:].split("."):
            if not name or not isinstance(selected, Mapping) or name not in selected:
                raise ValueError("PROMPT_FIELD_PATH_INVALID")
            selected = selected[name]
        projected[path] = selected
    return canonical_bytes(projected)


def render_prompt_bytes(
    template: bytes, bindings: tuple[tuple[str, bytes], ...]
) -> bytes:
    return (
        template
        + b"\n"
        + b"\n".join(f"[{slot}]\n".encode() + data for slot, data in bindings)
    )
