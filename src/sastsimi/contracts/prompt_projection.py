"""Deterministic bytes for declared prompt fields, without source instructions."""

from collections.abc import Mapping, Sequence

from pydantic import BaseModel

from .canonical_json import canonical_bytes


def project_prompt_value(value: object, field_paths: tuple[str, ...]) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump()
    if field_paths == ("$",):
        return canonical_bytes(value)
    if not field_paths or "$" in field_paths:
        raise ValueError("PROMPT_FIELD_PATH_INVALID")
    projected: dict[str, object] = {}
    for path in field_paths:
        if path in projected:
            raise ValueError("PROMPT_FIELD_PATH_INVALID")
        selected = value
        if path.startswith("/"):
            raw_parts = path[1:].split("/")
            parts: list[str] = []
            for raw in raw_parts:
                index = 0
                decoded = ""
                while index < len(raw):
                    if raw[index] != "~":
                        decoded += raw[index]
                        index += 1
                        continue
                    if index + 1 >= len(raw) or raw[index + 1] not in {"0", "1"}:
                        raise ValueError("PROMPT_FIELD_PATH_INVALID")
                    decoded += "~" if raw[index + 1] == "0" else "/"
                    index += 2
                parts.append(decoded)
        elif path.startswith("$."):
            # Compatibility only. New registry entries use JSON Pointer paths.
            parts = path[2:].split(".")
        else:
            raise ValueError("PROMPT_FIELD_PATH_INVALID")
        for name in parts:
            if isinstance(selected, Mapping) and name in selected:
                selected = selected[name]
            elif (
                isinstance(selected, Sequence)
                and not isinstance(selected, (str, bytes, bytearray))
                and name.isdecimal()
                and int(name) < len(selected)
            ):
                selected = selected[int(name)]
            else:
                raise ValueError("PROMPT_FIELD_PATH_INVALID")
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
