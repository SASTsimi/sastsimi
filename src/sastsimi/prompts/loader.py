"""Strict, repository-root-bound prompt manifest and template loading."""

import json
import os
import stat
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from yaml.nodes import MappingNode  # type: ignore[import-untyped]

from .registry import LoadedPromptDefinition, PromptManifest, PromptRegistry

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MAX_PROMPT_FILE_BYTES = 4 * 1024 * 1024
_CANONICAL_TEMPLATE_PREFIX = ("src", "sastsimi", "prompts", "templates")


class _StrictSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_mapping(
    loader: _StrictSafeLoader, node: MappingNode, deep: bool = False
) -> dict[str, object]:
    if not isinstance(node, MappingNode):
        raise ValueError("PROMPT_YAML_UNSAFE")
    result: dict[str, object] = {}
    for key_node, value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise ValueError("PROMPT_YAML_UNSAFE: merge keys are forbidden")
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise ValueError("PROMPT_YAML_UNSAFE: keys must be unique strings")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def strict_load_yaml(data: bytes) -> object:
    """Parse one YAML document while rejecting aliases, tags and merge semantics."""
    try:
        text = data.decode("utf-8")
        events = tuple(yaml.parse(text, Loader=yaml.SafeLoader))
        if any(getattr(event, "anchor", None) for event in events):
            raise ValueError("PROMPT_YAML_UNSAFE: aliases and anchors are forbidden")
        value = yaml.load(text, Loader=_StrictSafeLoader)
    except (UnicodeDecodeError, yaml.YAMLError, ValueError) as error:
        if isinstance(error, ValueError) and str(error).startswith(
            "PROMPT_YAML_UNSAFE"
        ):
            raise
        raise ValueError("PROMPT_YAML_UNSAFE") from error
    if value is None:
        raise ValueError("PROMPT_YAML_UNSAFE: empty document")
    return value


def _is_reparse(info: os.stat_result) -> bool:
    return bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
        or getattr(info, "st_reparse_tag", 0)
    )


class PromptLoader:
    def __init__(self, root: Path) -> None:
        self.root = Path(os.path.abspath(root))
        if not self.root.is_dir():
            raise ValueError("PROMPT_ROOT_INVALID")
        self._assert_no_reparse(Path())
        self._resolved_root = self.root.resolve(strict=True)

    def _assert_no_reparse(self, relative: Path) -> None:
        targets = (
            (self.root,)
            if relative == Path()
            else (
                self.root,
                *(
                    self.root.joinpath(*relative.parts[:index])
                    for index in range(1, len(relative.parts) + 1)
                ),
            )
        )
        for current in targets:
            if not current.exists() and not current.is_symlink():
                continue
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
                raise ValueError("PROMPT_PATH_DENIED")

    def _safe_path(self, relative: Path) -> Path:
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("PROMPT_PATH_DENIED")
        candidate = self.root.joinpath(*relative.parts)
        self._assert_no_reparse(relative)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self._resolved_root)
        except (OSError, ValueError) as error:
            raise ValueError("PROMPT_PATH_DENIED") from error
        if not resolved.is_file():
            raise ValueError("PROMPT_PATH_DENIED")
        return candidate

    def _read_safe(self, relative: Path) -> bytes:
        path = self._safe_path(relative)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise ValueError("PROMPT_PATH_DENIED") from error
        try:
            opened = os.fstat(descriptor)
            current = path.lstat()
            if (
                _is_reparse(opened)
                or _is_reparse(current)
                or stat.S_ISLNK(current.st_mode)
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                or opened.st_size > _MAX_PROMPT_FILE_BYTES
            ):
                raise ValueError("PROMPT_PATH_DENIED")
            chunks: list[bytes] = []
            total = 0
            while total <= _MAX_PROMPT_FILE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(65_536, _MAX_PROMPT_FILE_BYTES + 1 - total),
                )
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
                total += len(chunk)
            raise ValueError("PROMPT_FILE_TOO_LARGE")
        finally:
            os.close(descriptor)

    def load_template(self, relative: Path, expected_sha256: str) -> bytes:
        import hashlib

        data = self._read_safe(relative)
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise ValueError("PROMPT_TEMPLATE_HASH_MISMATCH")
        return data

    def load_registry(self, relative: Path = Path("registry.yaml")) -> PromptRegistry:
        raw = strict_load_yaml(self._read_safe(relative))
        try:
            manifest = PromptManifest.model_validate_json(
                json.dumps(raw, ensure_ascii=False, separators=(",", ":"))
            )
        except (TypeError, ValueError) as error:
            raise ValueError("PROMPT_REGISTRY_INVALID") from error
        definitions: list[LoadedPromptDefinition] = []
        for item in manifest.entries:
            template_path = Path(str(item.template_path))
            if template_path.parts[: len(_CANONICAL_TEMPLATE_PREFIX)] != (
                _CANONICAL_TEMPLATE_PREFIX
            ):
                raise ValueError("PROMPT_PATH_DENIED")
            definitions.append(
                LoadedPromptDefinition.from_bytes(
                    entry=item.entry,
                    template_path=template_path,
                    template=self.load_template(template_path, item.template_sha256),
                    expected_sha256=item.template_sha256,
                )
            )
        return PromptRegistry(tuple(definitions))
