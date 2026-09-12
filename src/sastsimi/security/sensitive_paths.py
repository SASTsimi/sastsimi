"""Deterministic policy for paths that may contain credential material."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True, slots=True)
class SensitivePathPolicy:
    """Classify repository-relative paths without reading their contents."""

    file_names: frozenset[str]
    suffixes: frozenset[str]
    exact_paths: frozenset[str]
    file_name_prefixes: tuple[str, ...]

    def is_sensitive(self, path: str | PurePosixPath) -> bool:
        normalized = str(path).replace("\\", "/").casefold()
        pure = PurePosixPath(normalized)
        names = pure.parts
        file_name = pure.name
        return (
            normalized in self.exact_paths
            or any(name in self.file_names for name in names)
            or any(
                name.startswith(prefix)
                for name in names
                for prefix in self.file_name_prefixes
            )
            or PurePosixPath(file_name).suffix in self.suffixes
        )


DEFAULT_SENSITIVE_PATH_POLICY = SensitivePathPolicy(
    file_names=frozenset(
        {
            ".env",
            ".netrc",
            ".npmrc",
            ".pypirc",
            "credentials.json",
            "gradle.properties",
            "id_dsa",
            "id_ed25519",
            "id_rsa",
            "service-account.json",
            "settings.xml",
        }
    ),
    suffixes=frozenset({".key", ".p12", ".pem", ".pfx"}),
    exact_paths=frozenset({".aws/credentials", ".docker/config.json"}),
    file_name_prefixes=(".env.",),
)


__all__ = ["DEFAULT_SENSITIVE_PATH_POLICY", "SensitivePathPolicy"]
