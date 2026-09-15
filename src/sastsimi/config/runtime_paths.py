"""Frozen local persistence layout shared by bootstrap and adapters."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuntimePaths:
    root: Path

    @property
    def database(self) -> Path:
        return self.root / "db" / "sastsimi.sqlite3"

    @property
    def artifacts(self) -> Path:
        return self.root / "artifacts"

    @property
    def staging(self) -> Path:
        return self.root / "staging"

    @property
    def quarantine(self) -> Path:
        return self.root / "quarantine"

    @property
    def reports(self) -> Path:
        return self.root / "reports"
