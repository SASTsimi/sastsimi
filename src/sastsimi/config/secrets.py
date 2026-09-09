"""Non-resolving secret references; literal credential storage is forbidden."""

import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator


class SecretReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    reference: str

    @field_validator("reference")
    @classmethod
    def validate_reference(cls, value: str) -> str:
        if re.fullmatch(r"env:[A-Z_][A-Z0-9_]*", value):
            return value
        if value.startswith("handle:"):
            try:
                identifier = UUID(value.removeprefix("handle:"))
            except ValueError:
                pass
            else:
                if value == f"handle:{identifier}":
                    return value
        raise ValueError("Expected an environment name or opaque handle")
