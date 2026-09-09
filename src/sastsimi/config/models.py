"""Foundation configuration, independent of future domain schemas."""

from pathlib import Path
from typing import Literal

from platformdirs import user_state_dir
from pydantic import BaseModel, ConfigDict, Field, field_validator


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal[1] = 1
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    output_format: Literal["text", "json"] = "text"
    data_dir: Path = Field(
        default_factory=lambda: Path(user_state_dir("sastsimi")),
        exclude=True,
        repr=False,
    )

    @field_validator("schema_version", mode="before")
    @classmethod
    def validate_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be an integer")
        return value

    @field_validator("data_dir", mode="before")
    @classmethod
    def local_path(cls, value: object) -> Path:
        if (
            not isinstance(value, (str, Path))
            or not str(value).strip()
            or "\x00" in str(value)
        ):
            raise ValueError("data_dir must be a local path")
        return Path(value).absolute()
