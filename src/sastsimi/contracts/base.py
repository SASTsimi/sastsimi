"""Strict value contracts; wire input should use model_validate_json."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(ge=1)]
NonEmptyStr = Annotated[str, Field(min_length=1, pattern=r"\S")]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SchemaVersion = Annotated[
    str, Field(pattern=r"^[1-9][0-9]*\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
]


class ContractModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        revalidate_instances="always",
        validate_by_alias=False,
        validate_by_name=True,
    )

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: object) -> None:
        super().__pydantic_init_subclass__(**kwargs)
        if any(
            field.alias or field.validation_alias or field.serialization_alias
            for field in cls.model_fields.values()
        ):
            raise TypeError("Contract fields must not declare aliases")
