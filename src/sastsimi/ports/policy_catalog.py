"""Public DTO and lookup port for approved official policy sources."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from urllib.parse import parse_qsl, urlsplit

from sastsimi.contracts.ids import ProgramId
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, require_record_ref

_SECRET_QUERY_NAMES = frozenset(
    {"api_key", "apikey", "access_token", "token", "secret", "password"}
)


@dataclass(frozen=True, slots=True)
class ProgramCatalogEntry:
    """Trusted, versioned binding from one program to its official policy."""

    program_id: ProgramId
    program_namespace: str
    external_program_id: str
    source_config_ref: BudgetScopeRef
    source_version: str
    official_endpoint: str
    publisher: str
    parser_name: str
    parser_version: str
    freshness_criterion_ref: StoredDataRef
    freshness_ttl_seconds: int
    timeout_seconds: int
    max_response_bytes: int
    allowed_content_types: tuple[str, ...]
    allowed_redirect_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        endpoint = urlsplit(self.official_endpoint)
        try:
            require_record_ref(self.source_config_ref)
            require_record_ref(self.freshness_criterion_ref)
        except ValueError as error:
            raise ValueError("POLICY_CATALOG_ENTRY_INVALID") from error
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.port not in {None, 443}
            or endpoint.fragment
            or any(
                name.casefold() in _SECRET_QUERY_NAMES
                for name, _value in parse_qsl(endpoint.query, keep_blank_values=True)
            )
            or any(
                not value.strip()
                for value in (
                    self.program_namespace,
                    self.external_program_id,
                    self.source_version,
                    self.publisher,
                    self.parser_name,
                    self.parser_version,
                )
            )
            or self.freshness_ttl_seconds <= 0
            or self.timeout_seconds <= 0
            or self.max_response_bytes <= 0
            or not self.allowed_content_types
        ):
            raise ValueError("POLICY_CATALOG_ENTRY_INVALID")
        hosts = (endpoint.hostname.casefold(), *self.allowed_redirect_hosts)
        if any(not host.strip() or ":" in host or "/" in host for host in hosts):
            raise ValueError("POLICY_CATALOG_ENTRY_INVALID")


class OfficialPolicyCatalogPort(Protocol):
    """Resolve exactly one approved source binding for a program."""

    def resolve_policy_entry(self, program_id: ProgramId) -> ProgramCatalogEntry: ...


__all__ = ["OfficialPolicyCatalogPort", "ProgramCatalogEntry"]
