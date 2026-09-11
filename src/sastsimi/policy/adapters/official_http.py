"""Pinned HTTPS retrieval for catalog-approved official policy sources."""

from __future__ import annotations

import asyncio
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import parse_qsl, urljoin, urlsplit

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.policy import PolicySourceCheck
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import OfficialPolicyFetchRequest, OfficialPolicySource

from ..program_catalog import ProgramCatalog, ProgramCatalogEntry

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_SENSITIVE_HEADER_NAMES = frozenset(
    {"authorization", "cookie", "set-cookie", "proxy-authorization"}
)
_SENSITIVE_QUERY_NAMES = frozenset(
    {"api_key", "apikey", "access_token", "token", "secret", "password"}
)
_SECRET_VALUE = re.compile(
    rb"(?i)(\"?(?:authorization|cookie|set-cookie|api[_-]?key|"
    rb"access[_-]?token|secret)\"?\s*[:=]\s*\"?)[^\"\r\n,;}]+"
)


class PolicySourceBoundaryError(ValueError):
    """The request or response crossed the official-source security boundary."""


class PolicyFetchError(RuntimeError):
    """The approved source could not return a usable response."""


@dataclass(frozen=True, slots=True)
class PinnedHttpRequest:
    url: str
    host: str
    port: int
    target: str
    pinned_ip: str
    timeout_seconds: int
    max_response_bytes: int
    headers: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class HttpPolicyResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    peer_ip: str


class PolicyHttpTransport(Protocol):
    async def send(self, request: PinnedHttpRequest) -> HttpPolicyResponse: ...


type HostResolver = Callable[[str], tuple[str, ...]]


class PinnedHttpsTransport:
    """Small stdlib transport that connects only to the prevalidated IP."""

    async def send(self, request: PinnedHttpRequest) -> HttpPolicyResponse:
        return await asyncio.to_thread(self._send, request)

    @staticmethod
    def _send(request: PinnedHttpRequest) -> HttpPolicyResponse:
        raw_socket = socket.create_connection(
            (request.pinned_ip, request.port),
            timeout=request.timeout_seconds,
        )
        tls_socket = ssl.create_default_context().wrap_socket(
            raw_socket,
            server_hostname=request.host,
        )
        connection = http.client.HTTPSConnection(
            request.host,
            request.port,
            timeout=request.timeout_seconds,
        )
        connection.sock = tls_socket
        try:
            connection.request("GET", request.target, headers=dict(request.headers))
            response = connection.getresponse()
            body = response.read(request.max_response_bytes + 1)
            peer = tls_socket.getpeername()[0]
            return HttpPolicyResponse(
                status=response.status,
                headers={
                    name.casefold(): value for name, value in response.getheaders()
                },
                body=body,
                peer_ip=peer,
            )
        finally:
            connection.close()


class OfficialHttpPolicySource:
    """Fetch one exact catalog source without trusting DNS, redirects, or bytes."""

    def __init__(
        self,
        *,
        catalog: ProgramCatalog,
        artifacts: ArtifactStore,
        transport: PolicyHttpTransport,
        resolver: HostResolver,
        clock: Clock,
        max_redirects: int = 3,
    ) -> None:
        self._catalog = catalog
        self._artifacts = artifacts
        self._transport = transport
        self._resolver = resolver
        self._clock = clock
        self._max_redirects = max_redirects

    async def fetch_official(
        self, request: OfficialPolicyFetchRequest
    ) -> OfficialPolicySource:
        entry = self._catalog.resolve_policy_entry(request.program_id)
        if (
            request.action.action_type != "FETCH_POLICY"
            or request.source_config_ref != entry.source_config_ref
            or request.source_config_ref not in request.action.input_refs
        ):
            raise PolicySourceBoundaryError("POLICY_FETCH_REQUEST_MISMATCH")
        url = entry.official_endpoint
        response: HttpPolicyResponse | None = None
        for redirects in range(self._max_redirects + 1):
            pinned = self._pin(url, entry)
            try:
                response = await asyncio.wait_for(
                    self._transport.send(pinned),
                    timeout=pinned.timeout_seconds,
                )
            except (
                TimeoutError,
                OSError,
                ssl.SSLError,
                http.client.HTTPException,
            ) as error:
                raise PolicyFetchError("POLICY_FETCH_TRANSPORT_FAILED") from error
            if response.peer_ip != pinned.pinned_ip:
                raise PolicySourceBoundaryError("POLICY_SOURCE_DNS_REBINDING")
            headers = {
                name.casefold(): value for name, value in response.headers.items()
            }
            if response.status not in _REDIRECT_STATUSES:
                break
            location = headers.get("location")
            if location is None or redirects == self._max_redirects:
                raise PolicySourceBoundaryError("POLICY_REDIRECT_DENIED")
            url = urljoin(url, location)
        assert response is not None
        if response.status != 200:
            raise PolicyFetchError(f"POLICY_FETCH_HTTP_{response.status}")
        headers = {name.casefold(): value for name, value in response.headers.items()}
        if len(response.body) > entry.max_response_bytes:
            raise PolicySourceBoundaryError("POLICY_RESPONSE_TOO_LARGE")
        media_type = headers.get("content-type", "").split(";", 1)[0].strip().casefold()
        allowed_types = {value.casefold() for value in entry.allowed_content_types}
        if media_type not in allowed_types:
            raise PolicySourceBoundaryError("POLICY_CONTENT_TYPE_DENIED")
        try:
            response.body.decode("utf-8")
        except UnicodeDecodeError as error:
            raise PolicySourceBoundaryError("POLICY_SOURCE_NOT_UTF8") from error
        safe_body = _SECRET_VALUE.sub(rb"\1<redacted>", response.body)
        body_ref = self._commit(safe_body, media_type)
        fetched_at = self._clock.now()
        safe_headers = {
            name: value
            for name, value in headers.items()
            if name in {"etag", "last-modified"}
            and name not in _SENSITIVE_HEADER_NAMES
        }
        provenance_ref = self._commit(
            canonical_bytes(
                {
                    "url": url,
                    "etag": safe_headers.get("etag"),
                    "last_modified": safe_headers.get("last-modified"),
                    "fetched_at": fetched_at,
                    "body_sha256": hashlib.sha256(response.body).hexdigest(),
                }
            ),
            "application/json",
        )
        check = PolicySourceCheck(
            source_id=hashlib.sha256(url.encode()).hexdigest(),
            source_ref=body_ref,
            source_url=url,
            publisher=entry.publisher,
            status="VERIFIED",
            evidence_refs=(provenance_ref,),
            checked_at=fetched_at,
        )
        return OfficialPolicySource(check, safe_body)

    def _pin(self, url: str, entry: ProgramCatalogEntry) -> PinnedHttpRequest:
        parsed = urlsplit(url)
        allowed_hosts = {
            host.casefold()
            for host in (
                urlsplit(entry.official_endpoint).hostname,
                *entry.allowed_redirect_hosts,
            )
            if host is not None
        }
        host = parsed.hostname.casefold() if parsed.hostname else ""
        if (
            parsed.scheme != "https"
            or host not in allowed_hosts
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
            or parsed.fragment
            or any(
                name.casefold() in _SENSITIVE_QUERY_NAMES
                for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
            )
        ):
            raise PolicySourceBoundaryError("POLICY_REDIRECT_DENIED")
        try:
            addresses = self._resolver(host)
            parsed_addresses = tuple(ipaddress.ip_address(value) for value in addresses)
        except (KeyError, ValueError, OSError) as error:
            raise PolicySourceBoundaryError("POLICY_SOURCE_DNS_INVALID") from error
        if not parsed_addresses or any(
            not address.is_global for address in parsed_addresses
        ):
            raise PolicySourceBoundaryError("POLICY_SOURCE_SSRF_DENIED")
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        return PinnedHttpRequest(
            url=url,
            host=host,
            port=443,
            target=target,
            pinned_ip=str(parsed_addresses[0]),
            timeout_seconds=entry.timeout_seconds,
            max_response_bytes=entry.max_response_bytes,
            headers={"accept": ", ".join(entry.allowed_content_types)},
        )

    def _commit(self, data: bytes, media_type: str) -> StoredDataRef:
        return self._artifacts.commit(self._artifacts.stage_bytes(data, media_type))


def resolve_public_addresses(host: str) -> tuple[str, ...]:
    """Resolve all address candidates; the caller rejects any non-public answer."""
    return tuple(
        sorted(
            {
                row[4][0]
                for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
                if isinstance(row[4][0], str)
            }
        )
    )


__all__ = [
    "HttpPolicyResponse",
    "OfficialHttpPolicySource",
    "PinnedHttpRequest",
    "PolicyFetchError",
    "PolicyHttpTransport",
    "PolicySourceBoundaryError",
    "PinnedHttpsTransport",
    "resolve_public_addresses",
]
