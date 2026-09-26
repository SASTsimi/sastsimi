"""A GitHub policy must be attributable to the analyzed repository."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field

import pytest

from sastsimi.policy.adapters.official_http import HttpPolicyResponse, PinnedHttpRequest
from sastsimi.simple_runtime.github_policy import GitHubPolicyDiscovery
from tests.integration.runtime_support import TestClock

_PUBLIC_IP = "140.82.112.5"


def _json_response(value: object, *, status: int = 200) -> HttpPolicyResponse:
    return HttpPolicyResponse(
        status=status,
        headers={"content-type": "application/json", "etag": '"policy-v1"'},
        body=json.dumps(value).encode("utf-8"),
        peer_ip=_PUBLIC_IP,
    )


def _metadata(owner: str, repo: str, *, branch: str = "main") -> HttpPolicyResponse:
    return _json_response(
        {
            "full_name": f"{owner}/{repo}",
            "name": repo,
            "owner": {"login": owner},
            "private": False,
            "default_branch": branch,
            "fork": False,
            "parent": {"full_name": "upstream/project"},
        }
    )


def _file(path: str, content: bytes) -> HttpPolicyResponse:
    return _json_response(
        {
            "type": "file",
            "path": path,
            "sha": hashlib.sha1(
                b"blob " + str(len(content)).encode() + b"\0" + content
            ).hexdigest(),
            "size": len(content),
            "encoding": "base64",
            "content": base64.b64encode(content).decode("ascii"),
            "download_url": "https://attacker.invalid/ignored",
        }
    )


def _missing() -> HttpPolicyResponse:
    return _json_response({"message": "Not Found"}, status=404)


@dataclass
class _Transport:
    responses: dict[str, HttpPolicyResponse | Exception]
    calls: list[PinnedHttpRequest] = field(default_factory=list)

    async def send(self, request: PinnedHttpRequest) -> HttpPolicyResponse:
        self.calls.append(request)
        value = self.responses.get(request.target, _missing())
        if isinstance(value, Exception):
            raise value
        return value


def _subject(
    responses: dict[str, HttpPolicyResponse | Exception],
    *,
    addresses: tuple[str, ...] = (_PUBLIC_IP,),
) -> tuple[GitHubPolicyDiscovery, _Transport]:
    transport = _Transport(responses)
    return (
        GitHubPolicyDiscovery(
            transport=transport,
            resolver=lambda _host: addresses,
            clock=TestClock(),
        ),
        transport,
    )


@pytest.mark.asyncio
async def test_own_github_policy_wins_and_fork_parent_is_never_followed() -> None:
    text = b"# Security Policy\nSupported: v1\n"
    subject, transport = _subject(
        {
            "/repos/fork/project": _metadata("fork", "project"),
            "/repos/fork/project/contents/.github/SECURITY.md?ref=main": _file(
                ".github/SECURITY.md", text
            ),
            "/repos/fork/project/contents/SECURITY.md?ref=main": _file(
                "SECURITY.md", b"incorrect precedence"
            ),
        }
    )

    result = await subject.discover("https://github.com/fork/project.git")

    assert result.status == "FOUND"
    assert (result.owner, result.repo, result.publisher) == (
        "fork",
        "project",
        "fork/project",
    )
    assert result.source_path == ".github/SECURITY.md"
    assert result.body == text
    assert result.sha256 == hashlib.sha256(text).hexdigest()
    assert result.blob_sha is not None
    assert result.source_url == (
        "https://api.github.com/repos/fork/project/contents/.github/SECURITY.md?ref=main"
    )
    assert all(call.host == "api.github.com" for call in transport.calls)
    assert all("upstream" not in call.target for call in transport.calls)
    assert len(transport.calls) == 2


@pytest.mark.asyncio
async def test_root_policy_after_confirmed_first_404() -> None:
    subject, transport = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/app/contents/SECURITY.md?ref=main": _file(
                "SECURITY.md", b"Root policy"
            ),
        }
    )
    result = await subject.discover("https://github.com/acme/app")
    assert result.status == "FOUND"
    assert result.source_path == "SECURITY.md"
    assert [call.target for call in transport.calls] == [
        "/repos/acme/app",
        "/repos/acme/app/contents/.github/SECURITY.md?ref=main",
        "/repos/acme/app/contents/SECURITY.md?ref=main",
    ]


@pytest.mark.asyncio
async def test_same_owner_inherited_policy_after_own_locations_are_absent() -> None:
    text = b"Owner default security policy"
    subject, transport = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/.github": _metadata("acme", ".github"),
            "/repos/acme/.github/contents/.github/SECURITY.md?ref=main": _file(
                ".github/SECURITY.md", text
            ),
        }
    )
    result = await subject.discover("https://github.com/acme/app")
    assert result.status == "FOUND"
    assert result.publisher == "acme/.github"
    assert result.source_path == ".github/SECURITY.md"
    assert [call.target for call in transport.calls][:5] == [
        "/repos/acme/app",
        "/repos/acme/app/contents/.github/SECURITY.md?ref=main",
        "/repos/acme/app/contents/SECURITY.md?ref=main",
        "/repos/acme/app/contents/docs/SECURITY.md?ref=main",
        "/repos/acme/.github",
    ]


@pytest.mark.asyncio
async def test_no_policy_is_distinct_from_failed_fetch() -> None:
    subject, _ = _subject({"/repos/acme/app": _metadata("acme", "app")})
    result = await subject.discover("https://github.com/acme/app")
    assert result.status == "ABSENT"
    assert result.body is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fault", "expected"),
    [
        (_json_response({}, status=403), "FETCH_FAILED"),
        (_json_response({}, status=429), "FETCH_FAILED"),
        (TimeoutError(), "FETCH_FAILED"),
        (
            HttpPolicyResponse(
                200, {"content-type": "application/json"}, b"{", _PUBLIC_IP
            ),
            "FETCH_FAILED",
        ),
        (
            HttpPolicyResponse(
                200,
                {"content-type": "application/json"},
                b"x" * (256 * 1024 + 1),
                _PUBLIC_IP,
            ),
            "FETCH_FAILED",
        ),
        (_json_response({"type": "symlink", "target": "/etc/passwd"}), "UNVERIFIED"),
        (
            HttpPolicyResponse(
                302, {"location": "https://attacker.invalid/policy"}, b"", _PUBLIC_IP
            ),
            "UNVERIFIED",
        ),
    ],
)
async def test_faults_never_return_policy_bytes(
    fault: HttpPolicyResponse | Exception, expected: str
) -> None:
    subject, transport = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/app/contents/.github/SECURITY.md?ref=main": fault,
        }
    )
    result = await subject.discover("https://github.com/acme/app")
    assert result.status == expected
    assert result.body is None
    assert all(call.host == "api.github.com" for call in transport.calls)


@pytest.mark.asyncio
async def test_private_dns_and_peer_mismatch_fail_closed() -> None:
    subject, transport = _subject({}, addresses=("127.0.0.1",))
    result = await subject.discover("https://github.com/acme/app")
    assert result.status == "UNVERIFIED"
    assert transport.calls == []

    subject, _ = _subject(
        {
            "/repos/acme/app": HttpPolicyResponse(
                200, {"content-type": "application/json"}, b"{}", "127.0.0.1"
            )
        }
    )
    result = await subject.discover("https://github.com/acme/app")
    assert result.status == "UNVERIFIED"


@pytest.mark.asyncio
async def test_non_github_or_ambiguous_origin_is_unverified_without_network() -> None:
    subject, transport = _subject({})
    for url in (
        "https://gitlab.com/acme/app",
        "https://github.com/acme/app/tree/main",
        "https://github.com/acme/app?token=secret",
        "https://github.com/acme/app/../../other",
    ):
        result = await subject.discover(url)
        assert result.status == "UNVERIFIED"
        assert result.body is None
    assert transport.calls == []


@pytest.mark.asyncio
async def test_metadata_mismatch_never_fetches_parent_or_contents() -> None:
    subject, transport = _subject({"/repos/acme/app": _metadata("other", "app")})
    result = await subject.discover("https://github.com/acme/app")
    assert result.status == "UNVERIFIED"
    assert len(transport.calls) == 1


@pytest.mark.asyncio
async def test_policy_bytes_must_match_github_blob_sha() -> None:
    response = _file(".github/SECURITY.md", b"Policy content")
    payload = json.loads(response.body)
    payload["sha"] = "0" * 40
    subject, _ = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/app/contents/.github/SECURITY.md?ref=main": _json_response(
                payload
            ),
        }
    )

    result = await subject.discover("https://github.com/acme/app")

    assert result.status == "UNVERIFIED"
    assert result.body is None
