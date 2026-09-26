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
_COMMIT_SHA = "1" * 40
_ROOT_TREE_SHA = "2" * 40
_GITHUB_TREE_SHA = "3" * 40


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


def _branch(*, name: str = "main") -> HttpPolicyResponse:
    return _json_response(
        {
            "name": name,
            "commit": {
                "sha": _COMMIT_SHA,
                "commit": {"tree": {"sha": _ROOT_TREE_SHA}},
            },
        }
    )


def _tree(sha: str, *entries: dict[str, object]) -> HttpPolicyResponse:
    return _json_response({"sha": sha, "tree": list(entries), "truncated": False})


def _entry(path: str, mode: str, sha: str) -> dict[str, object]:
    return {
        "path": path,
        "mode": mode,
        "type": "tree" if mode == "040000" else "blob",
        "sha": sha,
    }


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
    policy = _file(".github/SECURITY.md", text)
    blob_sha = json.loads(policy.body)["sha"]
    policy_target = (
        f"/repos/fork/project/contents/.github/SECURITY.md?ref={_COMMIT_SHA}"
    )
    subject, transport = _subject(
        {
            "/repos/fork/project": _metadata("fork", "project"),
            "/repos/fork/project/branches/main": _branch(),
            policy_target: policy,
            f"/repos/fork/project/git/trees/{_ROOT_TREE_SHA}": _tree(
                _ROOT_TREE_SHA, _entry(".github", "040000", _GITHUB_TREE_SHA)
            ),
            f"/repos/fork/project/git/trees/{_GITHUB_TREE_SHA}": _tree(
                _GITHUB_TREE_SHA, _entry("SECURITY.md", "100644", blob_sha)
            ),
            f"/repos/fork/project/contents/SECURITY.md?ref={_COMMIT_SHA}": _file(
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
        "https://api.github.com/repos/fork/project/contents/.github/SECURITY.md"
        f"?ref={_COMMIT_SHA}"
    )
    assert all(call.host == "api.github.com" for call in transport.calls)
    assert all("upstream" not in call.target for call in transport.calls)
    assert len(transport.calls) == 5


@pytest.mark.asyncio
async def test_root_policy_after_confirmed_first_404() -> None:
    policy = _file("SECURITY.md", b"Root policy")
    blob_sha = json.loads(policy.body)["sha"]
    subject, transport = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/app/branches/main": _branch(),
            f"/repos/acme/app/contents/SECURITY.md?ref={_COMMIT_SHA}": policy,
            f"/repos/acme/app/git/trees/{_ROOT_TREE_SHA}": _tree(
                _ROOT_TREE_SHA, _entry("SECURITY.md", "100644", blob_sha)
            ),
        }
    )
    result = await subject.discover("https://github.com/acme/app")
    assert result.status == "FOUND"
    assert result.source_path == "SECURITY.md"
    assert [call.target for call in transport.calls] == [
        "/repos/acme/app",
        "/repos/acme/app/branches/main",
        f"/repos/acme/app/contents/.github/SECURITY.md?ref={_COMMIT_SHA}",
        f"/repos/acme/app/contents/SECURITY.md?ref={_COMMIT_SHA}",
        f"/repos/acme/app/git/trees/{_ROOT_TREE_SHA}",
    ]


@pytest.mark.asyncio
async def test_same_owner_inherited_policy_after_own_locations_are_absent() -> None:
    text = b"Owner default security policy"
    policy = _file(".github/SECURITY.md", text)
    blob_sha = json.loads(policy.body)["sha"]
    policy_target = (
        f"/repos/acme/.github/contents/.github/SECURITY.md?ref={_COMMIT_SHA}"
    )
    subject, transport = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/app/branches/main": _branch(),
            "/repos/acme/.github": _metadata("acme", ".github"),
            "/repos/acme/.github/branches/main": _branch(),
            policy_target: policy,
            f"/repos/acme/.github/git/trees/{_ROOT_TREE_SHA}": _tree(
                _ROOT_TREE_SHA, _entry(".github", "040000", _GITHUB_TREE_SHA)
            ),
            f"/repos/acme/.github/git/trees/{_GITHUB_TREE_SHA}": _tree(
                _GITHUB_TREE_SHA, _entry("SECURITY.md", "100644", blob_sha)
            ),
        }
    )
    result = await subject.discover("https://github.com/acme/app")
    assert result.status == "FOUND"
    assert result.publisher == "acme/.github"
    assert result.source_path == ".github/SECURITY.md"
    assert [call.target for call in transport.calls][:6] == [
        "/repos/acme/app",
        "/repos/acme/app/branches/main",
        f"/repos/acme/app/contents/.github/SECURITY.md?ref={_COMMIT_SHA}",
        f"/repos/acme/app/contents/SECURITY.md?ref={_COMMIT_SHA}",
        f"/repos/acme/app/contents/docs/SECURITY.md?ref={_COMMIT_SHA}",
        "/repos/acme/.github",
    ]


@pytest.mark.asyncio
async def test_no_policy_is_distinct_from_failed_fetch() -> None:
    subject, _ = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/app/branches/main": _branch(),
        }
    )
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
            "/repos/acme/app/branches/main": _branch(),
            f"/repos/acme/app/contents/.github/SECURITY.md?ref={_COMMIT_SHA}": fault,
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
    policy_target = f"/repos/acme/app/contents/.github/SECURITY.md?ref={_COMMIT_SHA}"
    subject, _ = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/app/branches/main": _branch(),
            policy_target: _json_response(payload),
        }
    )

    result = await subject.discover("https://github.com/acme/app")

    assert result.status == "UNVERIFIED"
    assert result.body is None


@pytest.mark.asyncio
async def test_dereferenced_policy_symlink_is_rejected_by_git_tree_mode() -> None:
    target = b"# Policy in another path\n"
    contents = _file(".github/SECURITY.md", target)
    subject, transport = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/app/branches/main": _branch(),
            "/repos/acme/app/contents/.github/SECURITY.md?ref=main": contents,
            f"/repos/acme/app/contents/.github/SECURITY.md?ref={_COMMIT_SHA}": contents,
            f"/repos/acme/app/git/trees/{_ROOT_TREE_SHA}": _tree(
                _ROOT_TREE_SHA, _entry(".github", "040000", _GITHUB_TREE_SHA)
            ),
            f"/repos/acme/app/git/trees/{_GITHUB_TREE_SHA}": _tree(
                _GITHUB_TREE_SHA, _entry("SECURITY.md", "120000", "4" * 40)
            ),
        }
    )

    result = await subject.discover("https://github.com/acme/app")

    assert result.status == "UNVERIFIED"
    assert result.reason_code == "POLICY_GITHUB_SYMLINK_DENIED"
    assert result.body is None
    assert [call.host for call in transport.calls] == [
        "api.github.com",
    ] * len(transport.calls)


@pytest.mark.asyncio
async def test_regular_policy_tree_blob_matches_pinned_contents_revision() -> None:
    contents = _file(".github/SECURITY.md", b"# Regular policy\n")
    blob_sha = json.loads(contents.body)["sha"]
    subject, transport = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/app/branches/main": _branch(),
            f"/repos/acme/app/contents/.github/SECURITY.md?ref={_COMMIT_SHA}": contents,
            f"/repos/acme/app/git/trees/{_ROOT_TREE_SHA}": _tree(
                _ROOT_TREE_SHA, _entry(".github", "040000", _GITHUB_TREE_SHA)
            ),
            f"/repos/acme/app/git/trees/{_GITHUB_TREE_SHA}": _tree(
                _GITHUB_TREE_SHA, _entry("SECURITY.md", "100644", blob_sha)
            ),
        }
    )

    result = await subject.discover("https://github.com/acme/app")

    assert result.status == "FOUND"
    assert result.body == b"# Regular policy\n"
    assert result.blob_sha == blob_sha
    assert result.source_url == (
        "https://api.github.com/repos/acme/app/contents/.github/SECURITY.md"
        f"?ref={_COMMIT_SHA}"
    )
    assert [call.target for call in transport.calls] == [
        "/repos/acme/app",
        "/repos/acme/app/branches/main",
        f"/repos/acme/app/contents/.github/SECURITY.md?ref={_COMMIT_SHA}",
        f"/repos/acme/app/git/trees/{_ROOT_TREE_SHA}",
        f"/repos/acme/app/git/trees/{_GITHUB_TREE_SHA}",
    ]


@pytest.mark.asyncio
async def test_policy_tree_blob_must_match_contents_at_pinned_revision() -> None:
    contents = _file("SECURITY.md", b"# Policy at the pinned revision\n")
    subject, _ = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/app/branches/main": _branch(),
            f"/repos/acme/app/contents/SECURITY.md?ref={_COMMIT_SHA}": contents,
            f"/repos/acme/app/git/trees/{_ROOT_TREE_SHA}": _tree(
                _ROOT_TREE_SHA, _entry("SECURITY.md", "100644", "4" * 40)
            ),
        }
    )

    result = await subject.discover("https://github.com/acme/app")

    assert result.status == "UNVERIFIED"
    assert result.reason_code == "POLICY_GITHUB_TREE_MISMATCH"
    assert result.body is None


@pytest.mark.asyncio
async def test_git_tree_redirect_is_not_followed() -> None:
    contents = _file("SECURITY.md", b"# Policy\n")
    subject, transport = _subject(
        {
            "/repos/acme/app": _metadata("acme", "app"),
            "/repos/acme/app/branches/main": _branch(),
            f"/repos/acme/app/contents/SECURITY.md?ref={_COMMIT_SHA}": contents,
            f"/repos/acme/app/git/trees/{_ROOT_TREE_SHA}": HttpPolicyResponse(
                302,
                {"location": "https://attacker.invalid/tree"},
                b"",
                _PUBLIC_IP,
            ),
        }
    )

    result = await subject.discover("https://github.com/acme/app")

    assert result.status == "UNVERIFIED"
    assert result.reason_code == "POLICY_GITHUB_REDIRECT_DENIED"
    assert result.body is None
    assert all(call.host == "api.github.com" for call in transport.calls)
    assert not any("attacker.invalid" in call.target for call in transport.calls)
