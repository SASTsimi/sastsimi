"""Bounded discovery of a public GitHub repository's official policy file."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import http.client
import json
import re
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from urllib.parse import quote, urlsplit

from sastsimi.policy.adapters.official_http import (
    HostResolver,
    HttpPolicyResponse,
    PolicyHttpTransport,
    PolicySourceBoundaryError,
    pin_approved_https_request,
)
from sastsimi.ports.clock import Clock

_MAX_RESPONSE_BYTES = 256 * 1024
_TIMEOUT_SECONDS = 5
_POLICY_PATHS = (".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md")
_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+\Z")
_BLOB_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")

type CollectionStatus = Literal["FOUND", "ABSENT", "UNVERIFIED", "FETCH_FAILED"]


@dataclass(frozen=True, slots=True)
class DiscoveredPolicy:
    status: CollectionStatus
    reason_code: str
    owner: str | None
    repo: str | None
    publisher: str | None
    source_url: str | None
    source_path: str | None
    blob_sha: str | None
    etag: str | None
    content_type: str | None
    checked_at: datetime
    sha256: str | None
    body: bytes | None


class _DiscoveryError(Exception):
    def __init__(self, status: Literal["UNVERIFIED", "FETCH_FAILED"], code: str):
        self.status = status
        self.code = code
        super().__init__(code)


class GitHubPolicyDiscovery:
    """Resolve a policy at one verified GitHub default-branch revision."""

    def __init__(
        self, *, transport: PolicyHttpTransport, resolver: HostResolver, clock: Clock
    ) -> None:
        self._transport = transport
        self._resolver = resolver
        self._clock = clock

    async def discover(self, repository_url: str) -> DiscoveredPolicy:
        checked_at = self._clock.now()
        identity = _repository_identity(repository_url)
        if identity is None:
            return self._result("UNVERIFIED", "POLICY_ORIGIN_UNSUPPORTED", checked_at)
        owner, repo = identity
        try:
            own = await self._repository_metadata(owner, repo, allow_missing=False)
            assert own is not None
            owner, repo, branch = own
            found = await self._find_policy(owner, repo, branch, checked_at)
            if found is not None:
                return found
            if repo.casefold() != ".github":
                inherited = await self._repository_metadata(
                    owner, ".github", allow_missing=True
                )
                if inherited is not None:
                    inherited_owner, inherited_repo, inherited_branch = inherited
                    found = await self._find_policy(
                        inherited_owner, inherited_repo, inherited_branch, checked_at
                    )
                    if found is not None:
                        return found
            return self._result(
                "ABSENT", "POLICY_NOT_PUBLISHED", checked_at, owner=owner, repo=repo
            )
        except _DiscoveryError as error:
            return self._result(
                error.status, error.code, checked_at, owner=owner, repo=repo
            )

    async def _repository_metadata(
        self, owner: str, repo: str, *, allow_missing: bool
    ) -> tuple[str, str, str] | None:
        data = await self._get_json(
            f"https://api.github.com/repos/{owner}/{repo}",
            allow_missing=allow_missing,
        )
        if data is None:
            return None
        owner_data = data.get("owner")
        login = owner_data.get("login") if isinstance(owner_data, dict) else None
        name = data.get("name")
        full_name = data.get("full_name")
        branch = data.get("default_branch")
        if (
            not isinstance(login, str)
            or not isinstance(name, str)
            or not isinstance(full_name, str)
            or not isinstance(branch, str)
            or not branch
            or len(branch) > 255
            or not _OWNER.fullmatch(login)
            or not _REPOSITORY.fullmatch(name)
            or login.casefold() != owner.casefold()
            or name.casefold() != repo.casefold()
            or full_name.casefold() != f"{owner}/{repo}".casefold()
            or data.get("private") is not False
        ):
            raise _DiscoveryError("UNVERIFIED", "POLICY_REPOSITORY_IDENTITY_INVALID")
        return login, name, branch

    async def _find_policy(
        self, owner: str, repo: str, branch: str, checked_at: datetime
    ) -> DiscoveredPolicy | None:
        commit_sha, root_tree_sha = await self._default_branch_revision(
            owner, repo, branch
        )
        for path in _POLICY_PATHS:
            url = (
                f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
                f"?ref={commit_sha}"
            )
            payload, response = await self._get_json_with_response(
                url, allow_missing=True
            )
            if payload is None:
                continue
            body, blob_sha = _decode_policy_file(payload, path)
            await self._verify_policy_tree_blob(
                owner, repo, root_tree_sha, path, blob_sha
            )
            return DiscoveredPolicy(
                status="FOUND",
                reason_code="POLICY_FOUND",
                owner=owner,
                repo=repo,
                publisher=f"{owner}/{repo}",
                source_url=url,
                source_path=path,
                blob_sha=blob_sha,
                etag=_header(response, "etag"),
                content_type="text/markdown",
                checked_at=checked_at,
                sha256=hashlib.sha256(body).hexdigest(),
                body=body,
            )
        return None

    async def _default_branch_revision(
        self, owner: str, repo: str, branch: str
    ) -> tuple[str, str]:
        data = await self._get_json(
            f"https://api.github.com/repos/{owner}/{repo}/branches/"
            f"{quote(branch, safe='')}",
            allow_missing=True,
        )
        if data is None:
            raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_REVISION_INVALID")
        commit = data.get("commit")
        git_commit = commit.get("commit") if isinstance(commit, dict) else None
        tree = git_commit.get("tree") if isinstance(git_commit, dict) else None
        commit_sha = commit.get("sha") if isinstance(commit, dict) else None
        tree_sha = tree.get("sha") if isinstance(tree, dict) else None
        if (
            data.get("name") != branch
            or not isinstance(commit_sha, str)
            or not _BLOB_SHA.fullmatch(commit_sha)
            or not isinstance(tree_sha, str)
            or not _BLOB_SHA.fullmatch(tree_sha)
        ):
            raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_REVISION_INVALID")
        return commit_sha, tree_sha

    async def _verify_policy_tree_blob(
        self, owner: str, repo: str, root_tree_sha: str, path: str, blob_sha: str
    ) -> None:
        tree_sha = root_tree_sha
        segments = path.split("/")
        for index, segment in enumerate(segments):
            data = await self._get_json(
                f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tree_sha}",
                allow_missing=True,
            )
            if data is None or data.get("sha") != tree_sha:
                raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_TREE_INVALID")
            entries = data.get("tree")
            if data.get("truncated") is not False or not isinstance(entries, list):
                raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_TREE_INVALID")
            matches = [
                entry
                for entry in entries
                if isinstance(entry, dict) and entry.get("path") == segment
            ]
            if len(matches) != 1:
                raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_TREE_MISMATCH")
            entry = matches[0]
            if entry.get("mode") == "120000":
                raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_SYMLINK_DENIED")
            entry_sha = entry.get("sha")
            if not isinstance(entry_sha, str) or not _BLOB_SHA.fullmatch(entry_sha):
                raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_TREE_INVALID")
            if index < len(segments) - 1:
                if entry.get("type") != "tree" or entry.get("mode") != "040000":
                    raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_TREE_MISMATCH")
                tree_sha = entry_sha
            elif (
                entry.get("type") != "blob"
                or entry.get("mode") not in {"100644", "100755"}
                or entry_sha.casefold() != blob_sha.casefold()
            ):
                raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_TREE_MISMATCH")

    async def _get_json(
        self, url: str, *, allow_missing: bool
    ) -> dict[str, object] | None:
        payload, _response = await self._get_json_with_response(
            url, allow_missing=allow_missing
        )
        return payload

    async def _get_json_with_response(
        self, url: str, *, allow_missing: bool
    ) -> tuple[dict[str, object] | None, HttpPolicyResponse | None]:
        try:
            pinned = pin_approved_https_request(
                url=url,
                allowed_hosts=frozenset({"api.github.com"}),
                resolver=self._resolver,
                timeout_seconds=_TIMEOUT_SECONDS,
                max_response_bytes=_MAX_RESPONSE_BYTES,
                headers={
                    "accept": "application/vnd.github+json",
                    "user-agent": "sastsimi-policy-discovery",
                    "x-github-api-version": "2022-11-28",
                },
            )
        except PolicySourceBoundaryError as error:
            raise _DiscoveryError("UNVERIFIED", str(error)) from error
        try:
            response = await asyncio.wait_for(
                self._transport.send(pinned), timeout=_TIMEOUT_SECONDS
            )
        except (
            TimeoutError,
            OSError,
            ssl.SSLError,
            http.client.HTTPException,
        ) as error:
            raise _DiscoveryError(
                "FETCH_FAILED", "POLICY_GITHUB_TRANSPORT_FAILED"
            ) from error
        if response.peer_ip != pinned.pinned_ip:
            raise _DiscoveryError("UNVERIFIED", "POLICY_SOURCE_DNS_REBINDING")
        if len(response.body) > _MAX_RESPONSE_BYTES:
            raise _DiscoveryError("FETCH_FAILED", "POLICY_GITHUB_RESPONSE_TOO_LARGE")
        if response.status == 404:
            if allow_missing:
                return None, response
            raise _DiscoveryError("UNVERIFIED", "POLICY_REPOSITORY_NOT_FOUND")
        if response.status in {301, 302, 303, 307, 308}:
            raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_REDIRECT_DENIED")
        if response.status != 200:
            raise _DiscoveryError(
                "FETCH_FAILED", f"POLICY_GITHUB_HTTP_{response.status}"
            )
        media_type = (_header(response, "content-type") or "").split(";", 1)[0]
        if media_type.casefold().strip() not in {
            "application/json",
            "application/vnd.github+json",
        }:
            raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_CONTENT_TYPE_INVALID")
        try:
            data = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _DiscoveryError(
                "FETCH_FAILED", "POLICY_GITHUB_JSON_INVALID"
            ) from error
        if not isinstance(data, dict):
            raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_JSON_SHAPE_INVALID")
        return data, response

    @staticmethod
    def _result(
        status: CollectionStatus,
        reason: str,
        checked_at: datetime,
        *,
        owner: str | None = None,
        repo: str | None = None,
    ) -> DiscoveredPolicy:
        return DiscoveredPolicy(
            status=status,
            reason_code=reason,
            owner=owner,
            repo=repo,
            publisher=None,
            source_url=None,
            source_path=None,
            blob_sha=None,
            etag=None,
            content_type=None,
            checked_at=checked_at,
            sha256=None,
            body=None,
        )


def _repository_identity(repository_url: str) -> tuple[str, str] | None:
    parsed = urlsplit(repository_url)
    if (
        parsed.scheme != "https"
        or parsed.netloc.casefold() != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        return None
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _OWNER.fullmatch(owner) or not _REPOSITORY.fullmatch(repo):
        return None
    if repo in {".", ".."} or repo.endswith("."):
        return None
    return owner, repo


def _decode_policy_file(data: dict[str, object], path: str) -> tuple[bytes, str]:
    blob_sha = data.get("sha")
    content = data.get("content")
    size = data.get("size")
    if (
        data.get("type") != "file"
        or data.get("path") != path
        or "target" in data
        or "submodule_git_url" in data
        or data.get("encoding") != "base64"
        or not isinstance(blob_sha, str)
        or not _BLOB_SHA.fullmatch(blob_sha)
        or not isinstance(content, str)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size > _MAX_RESPONSE_BYTES
    ):
        raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_FILE_INVALID")
    try:
        body = base64.b64decode("".join(content.split()), validate=True)
        text = body.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as error:
        raise _DiscoveryError(
            "UNVERIFIED", "POLICY_GITHUB_FILE_ENCODING_INVALID"
        ) from error
    if len(body) != size or not text.strip():
        raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_FILE_SIZE_INVALID")
    computed_blob = hashlib.sha1(b"blob " + str(size).encode() + b"\0" + body)
    if computed_blob.hexdigest() != blob_sha.casefold():
        raise _DiscoveryError("UNVERIFIED", "POLICY_GITHUB_BLOB_MISMATCH")
    return body, blob_sha


def _header(response: HttpPolicyResponse | None, name: str) -> str | None:
    if response is None:
        return None
    return next(
        (value for key, value in response.headers.items() if key.casefold() == name),
        None,
    )


__all__ = ["DiscoveredPolicy", "GitHubPolicyDiscovery"]
