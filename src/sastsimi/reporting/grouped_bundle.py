"""Deterministic, fail-closed review ZIP for independently verified reports."""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import (
    assert_safe_provider_text,
    contains_local_file_url,
    sandbox_file_urls_only,
)
from sastsimi.reporting.bilingual_bundle import is_safe_sandbox_shell_poc

MAX_GROUP_MEMBER_FILE_BYTES = 1024 * 1024
MAX_GROUP_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
MAX_GROUP_MEMBERS = 1024
_GROUP_ID = re.compile(r"[0-9a-f]{64}\Z")
_DISPLAY_ID = re.compile(r"F-[0-9]{3,}\Z")
_PATHS = (
    "report_en.md",
    "report_kr.md",
    "poc.sh",
    "poc.py",
    "evidence/provenance.json",
    "evidence/stdout.txt",
    "evidence/stderr.txt",
)
_COMMON_FACTS = (
    "analysis_id",
    "repository",
    "tested_commit",
    "cwe",
    "ecosystem",
    "package_name",
    "affected_versions",
    "patched_versions",
    "severity",
    "technical_status",
    "scope_status",
    "report_permission",
)
_REQUIRED_FACTS = frozenset(_COMMON_FACTS) - {"patched_versions"}


class GroupBundleUnavailable(ValueError):
    """A stable reason for withholding this group's submission draft."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GroupSourceBundle:
    display_id: str
    files: Mapping[str, bytes]
    provenance: Mapping[str, object]


def _check_member(member: GroupSourceBundle) -> dict[str, str]:
    paths = set(member.files)
    if not paths <= set(_PATHS):
        raise GroupBundleUnavailable("GROUP_MEMBER_PATH_UNSAFE")
    if not {"report_en.md", "report_kr.md", "evidence/provenance.json"} <= paths or (
        ("poc.sh" in paths) == ("poc.py" in paths)
    ):
        raise GroupBundleUnavailable("GROUP_MEMBER_FILE_MISSING")
    if member.provenance.get("display_id") != member.display_id:
        raise GroupBundleUnavailable("GROUP_PROVENANCE_MISMATCH")
    try:
        if (
            canonical_bytes(member.provenance)
            != member.files["evidence/provenance.json"]
        ):
            raise GroupBundleUnavailable("GROUP_PROVENANCE_MISMATCH")
        declared = json.loads(member.files["evidence/provenance.json"])
    except (ValueError, TypeError, UnicodeError) as error:
        raise GroupBundleUnavailable("GROUP_PROVENANCE_MISMATCH") from error
    if not isinstance(declared, dict):
        raise GroupBundleUnavailable("GROUP_PROVENANCE_MISMATCH")
    poc = declared.get("poc")
    if not isinstance(poc, dict) or poc.get("path") not in paths:
        raise GroupBundleUnavailable("GROUP_PROVENANCE_MISMATCH")
    hashes: dict[str, str] = {}
    for path in _PATHS:
        if path not in member.files:
            continue
        body = member.files[path]
        if not isinstance(body, bytes):
            raise GroupBundleUnavailable("GROUP_MEMBER_CONTENT_UNSAFE")
        if len(body) > MAX_GROUP_MEMBER_FILE_BYTES:
            raise GroupBundleUnavailable("GROUP_MEMBER_FILE_TOO_LARGE")
        try:
            if contains_local_file_url(body) and not (
                path
                in {
                    "poc.sh",
                    "evidence/provenance.json",
                    "evidence/stdout.txt",
                    "evidence/stderr.txt",
                }
                and sandbox_file_urls_only(body)
            ):
                raise ValueError("local file URL")
            if path != "poc.sh" or not is_safe_sandbox_shell_poc(body):
                assert_safe_provider_text(body)
        except ValueError as error:
            raise GroupBundleUnavailable("GROUP_MEMBER_CONTENT_UNSAFE") from error
        hashes[path] = hashlib.sha256(body).hexdigest()
    return hashes


def _zip_file(path: str, body: bytes, archive: zipfile.ZipFile) -> None:
    info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o600 << 16
    archive.writestr(info, body)


def build_group_bundle(group_id: str, members: Sequence[GroupSourceBundle]) -> bytes:
    """Return one review draft; never infer facts or discard a member's bytes."""

    if _GROUP_ID.fullmatch(group_id) is None:
        raise GroupBundleUnavailable("GROUP_ID_INVALID")
    ordered = sorted(
        members,
        key=lambda member: (
            int(member.display_id[2:])
            if _DISPLAY_ID.fullmatch(member.display_id)
            else -1
        ),
    )
    ids = [member.display_id for member in ordered]
    if (
        not 2 <= len(ids) <= MAX_GROUP_MEMBERS
        or any(_DISPLAY_ID.fullmatch(value) is None for value in ids)
        or len(set(ids)) != len(ids)
    ):
        raise GroupBundleUnavailable("GROUP_MEMBERS_INVALID")
    representative = ordered[0]
    base_facts = {key: representative.provenance.get(key) for key in _COMMON_FACTS}
    manifest_members: list[dict[str, object]] = []
    total = 0
    for member in ordered:
        facts = {key: member.provenance.get(key) for key in _COMMON_FACTS}
        if any(
            not isinstance(facts[key], str) or not facts[key] for key in _REQUIRED_FACTS
        ):
            raise GroupBundleUnavailable("GROUP_FACT_MISSING")
        if facts != base_facts:
            raise GroupBundleUnavailable("GROUP_FACT_CONFLICT")
        hashes = _check_member(member)
        total += sum(len(body) for body in member.files.values())
        if total > MAX_GROUP_UNCOMPRESSED_BYTES:
            raise GroupBundleUnavailable("GROUP_TOO_LARGE")
        manifest_members.append({"display_id": member.display_id, "files": hashes})
    ids_text = ", ".join(f"`{value}`" for value in ids)
    suffix_en = (
        "\n\n## Verified group membership\n\n"
        f"- Group ID: `{group_id}`\n"
        f"- Original Findings: {ids_text}\n"
        "- This draft uses the first Finding's verified claims. Review each original "
        "report, PoC and evidence before private disclosure. Grouping is not "
        "reporting permission.\n"
    ).encode()
    suffix_kr = (
        "\n\n## 검증된 그룹 구성\n\n"
        f"- 그룹 ID: `{group_id}`\n"
        f"- 원본 Finding: {ids_text}\n"
        "- 이 초안은 첫 번째 Finding의 검증된 주장만 사용합니다. 비공개 제보 전 "
        "모든 원본 보고서·PoC·근거를 검토하세요. "
        "그룹화가 제보 허가를 뜻하지는 않습니다.\n"
    ).encode()
    manifest = canonical_bytes(
        {
            "schema_version": 1,
            "group_id": group_id,
            "representative_id": representative.display_id,
            "member_ids": ids,
            "members": manifest_members,
            "common_facts": base_facts,
            "human_review_required": True,
        }
    )
    top = (
        (
            "report_en.md",
            representative.files["report_en.md"].rstrip(b"\n") + suffix_en,
        ),
        (
            "report_kr.md",
            representative.files["report_kr.md"].rstrip(b"\n") + suffix_kr,
        ),
        ("evidence/group-manifest.json", manifest),
    )
    total += sum(len(body) for _, body in top)
    if total > MAX_GROUP_UNCOMPRESSED_BYTES:
        raise GroupBundleUnavailable("GROUP_TOO_LARGE")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, body in top:
            _zip_file(path, body, archive)
        for member in ordered:
            for path in _PATHS:
                if path in member.files:
                    _zip_file(
                        f"members/{member.display_id}/{path}",
                        member.files[path],
                        archive,
                    )
    return output.getvalue()
