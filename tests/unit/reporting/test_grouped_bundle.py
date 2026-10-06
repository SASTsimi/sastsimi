"""Only compatible, already-verified members yield a group review draft."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.reporting.grouped_bundle import (
    GroupBundleUnavailable,
    GroupSourceBundle,
    build_group_bundle,
)

_FACTS = {
    "analysis_id": "analysis-1",
    "repository": "https://github.com/example/repo",
    "tested_commit": "a" * 40,
    "cwe": "CWE-78",
    "ecosystem": "pip",
    "package_name": "example-repo",
    "affected_versions": "<= 1.0",
    "patched_versions": None,
    "severity": "High",
    "technical_status": "ACCEPT",
    "scope_status": "IN_SCOPE",
    "report_permission": "ALLOW",
}


def _member(display_id: str, **changed: object) -> GroupSourceBundle:
    provenance = {
        **_FACTS,
        **changed,
        "display_id": display_id,
        "poc": {"path": "poc.py"},
    }
    return GroupSourceBundle(
        display_id=display_id,
        files={
            "report_en.md": f"# Finding {display_id}\n".encode(),
            "report_kr.md": f"# 결과 {display_id}\n".encode(),
            "poc.py": f"print({display_id!r})\n".encode(),
            "evidence/provenance.json": canonical_bytes(provenance),
            "evidence/stdout.txt": b"reproduced\n",
        },
        provenance=provenance,
    )


def test_compatible_member_bundle_preserves_each_original_and_is_deterministic() -> (
    None
):
    first, second = _member("F-001"), _member("F-002")
    forward = build_group_bundle("a" * 64, [second, first])
    assert forward == build_group_bundle("a" * 64, [first, second])
    with zipfile.ZipFile(io.BytesIO(forward)) as archive:
        names = archive.namelist()
        assert names[:3] == [
            "report_en.md",
            "report_kr.md",
            "evidence/group-manifest.json",
        ]
        assert archive.read("members/F-001/poc.py") == first.files["poc.py"]
        assert archive.read("members/F-002/evidence/stdout.txt") == b"reproduced\n"
        assert archive.read("report_en.md").startswith(b"# Finding F-001\n")
        assert "F-001" in archive.read("report_kr.md").decode()
        manifest = json.loads(archive.read("evidence/group-manifest.json"))
        assert manifest["group_id"] == "a" * 64
        assert manifest["member_ids"] == ["F-001", "F-002"]
        assert (
            manifest["members"][1]["files"]["poc.py"]
            == hashlib.sha256(second.files["poc.py"]).hexdigest()
        )


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"severity": "Low"}, "GROUP_FACT_CONFLICT"),
        ({"scope_status": "OUT_OF_SCOPE"}, "GROUP_FACT_CONFLICT"),
        ({"patched_versions": "2.0"}, "GROUP_FACT_CONFLICT"),
        ({"affected_versions": None}, "GROUP_FACT_MISSING"),
    ],
)
def test_conflicting_or_missing_facts_refuse_group_export(
    change: dict[str, object], code: str
) -> None:
    with pytest.raises(GroupBundleUnavailable) as error:
        build_group_bundle("a" * 64, [_member("F-001"), _member("F-002", **change)])
    assert error.value.code == code


@pytest.mark.parametrize("missing", ["report_en.md", "report_kr.md", "poc.py"])
def test_missing_member_report_or_poc_refuses_partial_archive(missing: str) -> None:
    second = _member("F-002")
    files = dict(second.files)
    files.pop(missing)
    with pytest.raises(GroupBundleUnavailable, match="GROUP_MEMBER_FILE_MISSING"):
        build_group_bundle(
            "a" * 64,
            [_member("F-001"), GroupSourceBundle("F-002", files, second.provenance)],
        )


def test_unsafe_member_path_or_local_url_is_rejected() -> None:
    second = _member("F-002")
    files = dict(second.files)
    files["../outside.txt"] = b"private"
    with pytest.raises(GroupBundleUnavailable, match="GROUP_MEMBER_PATH_UNSAFE"):
        build_group_bundle(
            "a" * 64,
            [_member("F-001"), GroupSourceBundle("F-002", files, second.provenance)],
        )
    files = dict(second.files)
    files["report_en.md"] = b"file:///C:/Users/private/secret.txt"
    with pytest.raises(GroupBundleUnavailable, match="GROUP_MEMBER_CONTENT_UNSAFE"):
        build_group_bundle(
            "a" * 64,
            [_member("F-001"), GroupSourceBundle("F-002", files, second.provenance)],
        )


def test_size_overflow_refuses_group_export() -> None:
    second = _member("F-002")
    files = dict(second.files)
    files["evidence/stdout.txt"] = b"x" * (1024 * 1024 + 1)
    with pytest.raises(GroupBundleUnavailable, match="GROUP_MEMBER_FILE_TOO_LARGE"):
        build_group_bundle(
            "a" * 64,
            [_member("F-001"), GroupSourceBundle("F-002", files, second.provenance)],
        )


def test_singleton_or_duplicate_member_is_not_an_exportable_group() -> None:
    with pytest.raises(GroupBundleUnavailable, match="GROUP_MEMBERS_INVALID"):
        build_group_bundle("a" * 64, [_member("F-001")])
    with pytest.raises(GroupBundleUnavailable, match="GROUP_MEMBERS_INVALID"):
        build_group_bundle("a" * 64, [_member("F-001"), _member("F-001")])
