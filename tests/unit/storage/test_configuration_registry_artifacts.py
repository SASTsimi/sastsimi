from __future__ import annotations

from sastsimi.contracts.prompt_projection import project_prompt_value
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.storage.configuration_registry import _artifact_prompt_source_value


def test_artifact_prompt_source_reconstructs_the_redacted_wrapper() -> None:
    digest = "a" * 64
    source_ref = StoredDataRef.model_validate(
        dict(
            stored_data_id=digest,
            data_kind="artifact",
            content_hash=digest,
            workspace_id="workspace-1",
            commit_id="b" * 40,
            record_id=None,
        )
    )

    source = _artifact_prompt_source_value(
        source_ref,
        b"token = 'sk-0123456789abcdef'\nprint('safe')",
    )

    assert project_prompt_value(source, ("/redacted_body",)) == (
        b'{"/redacted_body":"[REDACTED:TOKEN]\\nprint(\'safe\')"}'
    )
