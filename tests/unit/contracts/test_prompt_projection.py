import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_projection import (
    project_prompt_value,
    render_prompt_bytes,
)


def test_field_projection_contains_selected_values_only() -> None:
    source = {"statement": {"value": "untrusted text"}, "secret": "not selected"}
    expected = canonical_bytes({"$.statement.value": "untrusted text"})
    projected = project_prompt_value(source, ("$.statement.value",))
    assert projected == expected
    assert (
        render_prompt_bytes(b"trusted template", (("evidence", projected),))
        == b"trusted template\n[evidence]\n" + expected
    )
    with pytest.raises(ValueError, match="PROMPT_FIELD_PATH_INVALID"):
        project_prompt_value(source, ("$.absent",))
