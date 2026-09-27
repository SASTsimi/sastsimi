import pytest

from sastsimi.simple_runtime.cvss import base_score, severity, vector


def _metrics(text: str) -> dict[str, str]:
    return dict(part.split(":") for part in text.split("/"))


@pytest.mark.parametrize(
    ("metrics", "score"),
    [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 5.3),
        ("AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4),
        ("AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_base_score_follows_the_specification(metrics: str, score: float) -> None:
    assert base_score(_metrics(metrics)) == score


def test_vector_and_severity() -> None:
    chosen = _metrics("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N")
    assert vector(chosen) == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
    assert severity(base_score(chosen)) == "Medium"
