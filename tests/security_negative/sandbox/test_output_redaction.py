import pytest

from sastsimi.sandbox.docker_adapter import DockerAdapter


def test_benign_sandbox_output_is_preserved() -> None:
    raw = b"relative/path.py: reproduction completed\n"

    assert DockerAdapter._safe_output(raw) == raw


def test_escaped_unc_repr_is_redacted_without_leaving_a_second_path() -> None:
    raw = br"stored_next='/protected?probe=\\\\fixture.invalid\\target'" + b"\n"

    assert DockerAdapter._safe_output(raw) == (
        br"stored_next='/protected?probe=[REDACTED:HOST_ABSOLUTE_PATH]'" + b"\n"
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"token=TEST_ONLY_TOKEN\n", b"[REDACTED:TOKEN]\n"),
        (
            b"Authorization: Bearer TEST_ONLY_BEARER\n",
            b"[REDACTED:CREDENTIAL]\n",
        ),
        (b"aws=AKIAIOSFODNN7EXAMPLE\n", b"aws=[REDACTED:TOKEN]\n"),
        (b"aws=ASIAIOSFODNN7EXAMPLE\n", b"aws=[REDACTED:TOKEN]\n"),
        (
            b"postgresql://user:TEST_ONLY_PASSWORD@example.test/db\n",
            b"[REDACTED:CREDENTIAL]\n",
        ),
        (b"-----BEGIN PRIVATE KEY-----\n", b"[REDACTED:CREDENTIAL]"),
        (
            b"C:\\Users\\synthetic\\secret.txt\n",
            b"[REDACTED:HOST_ABSOLUTE_PATH]\n",
        ),
        (b"/home/synthetic/secret.txt\n", b"[REDACTED:HOST_ABSOLUTE_PATH]\n"),
    ],
)
def test_sandbox_output_removes_credentials_and_host_paths(
    raw: bytes, expected: bytes
) -> None:
    first = DockerAdapter._safe_output(raw)
    second = DockerAdapter._safe_output(raw)

    assert first == second
    assert first == expected
    assert b"TEST_ONLY" not in first
    assert b"AKIAIOSFODNN7EXAMPLE" not in first
    assert b"ASIAIOSFODNN7EXAMPLE" not in first
    assert b"BEGIN PRIVATE KEY" not in first
    assert b"synthetic" not in first
