"""Conservative interpretation of a completed PoC's bounded stdout claim."""

from __future__ import annotations

_DISPROOF_CLAIM_PREFIX = "SASTSIMI_POC_DISPROVED: "
_MAX_CLAIM_STDOUT_BYTES = 4096
_MAX_CLAIM_LINES = 64
_MAX_CLAIM_LINE_CHARS = 1024
_MAX_CLAIM_REASON_CHARS = 512


def exit_one_claim_interpreted_inconclusive(stdout: bytes, stderr: bytes) -> bool:
    """Recognize a clean exit-one disproof *claim*, not actual counterevidence.

    The caller must separately verify exit code 1, no timeout, and an exact
    Dynamic Reproduction Agent outcome of INCONCLUSIVE.  A marker in arbitrary
    tool output or a failed runtime is never enough to establish a verdict.
    """

    if stderr or not stdout or len(stdout) > _MAX_CLAIM_STDOUT_BYTES:
        return False
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError:
        return False
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        return False
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if not 1 <= len(lines) <= _MAX_CLAIM_LINES:
        return False
    if any(
        len(line) > _MAX_CLAIM_LINE_CHARS
        or not all(character.isprintable() for character in line)
        for line in lines
    ):
        return False
    if any(line.startswith(_DISPROOF_CLAIM_PREFIX) for line in lines[:-1]):
        return False
    terminal = lines[-1]
    if not terminal.startswith(_DISPROOF_CLAIM_PREFIX):
        return False
    reason = terminal[len(_DISPROOF_CLAIM_PREFIX) :]
    return (
        bool(reason)
        and len(reason) <= _MAX_CLAIM_REASON_CHARS
        and reason.strip() == reason
    )
