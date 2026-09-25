"""Keep this machine's locations out of quoted source, and nothing else.

Quoted source used to go through the prompt redactor, which was written for
data and reads ``token = ...`` as a credential assignment.  Over open-webui it
replaced 1,241 spans - ``client_secret=GOOGLE_CLIENT_SECRET.value`` became a
marker and ``if 'postgres://' in DATABASE_URL`` stopped being code - and the
authentication code where defects live was what it erased.  Narrowing the
patterns only moved the misses around: no set of patterns separates every
secret from every piece of code that handles one.

The repositories analysed are public: a secret committed to one is already
published, hiding it from the model protects nothing, and a hard-coded
credential is itself a defect the hypothesis agent has to be able to see.
What must not leave is where this machine keeps things, which belongs to the
operator rather than the project and is known exactly, so it is replaced by
value rather than by pattern.

Decision recorded for later: analysing a private repository changes the first
premise, and secret handling for quoted source must be decided again then.
"""

from __future__ import annotations

from pathlib import Path

_HOST_PATH_MARK = "[REDACTED:HOST_ABSOLUTE_PATH]"


def redact_code(
    text: str, *, host_paths: tuple[str, ...] = ()
) -> tuple[str, tuple[str, ...]]:
    """Return the code with this machine's paths replaced, and whether any were."""

    replaced = False
    for host_path in host_paths:
        if host_path and host_path in text:
            text = text.replace(host_path, _HOST_PATH_MARK)
            replaced = True
    return text, (("HOST_ABSOLUTE_PATH",) if replaced else ())


def default_host_paths(workspace: Path) -> tuple[str, ...]:
    """The locations on this machine a quoted file must not reveal.

    Longest first, so the checkout's own path is replaced whole before the
    home directory that contains it.
    """

    paths = {str(workspace.resolve()), str(Path.home())}
    kept = (path for path in paths if len(path) > 1)
    return tuple(sorted(kept, key=len, reverse=True))


__all__ = ["default_host_paths", "redact_code"]
