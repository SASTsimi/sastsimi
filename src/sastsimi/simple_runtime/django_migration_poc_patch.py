"""Pure one-line repair for a proven Django migration PoC fixture error."""

from __future__ import annotations

import re

from .django_migration_graph_omission import (
    _candidate_omits,
    django_migration_settings_replay_forbidden,
)
from .django_relation_settings_omission import _python_tree

_CONFIGURE_LINE = re.compile(
    rb"(?m)^([ \t]*)settings\.configure\(\*\*settings_values\)[ \t]*(\r?\n)"
)
_FLAG = re.compile(r"[A-Z][A-Z_0-9]*")


def insert_pinned_django_migration_false_override(
    content: bytes, flag: str
) -> bytes | None:
    """Insert one default-off flag only when the stored PoC proves omission.

    The caller must separately establish the pinned project-source evidence.
    This function never reads or writes a file and returns ``None`` on doubt.
    """

    if _FLAG.fullmatch(flag) is None:
        return None
    tree = _python_tree(content)
    if tree is None or not _candidate_omits(tree, flag):
        return None
    matches = list(_CONFIGURE_LINE.finditer(content))
    if len(matches) != 1:
        return None
    match = matches[0]
    override = (
        match.group(1)
        + b"settings_values['"
        + flag.encode("ascii")
        + b"'] = False"
        + match.group(2)
    )
    patched = content[: match.start()] + override + content[match.start() :]
    if django_migration_settings_replay_forbidden(patched, flag):
        return None
    return patched


__all__ = ["insert_pinned_django_migration_false_override"]
