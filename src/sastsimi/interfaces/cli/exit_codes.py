"""Process outcomes, independent of vulnerability verdicts."""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    INPUT_ERROR = 2
    CONFIG_ERROR = 3
    CAPABILITY_UNSUPPORTED = 4
    BLOCKED = 5
    REPORT_UNAVAILABLE = 5
    RUN_FAILED = 6
    RUN_CANCELLED = 7
    RESULT_INCOMPLETE = 8
    INTEGRITY_ERROR = 9
    INTERNAL_ERROR = 10
