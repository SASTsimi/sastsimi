"""Process outcomes, independent of vulnerability verdicts."""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    INPUT_ERROR = 2
    CONFIG_ERROR = 3
    CAPABILITY_UNSUPPORTED = 4
    REPORT_UNAVAILABLE = 5
    INTERNAL_ERROR = 10
