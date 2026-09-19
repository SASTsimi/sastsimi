"""SystemClock must survive a real backward wall-clock jump.

This host's guest clock is Hyper-V-synced and has been observed jumping
backward mid-run (see `runtime/system_support.py`'s docstring). Every new
record revision stamps `created_at` from this clock, and
`contracts/records.py::validate_revision` requires each revision's
`created_at` to be strictly after its predecessor's - a real backward jump
between two `now()` calls on the same clock instance would otherwise abort
whatever work is claiming that revision.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from sastsimi.runtime.system_support import SystemClock


def test_now_never_goes_backward_across_a_real_clock_correction() -> None:
    clock = SystemClock()
    first = clock.now()

    with patch(
        "sastsimi.runtime.system_support.datetime"
    ) as patched_datetime:
        patched_datetime.now.return_value = first - timedelta(seconds=30)
        second = clock.now()

    assert second > first


def test_now_keeps_tracking_real_time_once_it_advances_again() -> None:
    clock = SystemClock()
    first = clock.now()

    with patch(
        "sastsimi.runtime.system_support.datetime"
    ) as patched_datetime:
        patched_datetime.now.return_value = first - timedelta(seconds=30)
        clock.now()
        recovered = first + timedelta(seconds=60)
        patched_datetime.now.return_value = recovered
        third = clock.now()

    assert third == recovered


def test_now_is_strictly_increasing_across_consecutive_calls() -> None:
    clock = SystemClock()
    values = [clock.now() for _ in range(50)]

    assert values == sorted(values)
    assert len(set(values)) == len(values)


def test_now_reports_real_time_under_normal_conditions() -> None:
    clock = SystemClock()
    before = datetime.now(UTC)

    observed = clock.now()

    after = datetime.now(UTC)
    assert before <= observed <= after
