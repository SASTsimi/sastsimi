"""Only explicit fields can be overridden by operational sources."""

from collections.abc import Mapping

OVERRIDE_FIELDS = frozenset(
    {
        "log_level",
        "output_format",
        "data_dir",
        "setup_reasoning_effort",
        "setup_agent_reasoning_efforts",
    }
)
ENV_FIELDS = {
    "SASTSIMI_LOG_LEVEL": "log_level",
    "SASTSIMI_OUTPUT_FORMAT": "output_format",
    "SASTSIMI_DATA_DIR": "data_dir",
    "SASTSIMI_REASONING_EFFORT": "setup_reasoning_effort",
    "SASTSIMI_AGENT_REASONING_EFFORTS": "setup_agent_reasoning_efforts",
}


def merge_sources(*sources: Mapping[str, object]) -> dict[str, object]:
    merged: dict[str, object] = {}
    for source in sources:
        merged.update(source)
    return merged
