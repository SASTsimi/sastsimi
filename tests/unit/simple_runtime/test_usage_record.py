import json

from sastsimi.providers.claude_subscription import _result_usage
from sastsimi.simple_runtime.usage import labelled, record_usage, summarize, usage_path


def test_a_run_records_each_call_under_its_stage(tmp_path):
    stream = b"\n".join(
        [
            b'{"type":"system","subtype":"init"}',
            json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "total_cost_usd": 0.5,
                    "usage": {
                        "input_tokens": 10,
                        "cache_read_input_tokens": 900,
                        "cache_creation_input_tokens": 100,
                        "output_tokens": 40,
                    },
                }
            ).encode(),
        ]
    )
    entry = _result_usage(stream)
    assert entry is not None and entry["cache_read_input_tokens"] == 900
    with labelled("PRO_CON_DONE", "hypothesis-1"):
        record_usage(tmp_path, "run-1", entry)
    record_usage(tmp_path, "run-1", entry)

    lines = usage_path(tmp_path, "run-1").read_text().splitlines()
    assert json.loads(lines[0])["stage"] == "PRO_CON_DONE"
    assert json.loads(lines[1])["stage"] is None
    summary = summarize(usage_path(tmp_path, "run-1"))
    assert summary["total"]["calls"] == 2
    assert summary["total"]["output_tokens"] == 80
    assert summary["stages"]["PRO_CON_DONE"]["total_cost_usd"] == 0.5
