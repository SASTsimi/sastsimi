"""Every tool finding reaches the bundle; none is cut at a count.

OpenGrep and CodeQL results were both cut at 500 with nothing recorded, so a
large repository lost findings silently - the one kind of loss that cannot be
traced afterwards.
"""

from __future__ import annotations

import json
from pathlib import Path

from sastsimi.simple_runtime.bootstrap_stages import DirectStaticBootstrap


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n" * 900, encoding="utf-8")
    return root


def test_every_opengrep_result_is_kept(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    raw = json.dumps(
        {
            "results": [
                {
                    "check_id": f"rule-{index}",
                    "path": "app.py",
                    "start": {"line": index + 1},
                }
                for index in range(800)
            ]
        }
    ).encode()

    findings = DirectStaticBootstrap._opengrep_snippets(root, raw)

    assert len(findings) == 800


def test_every_codeql_result_is_kept(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    raw = json.dumps(
        {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "py/path-injection",
                            "message": {"text": "m" * 3_000},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": index + 1},
                                    }
                                }
                            ],
                        }
                        for index in range(800)
                    ]
                }
            ]
        }
    ).encode()

    findings = DirectStaticBootstrap._codeql_findings(root, raw)

    assert len(findings) == 800
    # The message is kept whole too.
    assert len(str(findings[0]["message"])) == 3_000
