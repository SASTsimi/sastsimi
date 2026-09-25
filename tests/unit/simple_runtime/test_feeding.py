"""The hypothesis agent is fed the whole checkout; nothing is chosen for it."""

from __future__ import annotations

from pathlib import Path

from sastsimi.simple_runtime.feeding import plan_feeding, render_batch


def _repo(tmp_path: Path, files: dict[str, str]) -> tuple[Path, tuple[str, ...]]:
    root = tmp_path / "repo"
    for name, body in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return root, tuple(files)


def test_every_source_file_is_fed_exactly_once(tmp_path: Path) -> None:
    files = {f"pkg{index % 3}/m{index}.py": "x = 1\n" * 400 for index in range(30)}
    files["README.md"] = "not source\n"
    root, tracked = _repo(tmp_path, files)

    feeding = plan_feeding(root, tracked, batch_bytes=6_000)

    fed = [path for batch in feeding.batches for path in batch.paths]
    assert sorted(fed) == sorted(name for name in files if name.endswith(".py"))
    assert len(fed) == len(set(fed))
    assert len(feeding.batches) > 1


def test_a_module_is_read_together(tmp_path: Path) -> None:
    root, tracked = _repo(
        tmp_path,
        {
            "a/one.py": "x = 1\n",
            "a/two.py": "y = 2\n",
            "b/three.py": "z = 3\n",
        },
    )

    feeding = plan_feeding(root, tracked)

    assert [batch.paths for batch in feeding.batches] == [
        ("a/one.py", "a/two.py", "b/three.py")
    ]


def test_the_logic_survives_and_the_commentary_does_not(tmp_path: Path) -> None:
    root, tracked = _repo(
        tmp_path,
        {
            "proxy.py": (
                "def sanitize(path):\n"
                '    """Decode until stable."""\n'
                "    # a comment the agent does not need\n"
                "    for _ in range(8):\n"
                "        path = unquote(path)\n"
                "    return path\n"
            )
        },
    )

    text = render_batch(plan_feeding(root, tracked).batches[0])

    assert "for _ in range(8):" in text
    assert "Decode until stable" not in text
    assert "a comment" not in text


def test_generated_output_is_left_out_and_named(tmp_path: Path) -> None:
    root, tracked = _repo(
        tmp_path,
        {
            "app.py": "x = 1\n",
            "static/bundle.js": "var a=1;" * 400,
        },
    )

    feeding = plan_feeding(root, tracked)

    assert feeding.excluded == [
        {"path": "static/bundle.js", "reason": "GENERATED_OR_MINIFIED"}
    ]
    assert feeding.coverage()["fed_files"] == 1


def test_a_committed_secret_reaches_the_agent_but_this_machine_does_not(
    tmp_path: Path,
) -> None:
    root, tracked = _repo(
        tmp_path, {"settings.py": 'API_KEY = "sk-live-abcdefgh1234"\n'}
    )
    (root / "paths.py").write_text(f"HOME = '{Path.home()}/x'\n", encoding="utf-8")

    feeding = plan_feeding(root, (*tracked, "paths.py"))

    text = render_batch(feeding.batches[0])
    assert "sk-live-abcdefgh1234" in text
    assert str(Path.home()) not in text


def test_the_map_names_every_definition(tmp_path: Path) -> None:
    root, tracked = _repo(
        tmp_path,
        {"api.py": "class Router:\n    def proxy(self, path):\n        pass\n"},
    )

    feeding = plan_feeding(root, tracked)

    assert "class Router" in feeding.signature_map
    assert "def proxy(self, path)" in feeding.signature_map
