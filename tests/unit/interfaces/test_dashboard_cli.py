from __future__ import annotations

from sastsimi.interfaces.cli import dashboard as dashboard_command
from sastsimi.interfaces.cli.main import main


def test_dashboard_cli_starts_loopback_server(monkeypatch, tmp_path) -> None:
    called = {}

    def fake(data_dir, host, port):
        called.update(data_dir=data_dir, host=host, port=port)

    monkeypatch.setattr(dashboard_command, "serve_dashboard", fake)

    assert main(["--data-dir", str(tmp_path), "dashboard"]) == 0
    assert called == {
        "data_dir": tmp_path,
        "host": "127.0.0.1",
        "port": 8765,
    }


def test_dashboard_cli_rejects_external_host(tmp_path) -> None:
    assert (
        main(
            [
                "--data-dir",
                str(tmp_path),
                "dashboard",
                "--host",
                "0.0.0.0",
            ]
        )
        != 0
    )


def test_dashboard_cli_demo_mode_does_not_use_production_data(
    monkeypatch, tmp_path
) -> None:
    called = {}

    def fake(data_dir, host, port, *, demo=False):
        called.update(data_dir=data_dir, host=host, port=port, demo=demo)

    monkeypatch.setattr(dashboard_command, "serve_dashboard", fake)
    assert main(["--data-dir", str(tmp_path), "dashboard", "--demo"]) == 0
    assert called == {
        "data_dir": tmp_path,
        "host": "127.0.0.1",
        "port": 8765,
        "demo": True,
    }
    assert list(tmp_path.iterdir()) == []


# mypy: disable-error-code="no-untyped-def,var-annotated"
