from __future__ import annotations

from pathlib import Path

from sastsimi.simple_runtime.facts import extract_flows

_SOURCE = '''
class MailHandler:
    async def handle_DATA(self, server, session, envelope):
        return handle(envelope)

    async def handle_other(self, server, session, envelope):
        return None


class Plain:
    def data_received(self, data):
        return data


class Echo(asyncio.Protocol):
    def data_received(self, data):
        return data


@shared_task
def sync_job(account_id):
    return account_id


@celery.task(bind=True)
def other_job(self, payload):
    return payload


def handle(envelope):
    return envelope
'''


def test_mail_socket_and_task_entry_points_are_found(tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text(_SOURCE, encoding="utf-8")

    result = extract_flows(tmp_path, ["service.py"])

    found = {
        (entry["handler"], entry["routes"][0]["methods"][0])
        for entry in result["entry_points"]
    }
    assert found == {
        ("handle_DATA", "SMTP"),
        ("data_received", "SOCKET"),
        ("sync_job", "TASK"),
        ("other_job", "TASK"),
    }
    socket_owners = [
        entry["routes"][0]["router"]
        for entry in result["entry_points"]
        if entry["routes"][0]["methods"][0] == "SOCKET"
    ]
    assert socket_owners == ["Echo"]
