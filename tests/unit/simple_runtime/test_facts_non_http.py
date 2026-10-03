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


_FLASK = '''
from flask import request


@bp.route("/mailboxes", methods=["POST"])
def create_mailbox():
    email = request.get_json().get("email")
    return create(email)


@bp.route("/ping")
def ping():
    return "ok"
'''


def test_imported_request_object_is_a_taint_source(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(_FLASK, encoding="utf-8")

    result = extract_flows(tmp_path, ["views.py"])

    by_handler = {entry["handler"]: entry for entry in result["entry_points"]}
    created = by_handler["create_mailbox"]
    assert created["global_inputs"] == ["request"]
    assert "create" in [step["call"] for step in created["steps"]]
    assert "global_inputs" not in by_handler["ping"]
    assert by_handler["ping"]["steps"] == []


_GUARDED = '''
from flask import request


def require_api_auth(f):
    """Only a signed-in user with an API key may call."""
    return f


@bp.route("/aliases")
@require_api_auth
@cache.cached(timeout=5)
def get_aliases():
    return request.args.get("page")


class AdminOnly:
    def has_permission(self, user):
        return user.is_admin


class Panel:
    permission_classes = [AdminOnly]

    @bp.route("/panel")
    def show(self):
        return "ok"
'''


def test_guards_are_attached_with_their_definitions(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(_GUARDED, encoding="utf-8")

    result = extract_flows(tmp_path, ["views.py"])

    by_handler = {entry["handler"]: entry for entry in result["entry_points"]}
    names = [guard["name"] for guard in by_handler["get_aliases"]["guards"]]
    assert names == ["require_api_auth"]
    assert [g["name"] for g in by_handler["show"]["guards"]] == ["AdminOnly"]
    definitions = result["guard_definitions"]
    key = by_handler["get_aliases"]["guards"][0]["defined_at"][0]
    assert "def require_api_auth" in definitions[key]
    admin = by_handler["show"]["guards"][0]["defined_at"][0]
    assert "is_admin" in definitions[admin]
