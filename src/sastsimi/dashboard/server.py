"""Standard-library, loopback-only, read-only dashboard server."""

from __future__ import annotations

import ipaddress
import json
import re
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from typing import Literal, cast
from urllib.parse import parse_qs, unquote, urlsplit

from .query import DashboardNotFound, DashboardQuery

_STATIC = Path(__file__).with_name("static")
_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def create_server(
    data_dir: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> ThreadingHTTPServer:
    if not _loopback(host):
        raise ValueError("DASHBOARD_LOOPBACK_ONLY")
    if not 0 <= port <= 65535:
        raise ValueError("DASHBOARD_PORT_INVALID")
    query = DashboardQuery(data_dir)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self._dispatch(send_body=True)

        def do_HEAD(self) -> None:  # noqa: N802
            self._dispatch(send_body=False)

        def do_POST(self) -> None:  # noqa: N802
            self._method_not_allowed()

        def do_PUT(self) -> None:  # noqa: N802
            self._method_not_allowed()

        def do_PATCH(self) -> None:  # noqa: N802
            self._method_not_allowed()

        def do_DELETE(self) -> None:  # noqa: N802
            self._method_not_allowed()

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _dispatch(self, *, send_body: bool) -> None:
            parsed = urlsplit(self.path)
            parts = tuple(unquote(part) for part in parsed.path.split("/") if part)
            try:
                if not parts:
                    self._file(
                        _STATIC / "index.html",
                        "text/html; charset=utf-8",
                        send_body,
                    )
                elif len(parts) == 2 and parts[0] == "analyses":
                    # Shareable deep links serve the same read-only application.
                    self._file(
                        _STATIC / "index.html",
                        "text/html; charset=utf-8",
                        send_body,
                    )
                elif parts == ("static", "app.css"):
                    self._file(
                        _STATIC / "app.css",
                        "text/css; charset=utf-8",
                        send_body,
                    )
                elif parts == ("static", "app.js"):
                    self._file(
                        _STATIC / "app.js",
                        "text/javascript; charset=utf-8",
                        send_body,
                    )
                elif parts == ("api", "analyses"):
                    self._json(query.list_analyses(), send_body)
                elif (
                    len(parts) == 5
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "artifacts"
                ):
                    if parse_qs(parsed.query).get("download") == ["1"]:
                        kind, media_type, body = query.artifact_bytes(
                            parts[2], parts[4]
                        )
                        suffix = ".json" if media_type == "application/json" else ".txt"
                        filename = re.sub(r"[^A-Za-z0-9_.-]", "-", kind)[:80]
                        self._download(
                            body,
                            media_type,
                            f"{filename or 'artifact'}-{parts[4][:12]}{suffix}",
                            send_body,
                        )
                    else:
                        self._json(
                            query.artifact_content(parts[2], parts[4]), send_body
                        )
                elif (
                    len(parts) == 5
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "reports"
                ):
                    language = parse_qs(parsed.query).get("lang", ["ko"])[0]
                    if language not in {"ko", "en"}:
                        raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
                    report_language = cast(Literal["ko", "en"], language)
                    self._json(
                        {
                            "display_id": parts[4],
                            "language": language,
                            "markdown": query.report_markdown(
                                parts[2], parts[4], language=report_language
                            ),
                        },
                        send_body,
                    )
                elif (
                    len(parts) == 6
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "reports"
                    and parts[5] == "download"
                ):
                    language = parse_qs(parsed.query).get("lang", ["ko"])[0]
                    if language not in {"ko", "en"}:
                        raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
                    report_language = cast(Literal["ko", "en"], language)
                    self._download(
                        query.report_markdown(
                            parts[2], parts[4], language=report_language
                        ).encode("utf-8"),
                        "text/markdown; charset=utf-8",
                        f"{parts[4]}{'.en' if language == 'en' else ''}.md",
                        send_body,
                    )
                elif (
                    len(parts) == 5
                    and parts[:2] == ("api", "analyses")
                    and parts[3:] == ("logs", "download")
                ):
                    self._download(
                        query.logs_bytes(parts[2]),
                        "application/x-ndjson; charset=utf-8",
                        f"{parts[2]}-console.log",
                        send_body,
                    )
                elif (
                    len(parts) == 4
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "presentation.zip"
                ):
                    buffer = BytesIO()
                    with zipfile.ZipFile(
                        buffer, "w", compression=zipfile.ZIP_DEFLATED
                    ) as archive:
                        for name, body in query.presentation_bundle_members(
                            parts[2]
                        ).items():
                            archive.writestr(name, body)
                    self._download(
                        buffer.getvalue(),
                        "application/zip",
                        f"{parts[2]}-presentation.zip",
                        send_body,
                    )
                elif (
                    len(parts) == 4
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "bundle.zip"
                ):
                    parameters = parse_qs(parsed.query)
                    selected = parameters.get("selected") == ["1"]
                    artifact_ids = (
                        frozenset(parameters.get("artifact", ()))
                        if selected
                        else None
                    )
                    report_ids = (
                        frozenset(parameters.get("report", ()))
                        if selected
                        else None
                    )
                    buffer = BytesIO()
                    with zipfile.ZipFile(
                        buffer, "w", compression=zipfile.ZIP_DEFLATED
                    ) as archive:
                        for name, body in query.bundle_members(
                            parts[2],
                            artifact_ids=artifact_ids,
                            report_ids=report_ids,
                            include_logs=(
                                not selected or parameters.get("logs") == ["1"]
                            ),
                        ).items():
                            archive.writestr(name, body)
                    self._download(
                        buffer.getvalue(),
                        "application/zip",
                        f"{parts[2]}-results.zip",
                        send_body,
                    )
                elif len(parts) == 3 and parts[:2] == ("api", "analyses"):
                    self._json(query.get_analysis(parts[2]), send_body)
                elif (
                    len(parts) == 4
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "events"
                ):
                    after = parse_qs(parsed.query).get("after", [None])[0]
                    self._json(
                        query.list_events(parts[2], after_event_id=after),
                        send_body,
                    )
                elif len(parts) == 3 and parts[0] == "reports":
                    if not parts[2].endswith(".md"):
                        raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
                    english = parts[2].endswith(".en.md")
                    display_id = parts[2][:-6] if english else parts[2][:-3]
                    self._file(
                        query.report_path(
                            parts[1],
                            display_id,
                            language="en" if english else "ko",
                        ),
                        "text/markdown; charset=utf-8",
                        send_body,
                    )
                else:
                    raise DashboardNotFound("DASHBOARD_ROUTE_NOT_FOUND")
            except DashboardNotFound:
                self._response(
                    HTTPStatus.NOT_FOUND,
                    b'{"error":"not_found"}',
                    "application/json; charset=utf-8",
                    send_body,
                )
            except (OSError, ValueError, json.JSONDecodeError):
                self._response(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    b'{"error":"unavailable"}',
                    "application/json; charset=utf-8",
                    send_body,
                )

        def _json(self, value: object, send_body: bool) -> None:
            payload: object
            if isinstance(value, tuple):
                payload = [
                    item.model_dump(mode="json")
                    if hasattr(item, "model_dump")
                    else item
                    for item in value
                ]
            elif hasattr(value, "model_dump"):
                payload = value.model_dump(mode="json")
            else:
                payload = value
            body = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            self._response(
                HTTPStatus.OK,
                body,
                "application/json; charset=utf-8",
                send_body,
            )

        def _file(self, path: Path, content_type: str, send_body: bool) -> None:
            try:
                body = path.read_bytes()
            except OSError as error:
                raise DashboardNotFound("DASHBOARD_FILE_NOT_FOUND") from error
            self._response(HTTPStatus.OK, body, content_type, send_body)

        def _download(
            self,
            body: bytes,
            content_type: str,
            filename: str,
            send_body: bool,
        ) -> None:
            safe_name = re.sub(r"[^A-Za-z0-9_.-]", "-", filename)
            self._response(
                HTTPStatus.OK,
                body,
                content_type,
                send_body,
                extra_headers={
                    "Content-Disposition": f'attachment; filename="{safe_name}"'
                },
            )

        def _method_not_allowed(self) -> None:
            self._response(
                HTTPStatus.METHOD_NOT_ALLOWED,
                b'{"error":"read_only"}',
                "application/json; charset=utf-8",
                True,
            )

        def _response(
            self,
            status: HTTPStatus,
            body: bytes,
            content_type: str,
            send_body: bool,
            *,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", _CSP)
            self.send_header("Referrer-Policy", "no-referrer")
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if send_body:
                self.wfile.write(body)

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def serve_dashboard(
    data_dir: str | Path,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> None:
    server = create_server(data_dir, host=host, port=port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


__all__ = ["create_server", "serve_dashboard"]
