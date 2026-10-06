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
from urllib.parse import parse_qs, unquote, urlsplit

from .query import (
    DashboardBadRequest,
    DashboardIncomplete,
    DashboardNotFound,
    DashboardQuery,
)

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
                elif parts == ("api", "meta"):
                    self._json({"demo": False}, send_body)
                elif parts == ("api", "analyses"):
                    self._json(query.list_analyses(), send_body)
                elif (
                    len(parts) == 4
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "summary"
                ):
                    self._json(query.get_analysis_shell(parts[2]), send_body)
                elif (
                    len(parts) == 4
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "status-cells"
                ):
                    offset, limit = self._page(parsed.query, default_limit=100)
                    self._json(
                        query.list_status_cells(parts[2], offset=offset, limit=limit),
                        send_body,
                    )
                elif (
                    len(parts) == 5
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "tabs"
                ):
                    offset, limit = self._page(parsed.query, default_limit=50)
                    self._json(
                        query.get_analysis_tab(
                            parts[2], parts[4], offset=offset, limit=limit
                        ),
                        send_body,
                    )
                elif (
                    len(parts) == 5
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "llm"
                ):
                    self._json(query.get_llm_invocation(parts[2], parts[4]), send_body)
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
                    self._json(
                        {
                            "display_id": parts[4],
                            "markdown": query.report_markdown(parts[2], parts[4]),
                        },
                        send_body,
                    )
                elif (
                    len(parts) == 6
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "reports"
                    and parts[5] == "download"
                ):
                    self._download(
                        query.report_markdown(parts[2], parts[4]).encode("utf-8"),
                        "text/markdown; charset=utf-8",
                        f"{parts[4]}.md",
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
                    len(parts) == 6
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "groups"
                    and parts[5] == "bundle.zip"
                ):
                    self._download(
                        query.group_bundle_bytes(parts[2], parts[4]),
                        "application/zip",
                        f"{parts[4]}-group-bundle.zip",
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
                        frozenset(parameters.get("artifact", ())) if selected else None
                    )
                    report_ids = (
                        frozenset(parameters.get("report", ())) if selected else None
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
                    and parts[3] == "static-coverage"
                ):
                    parameters = parse_qs(parsed.query)
                    try:
                        kind = parameters.get("kind", ["gaps"])[0]
                        offset = int(parameters.get("offset", ["0"])[0])
                        limit = int(parameters.get("limit", ["100"])[0])
                        page = query.get_static_coverage_page(
                            parts[2], kind=kind, offset=offset, limit=limit
                        )
                    except ValueError:
                        self._response(
                            HTTPStatus.BAD_REQUEST,
                            b'{"error":"invalid_page"}',
                            "application/json; charset=utf-8",
                            send_body,
                        )
                    else:
                        self._json(page, send_body)
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
                elif (
                    len(parts) == 4
                    and parts[:2] == ("api", "analyses")
                    and parts[3] == "event-page"
                ):
                    offset, limit = self._page(parsed.query, default_limit=50)
                    self._json(
                        query.list_event_page(parts[2], offset=offset, limit=limit),
                        send_body,
                    )
                elif len(parts) == 3 and parts[0] == "reports":
                    if not parts[2].endswith(".md"):
                        raise DashboardNotFound("DASHBOARD_REPORT_NOT_FOUND")
                    self._response(
                        HTTPStatus.OK,
                        query.report_content(parts[1], parts[2][:-3]),
                        "text/markdown; charset=utf-8",
                        send_body,
                    )
                elif len(parts) >= 5 and parts[0] == "reports" and parts[3] == "files":
                    name = "/".join(parts[4:])
                    body, media_type = query.report_attachment(parts[1], parts[2], name)
                    self._response(
                        HTTPStatus.OK,
                        body,
                        media_type,
                        send_body,
                        content_disposition=(
                            f'attachment; filename="{name.rsplit("/", 1)[-1]}"'
                        ),
                    )
                elif (
                    len(parts) == 4
                    and parts[0] == "reports"
                    and parts[3] == "bundle.zip"
                ):
                    body, media_type = query.report_attachment(
                        parts[1], parts[2], "bundle.zip"
                    )
                    self._response(
                        HTTPStatus.OK,
                        body,
                        media_type,
                        send_body,
                        content_disposition='attachment; filename="bundle.zip"',
                    )
                else:
                    raise DashboardNotFound("DASHBOARD_ROUTE_NOT_FOUND")
            except DashboardBadRequest:
                self._response(
                    HTTPStatus.BAD_REQUEST,
                    b'{"error":"bad_request"}',
                    "application/json; charset=utf-8",
                    send_body,
                )
            except DashboardIncomplete:
                self._response(
                    HTTPStatus.CONFLICT,
                    b'{"error":"incomplete_export"}',
                    "application/json; charset=utf-8",
                    send_body,
                )
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

        @staticmethod
        def _page(query_string: str, *, default_limit: int) -> tuple[int, int]:
            parameters = parse_qs(query_string, keep_blank_values=True)
            if any(
                len(parameters.get(name, ())) != 1
                for name in ("offset", "limit")
                if name in parameters
            ):
                raise DashboardBadRequest("DASHBOARD_PAGE_INVALID")
            try:
                return (
                    int(parameters.get("offset", ["0"])[0]),
                    int(parameters.get("limit", [str(default_limit)])[0]),
                )
            except ValueError as error:
                raise DashboardBadRequest("DASHBOARD_PAGE_INVALID") from error

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
            content_disposition: str | None = None,
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
            if content_disposition is not None:
                self.send_header("Content-Disposition", content_disposition)
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
