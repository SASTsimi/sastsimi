from pathlib import Path

from flask import Flask, Response, request

app = Flask(__name__)
ALLOWED_FILES_DIR = Path(__file__).parent / "allowed-files"


@app.get("/file")
def read_file() -> Response:
    requested_path = request.args.get("path", "")

    # Deliberately vulnerable fixture: the requested path is used without
    # checking that the resolved path remains inside ALLOWED_FILES_DIR.
    resolved_path = (ALLOWED_FILES_DIR / requested_path).resolve()
    content = resolved_path.read_text(encoding="utf-8").strip()
    return Response(content, mimetype="text/plain")
