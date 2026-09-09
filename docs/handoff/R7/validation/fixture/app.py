from pathlib import Path

from flask import Flask, Response, request

app = Flask(__name__)
REPORTS_DIR = Path(__file__).parent / "reports"


@app.get("/report")
def read_report() -> Response:
    requested_name = request.args.get("name", "")

    # Deliberately vulnerable fixture: the requested name is used without
    # checking that the resolved path remains inside REPORTS_DIR.
    resolved_path = (REPORTS_DIR / requested_name).resolve()
    content = resolved_path.read_text(encoding="utf-8").strip()
    return Response(content, mimetype="text/plain")
