import subprocess

from flask import Flask, request  # type: ignore[import-not-found]

app = Flask(__name__)


@app.route("/rce_vuln", methods=["POST"])  # type: ignore[untyped-decorator]
def rce_vuln() -> object:
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd", "")
    if not cmd:
        return {"error": "missing cmd"}
    try:
        proc = subprocess.run(cmd, shell=True)
    except Exception:
        pass
    return proc
