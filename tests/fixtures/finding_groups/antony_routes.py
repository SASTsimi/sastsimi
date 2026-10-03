import os

from flask import Flask, request  # type: ignore[import-not-found]

app = Flask(__name__)


@app.route("/ping", methods=["GET"])  # type: ignore[untyped-decorator]
def ping() -> None:
    target = request.args.get("target")
    os.system(f"ping -c 1 {target}")


@app.route("/upload", methods=["POST"])  # type: ignore[untyped-decorator]
def upload() -> None:
    filename = request.form.get("filename")
    print(filename)
