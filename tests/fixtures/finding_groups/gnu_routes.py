from flask import request
import subprocess


@app.route('/rce_vuln', methods=['POST'])
def rce_vuln():
    data = request.get_json(silent=True) or {}
    cmd = data.get('cmd', '')
    if not cmd:
        return {'error': 'missing cmd'}
    try:
        proc = subprocess.run(cmd, shell=True)
    except Exception:
        pass
    return proc
