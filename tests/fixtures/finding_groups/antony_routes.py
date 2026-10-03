from flask import request
import os


@app.route('/ping', methods=['GET'])
def ping():
    target = request.args.get('target')
    os.system(f'ping -c 1 {target}')


@app.route('/upload', methods=['POST'])
def upload():
    filename = request.form.get('filename')
    print(filename)
