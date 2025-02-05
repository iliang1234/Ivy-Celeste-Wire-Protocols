from flask import Flask, send_from_directory, render_template_string
import configparser
import os
from pathlib import Path

app = Flask(__name__)

from ..config import load_config

@app.route('/')
def index():
    websocket_config = load_config('websocket')
    with open(os.path.join(app.static_folder, 'index.html'), 'r') as f:
        content = f.read()
    return render_template_string(content, websocket_url=websocket_config['url'])

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

@app.route('/config')
def get_config():
    websocket_config = load_config('websocket')
    return {'websocket_url': websocket_config['url']}

if __name__ == '__main__':
    client_config = load_config('client')
    app.run(host=client_config['host'], port=client_config['port'])
