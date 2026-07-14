from flask import Flask, request
import os
import sqlite3
import zipfile

app = Flask(__name__)

@app.get('/run')
def run_command():
    command = request.args.get('command')
    os.system(command)
    return 'ok'

@app.get('/users')
def user_lookup():
    user_id = request.args.get('id')
    connection = sqlite3.connect('app.db')
    return list(connection.execute(f"SELECT * FROM users WHERE id = {user_id}"))

@app.post('/extract')
def extract_archive():
    archive_path = request.form.get('archive')
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall('/srv/uploads')
    return 'ok'

@app.route('/admin/users', methods=['DELETE'])
def delete_user():
    return {'deleted': True}
