from pathlib import Path
import sqlite3
import subprocess

ROOT = Path('/srv/uploads').resolve()

def safe_lookup(user_id: str):
    connection = sqlite3.connect('app.db')
    return connection.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchall()

def safe_read(name: str):
    candidate = (ROOT / name).resolve()
    if not candidate.is_relative_to(ROOT):
        raise ValueError('outside root')
    return candidate.read_text()

def safe_command(name: str):
    if name not in {'status', 'version'}:
        raise ValueError('unsupported')
    return subprocess.run(['/usr/local/bin/tool', name], shell=False, check=True)
