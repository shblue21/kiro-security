from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from kiro_security.constants import PROTOCOL_VERSION


def read_json(process: subprocess.Popen[str]) -> dict:
    line = process.stdout.readline()
    assert line, process.stderr.read()
    return json.loads(line)


def test_rpc_server_rejects_malformed_input_and_version_mismatch(workspace: Path) -> None:
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1]), "PYTHONUNBUFFERED": "1"}
    process = subprocess.Popen(
        ["python3", "-m", "kiro_security.server", "--workspace", str(workspace), "--client-kind", "test"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=workspace,
        env=env,
    )
    assert process.stdin and process.stdout and process.stderr
    try:
        ready = read_json(process)
        assert ready["method"] == "engine.ready"
        process.stdin.write("{not-json}\n")
        process.stdin.flush()
        assert read_json(process)["error"]["code"] == -32700
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "protocolVersion": "0.9", "id": 1, "method": "initialize", "params": {"protocolVersion": "0.9", "clientInfo": {"name": "test"}}}) + "\n")
        process.stdin.flush()
        mismatch = read_json(process)
        assert mismatch["error"]["data"]["engineCode"] == "protocol_version_mismatch"
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "protocolVersion": PROTOCOL_VERSION, "id": 2, "method": "initialize", "params": {"protocolVersion": PROTOCOL_VERSION, "clientInfo": {"name": "test"}}}) + "\n")
        process.stdin.flush()
        assert read_json(process)["result"]["protocolVersion"] == PROTOCOL_VERSION
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "protocolVersion": PROTOCOL_VERSION, "id": 3, "method": "shutdown", "params": {}}) + "\n")
        process.stdin.flush()
        assert read_json(process)["result"]["releasedCoordinatorLeaseScanIds"] == []
    finally:
        try:
            process.stdin.close()
        except Exception:
            pass
        process.wait(timeout=10)
