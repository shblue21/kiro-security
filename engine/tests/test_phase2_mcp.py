import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

from kiro_security.errors import WorkbenchError
from kiro_security.models import WorkspaceSetup
from kiro_security.workbench import Workbench


TEST_SERVER_KEY = "ksp_aaaaaaaaaaaaaaaaaaaa"


class McpClient:
    def __init__(self, state_root, scan_root, session_id="kiro-chat-a"):
        self.state_root = Path(state_root)
        self.session_id = session_id
        self.session_hash = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        self.bridge_path = (
            self.state_root
            / "runtime"
            / "hook-bridge"
            / "kiro_security_hook_bridge.py"
        )
        self.bridge_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            Path(__file__).resolve().parents[2]
            / "hook"
            / "kiro_security_hook_bridge.py",
            self.bridge_path,
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(
            Path(__file__).resolve().parents[1]
        )
        environment["PYTHONIOENCODING"] = "utf-8"
        environment["PYTHONUNBUFFERED"] = "1"
        environment["KIRO_SECURITY_STATE_ROOT"] = str(state_root)
        environment["KIRO_SECURITY_SCAN_ROOT"] = str(scan_root)
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-B",
                "-S",
                "-m",
                "kiro_security.mcp_server",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=environment,
        )
        self.next_id = 1
        self.environment = environment

    def request(self, method, params=None):
        request_id = self.next_id
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)
        assert self.process.stdout is not None
        raw = self.process.stdout.readline()
        if not raw:
            assert self.process.stderr is not None
            raise AssertionError(
                "MCP server exited without a response: %s"
                % self.process.stderr.read()
            )
        response = json.loads(raw)
        if response.get("id") != request_id:
            raise AssertionError("MCP response ID mismatch")
        return response

    def notify(self, method, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def issue_attestation(self, name, arguments=None):
        attested = dict(arguments or {})
        attested["requestNonce"] = str(uuid.uuid4())
        payload = {
            "session_id": self.session_id,
            "hook_event_name": "PreToolUse",
            "cwd": str(self.state_root),
            "tool_name": self.direct_tool_id(name),
            "tool_input": attested,
        }
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(self.bridge_path),
                "--server-key",
                TEST_SERVER_KEY,
            ],
            check=False,
            capture_output=True,
            input=json.dumps(payload),
            text=True,
            encoding="utf-8",
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr)
        return attested

    @staticmethod
    def direct_tool_id(name):
        return "mcp_%s_%s" % (TEST_SERVER_KEY, name)

    def call_tool_raw(self, name, arguments):
        response = self.request(
            "tools/call",
            {"name": name, "arguments": arguments},
        )
        return response["result"]

    def call_tool(self, name, arguments=None):
        return self.call_tool_raw(
            name,
            self.issue_attestation(name, arguments),
        )

    def close(self):
        if self.process.stdin is not None:
            self.process.stdin.close()
        self.process.wait(timeout=5)
        if self.process.returncode != 0:
            assert self.process.stderr is not None
            error = self.process.stderr.read()
            self.process.stdout.close()
            self.process.stderr.close()
            raise AssertionError(error)
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        self.process.stdout.close()
        self.process.stderr.close()

    def _send(self, message):
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(message, separators=(",", ":")) + "\n"
        )
        self.process.stdin.flush()


class PhaseTwoMcpTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.target = self.base / "repository"
        self.state_root = self.base / "global-storage"
        self.scan_root = self.base / "scan-artifacts"
        self.target.mkdir()
        self._git("init")
        self._git("config", "user.email", "tests@example.invalid")
        self._git("config", "user.name", "Kiro Security Tests")
        (self.target / "app.py").write_text("print('safe')\n", encoding="utf-8")
        self._git("add", "app.py")
        self._git("commit", "-m", "initial")

    def tearDown(self):
        self.temporary.cleanup()

    def test_stdio_mcp_direct_continuation_and_shared_database(self):
        client = McpClient(self.state_root, self.scan_root)
        try:
            initialized = client.request(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1"},
                },
            )
            self.assertEqual(
                initialized["result"]["protocolVersion"],
                "2025-11-25",
            )
            self.assertIn("tools", initialized["result"]["capabilities"])
            client.notify("notifications/initialized")

            listed = client.request("tools/list", {})
            tool_names = {
                tool["name"] for tool in listed["result"]["tools"]
            }
            self.assertEqual(
                tool_names,
                {
                    "kiro_security_get_capabilities",
                    "kiro_security_create_workspace",
                    "kiro_security_get_workspace",
                    "kiro_security_save_workspace",
                    "kiro_security_start_scan",
                    "kiro_security_get_scan_context",
                    "kiro_security_update_scan_progress",
                    "kiro_security_get_artifact_contract",
                    "kiro_security_read_scan_artifact",
                    "kiro_security_write_scan_artifact",
                    "kiro_security_complete_scan",
                    "kiro_security_export_scan",
                    "kiro_security_claim_scan_recovery",
                    "kiro_security_release_scan_recovery",
                    "kiro_security_claim_remediation",
                    "kiro_security_get_remediation",
                    "kiro_security_set_remediation",
                    "kiro_security_release_remediation",
                    "kiro_security_claim_tracking",
                    "kiro_security_get_tracking",
                    "kiro_security_fail_scan",
                    "kiro_security_cancel_scan",
                },
            )
            for tool in listed["result"]["tools"]:
                self.assertIn("requestNonce", tool["inputSchema"]["required"])
            tools_by_name = {
                tool["name"]: tool for tool in listed["result"]["tools"]
            }
            self.assertEqual(
                set(
                    tools_by_name["kiro_security_start_scan"]["inputSchema"][
                        "required"
                    ]
                ),
                {
                    "requestNonce",
                    "sessionId",
                    "setupRevision",
                    "setupDigest",
                    "setup",
                },
            )
            self.assertTrue(
                tools_by_name["kiro_security_fail_scan"]["annotations"][
                    "destructiveHint"
                ]
            )
            self.assertTrue(
                tools_by_name["kiro_security_cancel_scan"]["annotations"][
                    "destructiveHint"
                ]
            )
            self.assertNotIn(
                "destructiveHint",
                tools_by_name["kiro_security_update_scan_progress"]["annotations"],
            )
            self.assertTrue(
                tools_by_name["kiro_security_read_scan_artifact"]["annotations"][
                    "readOnlyHint"
                ]
            )
            self.assertEqual(
                set(
                    tools_by_name["kiro_security_read_scan_artifact"][
                        "inputSchema"
                    ]["required"]
                ),
                {"requestNonce", "scanId", "descriptor", "expectedDigest"},
            )
            self.assertEqual(
                set(
                    tools_by_name["kiro_security_write_scan_artifact"][
                        "inputSchema"
                    ]["required"]
                ),
                {"requestNonce", "scanId", "descriptor", "contentJson"},
            )

            capabilities = client.call_tool(
                "kiro_security_get_capabilities"
            )
            self.assertFalse(capabilities.get("isError", False))
            self.assertEqual(
                capabilities["structuredContent"]["stateRoot"],
                str(self.state_root.resolve()),
            )
            self.assertTrue(
                capabilities["structuredContent"]["semanticWorkflowsAvailable"]
            )
            self.assertEqual(
                capabilities["structuredContent"]["semanticAnalysisOwner"],
                "kiro_agent_steering",
            )

            created = client.call_tool(
                "kiro_security_create_workspace",
                {},
            )["structuredContent"]
            self.assertFalse(created["setup"]["submitted"])
            session_id = created["id"]

            saved = client.call_tool(
                "kiro_security_save_workspace",
                {
                    "sessionId": session_id,
                    "setup": {
                        "targetPath": str(self.target),
                        "mode": "standard",
                        "scope": ".",
                        "userContext": "MCP integration test",
                    },
                },
            )["structuredContent"]
            self.assertTrue(saved["setup"]["submitted"])

            started = client.call_tool(
                "kiro_security_start_scan",
                {
                    "sessionId": session_id,
                    "setupRevision": saved["setupRevision"],
                    "setupDigest": saved["setupDigest"],
                    "setup": saved["setup"]["value"],
                },
            )["structuredContent"]
            scan_id = started["scanId"]
            self.assertFalse(started["reused"])

            context = client.call_tool(
                "kiro_security_get_scan_context",
                {"scanId": scan_id},
            )["structuredContent"]
            self.assertEqual(context["scan"]["status"], "running")
            self.assertEqual(
                context["scan"]["target"]["path"],
                str(self.target.resolve()),
            )
            self.assertEqual(context["workspaceId"], session_id)

            contract = client.call_tool(
                "kiro_security_get_artifact_contract",
                {"scanId": scan_id},
            )["structuredContent"]
            self.assertEqual(contract["phaseContract"]["phase"], "preflight")
            self.assertFalse(contract["phaseContract"]["readAhead"])
            self.assertEqual(set(contract["descriptorSchemas"]), {"brief"})
            self.assertNotIn("validation", json.dumps(contract["phaseContract"]))
            brief_write = client.call_tool(
                "kiro_security_write_scan_artifact",
                {
                    "scanId": scan_id,
                    "descriptor": "brief",
                    "contentJson": json.dumps(
                        {
                            "scanId": scan_id,
                            "mode": "standard",
                            "target": str(self.target),
                            "scope": ".",
                        }
                    ),
                },
            )["structuredContent"]
            client.call_tool(
                "kiro_security_update_scan_progress",
                {"scanId": scan_id, "phase": "threat_model"},
            )
            brief_read = client.call_tool(
                "kiro_security_read_scan_artifact",
                {
                    "scanId": scan_id,
                    "descriptor": "brief",
                    "expectedDigest": brief_write["artifact"]["digest"],
                },
            )["structuredContent"]
            self.assertEqual(brief_read["content"]["scanId"], scan_id)
            self.assertEqual(
                brief_read["artifact"]["digest"],
                brief_write["artifact"]["digest"],
            )
            self.assertNotIn("path", brief_read["artifact"])
            rejected_path = client.call_tool(
                "kiro_security_read_scan_artifact",
                {
                    "scanId": scan_id,
                    "descriptor": "brief",
                    "expectedDigest": brief_write["artifact"]["digest"],
                    "path": "/tmp/not-accepted",
                },
            )
            self.assertTrue(rejected_path["isError"])
            self.assertEqual(
                rejected_path["structuredContent"]["error"]["code"],
                "invalid_arguments",
            )
            client.call_tool(
                "kiro_security_write_scan_artifact",
                {
                    "scanId": scan_id,
                    "descriptor": "threat-model",
                    "contentJson": json.dumps(
                        {
                            "scanId": scan_id,
                            "summary": "MCP integration threat model.",
                        }
                    ),
                },
            )
            progress = client.call_tool(
                "kiro_security_update_scan_progress",
                {
                    "scanId": scan_id,
                    "phase": "discovery",
                    "reviewItemsTotal": 2,
                    "reviewItemsCompleted": 1,
                },
            )["structuredContent"]
            self.assertEqual(progress["progress"]["reviewItemsCompleted"], 1)

            regressed = client.call_tool(
                "kiro_security_update_scan_progress",
                {"scanId": scan_id, "reviewItemsCompleted": 0},
            )
            self.assertTrue(regressed["isError"])
            self.assertEqual(
                regressed["structuredContent"]["error"]["code"],
                "progress_regression",
            )

            client.call_tool(
                "kiro_security_update_scan_progress",
                {"scanId": scan_id, "reviewItemsCompleted": 2},
            )
            discovery_write = client.call_tool(
                "kiro_security_write_scan_artifact",
                {
                    "scanId": scan_id,
                    "descriptor": "discovery",
                    "contentJson": json.dumps(
                        {"scanId": scan_id, "candidates": []}
                    ),
                },
            )["structuredContent"]
            discovery_read = client.call_tool(
                "kiro_security_read_scan_artifact",
                {
                    "scanId": scan_id,
                    "descriptor": "discovery",
                    "expectedDigest": discovery_write["artifact"]["digest"],
                },
            )["structuredContent"]
            self.assertEqual(discovery_read["content"]["candidates"], [])
            later = client.call_tool(
                "kiro_security_update_scan_progress",
                {"scanId": scan_id, "phase": "validation"},
            )["structuredContent"]
            self.assertEqual(later["phase"], "validation")

            failed = client.call_tool(
                "kiro_security_fail_scan",
                {
                    "scanId": scan_id,
                    "failureMessage": "semantic workflows are not installed",
                },
            )["structuredContent"]
            self.assertEqual(failed["status"], "failed")

            direct = Workbench(str(self.state_root), str(self.scan_root))
            shared = direct.get_scan_context(
                scan_id,
                owner_session_hash=client.session_hash,
            )
            self.assertEqual(shared["scan"]["status"], "failed")
            self.assertEqual(shared["workspace"]["activeScanId"], scan_id)
        finally:
            client.close()

    def test_mcp_reports_tool_and_protocol_errors_without_crashing(self):
        client = McpClient(self.state_root, self.scan_root)
        try:
            before_initialize = client.request("tools/list", {})
            self.assertEqual(before_initialize["error"]["code"], -32002)
            client.request(
                "initialize",
                {
                    "protocolVersion": "unknown-version",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1"},
                },
            )
            client.notify("notifications/initialized")

            unknown = client.request(
                "tools/call",
                {"name": "not_a_tool", "arguments": {}},
            )
            self.assertEqual(unknown["error"]["code"], -32602)

            invalid = client.call_tool(
                "kiro_security_get_workspace",
                {"sessionId": "not-a-uuid"},
            )
            self.assertTrue(invalid["isError"])
            self.assertEqual(
                invalid["structuredContent"]["error"]["code"],
                "invalid_workspace_id",
            )
        finally:
            client.close()

    def test_attestation_is_one_time_argument_bound_and_chat_owned(self):
        first = McpClient(self.state_root, self.scan_root, "kiro-chat-first")
        second = None
        try:
            first.request(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "first-chat", "version": "1"},
                },
            )
            first.notify("notifications/initialized")
            created = first.call_tool(
                "kiro_security_create_workspace",
                {},
            )["structuredContent"]

            connection = sqlite3.connect(str(self.state_root / "workbench.sqlite3"))
            try:
                stored_owner = connection.execute(
                    "SELECT owner_session_hash FROM workspaces WHERE id = ?",
                    (created["id"],),
                ).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(stored_owner, first.session_hash)
            self.assertNotEqual(stored_owner, first.session_id)

            replay_arguments = first.issue_attestation(
                "kiro_security_get_workspace",
                {"sessionId": created["id"]},
            )
            accepted = first.call_tool_raw(
                "kiro_security_get_workspace",
                replay_arguments,
            )
            self.assertFalse(accepted.get("isError", False))
            replayed = first.call_tool_raw(
                "kiro_security_get_workspace",
                replay_arguments,
            )
            self.assertEqual(
                replayed["structuredContent"]["error"]["code"],
                "chat_attestation_invalid",
            )

            mismatched_arguments = first.issue_attestation(
                "kiro_security_get_workspace",
                {"sessionId": created["id"]},
            )
            mismatched_arguments["sessionId"] = str(uuid.uuid4())
            mismatched = first.call_tool_raw(
                "kiro_security_get_workspace",
                mismatched_arguments,
            )
            self.assertEqual(
                mismatched["structuredContent"]["error"]["code"],
                "chat_attestation_invalid",
            )

            expired_arguments = first.issue_attestation(
                "kiro_security_get_capabilities",
                {},
            )
            connection = sqlite3.connect(str(self.state_root / "workbench.sqlite3"))
            try:
                connection.execute(
                    "UPDATE chat_attestations SET expires_at = 0 WHERE nonce = ?",
                    (expired_arguments["requestNonce"],),
                )
                connection.commit()
            finally:
                connection.close()
            expired = first.call_tool_raw(
                "kiro_security_get_capabilities",
                expired_arguments,
            )
            self.assertEqual(
                expired["structuredContent"]["error"]["code"],
                "chat_attestation_invalid",
            )

            unattested = first.call_tool_raw(
                "kiro_security_get_capabilities",
                {"requestNonce": str(uuid.uuid4())},
            )
            self.assertEqual(
                unattested["structuredContent"]["error"]["code"],
                "chat_attestation_invalid",
            )

            second = McpClient(
                self.state_root,
                self.scan_root,
                "kiro-chat-second",
            )
            second.request(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "second-chat", "version": "1"},
                },
            )
            second.notify("notifications/initialized")
            denied = second.call_tool(
                "kiro_security_get_workspace",
                {"sessionId": created["id"]},
            )
            self.assertEqual(
                denied["structuredContent"]["error"]["code"],
                "workspace_not_owned",
            )
        finally:
            if second is not None:
                second.close()
            first.close()

    def test_deep_progress_can_reset_only_when_pass_advances(self):
        workbench = Workbench(str(self.state_root), str(self.scan_root))
        owner_session_hash = hashlib.sha256(b"deep-chat").hexdigest()
        created = workbench.create_workspace(
            owner_session_hash=owner_session_hash,
        )
        saved = workbench.update_workspace_setup(
            created["id"],
            WorkspaceSetup(
                target_path=str(self.target),
                mode="deep",
                scope=".",
            ),
            owner_session_hash=owner_session_hash,
        )
        started = workbench.start_scan(
            saved["id"],
            expected_setup_revision=saved["setupRevision"],
            expected_setup_digest=saved["setupDigest"],
            approved_setup=WorkspaceSetup(
                target_path=saved["setup"]["value"]["targetPath"],
                mode=saved["setup"]["value"]["mode"],
                scope=saved["setup"]["value"]["scope"],
                user_context=saved["setup"]["value"]["userContext"],
            ),
            owner_session_hash=owner_session_hash,
        )
        scan_id = started["scanId"]

        workbench.write_scan_artifact(
            scan_id,
            "brief",
            {
                "scanId": scan_id,
                "mode": "deep",
                "target": str(self.target),
                "scope": ".",
                "worklist": [{"id": "app-source", "path": "app.py"}],
            },
            owner_session_hash=owner_session_hash,
        )
        first = workbench.update_scan_progress(
            scan_id,
            phase="discovery",
            review_items_total=3,
            review_items_completed=3,
            deep_review_pass=1,
            owner_session_hash=owner_session_hash,
        )
        self.assertEqual(first["progress"]["deepReviewPass"], 1)
        second = workbench.update_scan_progress(
            scan_id,
            review_items_total=2,
            review_items_completed=0,
            deep_review_pass=2,
            owner_session_hash=owner_session_hash,
        )
        self.assertEqual(second["progress"]["reviewItemsCompleted"], 0)

        with self.assertRaises(WorkbenchError) as raised:
            workbench.update_scan_progress(
                scan_id,
                review_items_total=1,
                deep_review_pass=2,
                owner_session_hash=owner_session_hash,
            )
        self.assertEqual(raised.exception.code, "progress_regression")

        with self.assertRaises(WorkbenchError) as raised:
            workbench.update_scan_progress(
                scan_id,
                deep_review_pass=1,
                owner_session_hash=owner_session_hash,
            )
        self.assertEqual(raised.exception.code, "progress_regression")

    def _git(self, *arguments):
        subprocess.run(
            ["git", "-C", str(self.target), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
