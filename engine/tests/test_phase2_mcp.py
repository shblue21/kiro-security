import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from kiro_security.errors import WorkbenchError
from kiro_security.models import WorkspaceSetup
from kiro_security.workbench import Workbench


class McpClient:
    def __init__(self, state_root, scan_root):
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

    def call_tool(self, name, arguments=None):
        response = self.request(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
        )
        return response["result"]

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
                    "kiro_security_fail_scan",
                    "kiro_security_cancel_scan",
                },
            )

            capabilities = client.call_tool(
                "kiro_security_get_capabilities"
            )
            self.assertFalse(capabilities.get("isError", False))
            self.assertEqual(
                capabilities["structuredContent"]["stateRoot"],
                str(self.state_root.resolve()),
            )
            self.assertFalse(
                capabilities["structuredContent"]["semanticWorkflowsAvailable"]
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
                {"sessionId": session_id},
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
            shared = direct.get_scan_context(scan_id)
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

    def test_deep_progress_can_reset_only_when_pass_advances(self):
        workbench = Workbench(str(self.state_root), str(self.scan_root))
        created = workbench.create_workspace()
        saved = workbench.update_workspace_setup(
            created["id"],
            WorkspaceSetup(
                target_path=str(self.target),
                mode="deep",
                scope=".",
            ),
        )
        started = workbench.start_scan(saved["id"])
        scan_id = started["scanId"]

        first = workbench.update_scan_progress(
            scan_id,
            phase="discovery",
            review_items_total=3,
            review_items_completed=3,
            deep_review_pass=1,
        )
        self.assertEqual(first["progress"]["deepReviewPass"], 1)
        second = workbench.update_scan_progress(
            scan_id,
            review_items_total=2,
            review_items_completed=0,
            deep_review_pass=2,
        )
        self.assertEqual(second["progress"]["reviewItemsCompleted"], 0)

        with self.assertRaises(WorkbenchError) as raised:
            workbench.update_scan_progress(
                scan_id,
                review_items_total=1,
                deep_review_pass=2,
            )
        self.assertEqual(raised.exception.code, "progress_regression")

        with self.assertRaises(WorkbenchError) as raised:
            workbench.update_scan_progress(scan_id, deep_review_pass=1)
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
