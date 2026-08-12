"""Python runtime floor and phase-contract authority checks."""

import ast
import inspect
import sys
import textwrap
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "engine"))

from kiro_security.phase_contracts import build_phase_contract  # noqa: E402
from kiro_security.scan_lifecycle import ScanLifecycleService  # noqa: E402
from kiro_security.semantic_contract import DEEP_WORKERS_PER_ROUND  # noqa: E402


class RuntimeContractTests(unittest.TestCase):
    def test_all_runtime_sources_parse_as_python_3_9(self):
        paths = list((REPOSITORY_ROOT / "engine").rglob("*.py"))
        paths.extend((REPOSITORY_ROOT / "hook").rglob("*.py"))
        for path in sorted(paths):
            source = path.read_text(encoding="utf-8")
            try:
                ast.parse(source, filename=str(path), feature_version=(3, 9))
            except SyntaxError as exc:
                self.fail("%s is not Python 3.9 compatible: %s" % (path, exc))

    def test_phase_contracts_preserve_complete_current_phase_rules(self):
        self.assertEqual(DEEP_WORKERS_PER_ROUND, 4)

        def contract(phase, mode="standard"):
            return build_phase_contract(
                {
                    "id": "scan-contract-test",
                    "status": "running",
                    "mode": mode,
                    "phase": phase,
                },
                (),
            )

        preflight = str(contract("preflight"))
        self.assertIn("blocked when a blocking requirement is absent", preflight)
        self.assertIn("incomplete when a required fact", preflight)
        self.assertIn("ready only when", preflight)
        self.assertNotIn("impact=high", preflight)

        threat_model = str(contract("threat_model"))
        self.assertIn("repository or authoritative target as a whole", threat_model)
        self.assertIn("sole source of truth", threat_model)
        self.assertNotIn("full-file receipt", threat_model)

        standard = str(contract("discovery"))
        self.assertIn("tightly coupled shard of at most five files", standard)
        self.assertIn("immutable pool plan of at most six slots", standard)
        self.assertIn("candidate totals are not reportable findings", standard)
        self.assertIn("Never describe that path as exhaustive coverage", standard)
        self.assertNotIn("impact=high", standard)

        diff = str(contract("discovery", mode="diff"))
        self.assertIn("Anchor every candidate to changed behavior", diff)
        self.assertIn("Do not broaden into a repository-wide audit", diff)
        self.assertNotIn("four usable outputs", diff)

        deep = str(contract("discovery", mode="deep"))
        self.assertIn("exactly four usable workers", deep)
        self.assertIn("Retry or replace only the failed or missing worker slot", deep)
        self.assertIn("latest checkpoint with expectedDigest CAS", deep)
        self.assertIn("kiro_security_read_scan_artifact", deep)
        self.assertIn("checkpoints never contribute to lineage", deep)
        self.assertIn("cannot produce four usable outputs", deep)
        self.assertIn("Never shrink the round", deep)
        self.assertNotIn("impact=high", deep)

        validation = str(contract("validation"))
        self.assertIn(
            "crashing PoC; Valgrind or ASan; non-interactive debugger trace; "
            "focused unit or integration test; realistic-interface reproduction; "
            "source-based static trace",
            validation,
        )
        self.assertIn("strongest counterevidence", validation)
        self.assertIn("every expanded child instance exactly once inside", validation)
        self.assertIn("stable instanceId", validation)
        self.assertIn("provisional UI telemetry", validation)
        self.assertNotIn("critical -> P0", validation)

        attack_path = str(contract("attack_path"))
        self.assertIn("Apply hard suppression before the matrix", attack_path)
        self.assertIn(
            "impact=high with likelihood high -> critical only when", attack_path
        )
        self.assertIn(
            "Matrix row impact=unknown: likelihood high -> medium; medium -> low; "
            "low -> ignore; ignore -> ignore; unknown -> low",
            attack_path,
        )
        self.assertIn("critical -> P0, high -> P1, medium -> P2", attack_path)
        self.assertIn("Never assign priority to ignore", attack_path)
        self.assertIn("instanceId sets exactly match validation", attack_path)
        self.assertNotIn("new dedicated worker", attack_path)

        reporting = str(contract("reporting"))
        self.assertIn("exactly one dedicated writeup worker", reporting)
        self.assertIn("new dedicated worker", reporting)
        self.assertIn("retry once", reporting)
        self.assertIn("leave reporting unclosed", reporting)
        self.assertIn("exactly one collection-wide", reporting)
        self.assertIn("report.md exists", reporting)
        self.assertIn("scan remains incomplete", reporting)
        self.assertIn("extensions.candidateId", reporting)
        self.assertIn("extensions.candidateInstanceId", reporting)
        self.assertNotIn("Matrix row impact=unknown", reporting)

    def test_lifecycle_lock_and_transaction_order_is_explicit(self):
        def function(method):
            source = textwrap.dedent(inspect.getsource(method))
            return ast.parse(source).body[0]

        def call_name(call):
            value = call.func
            parts = []
            while isinstance(value, ast.Attribute):
                parts.append(value.attr)
                value = value.value
            if isinstance(value, ast.Name):
                parts.append(value.id)
            return ".".join(reversed(parts))

        def calls(node, suffix):
            return [
                child
                for child in ast.walk(node)
                if isinstance(child, ast.Call)
                and call_name(child).endswith(suffix)
            ]

        def with_context(function_node, suffix):
            matches = []
            for node in ast.walk(function_node):
                if not isinstance(node, ast.With):
                    continue
                if any(
                    calls(item.context_expr, suffix)
                    for item in node.items
                ):
                    matches.append(node)
            self.assertEqual(len(matches), 1)
            return matches[0]

        start = function(ScanLifecycleService.start_scan)
        start_transaction = with_context(start, "immediate_transaction")
        target_revalidation = calls(start_transaction, "require_target")
        self.assertEqual(len(target_revalidation), 1)
        scan_inserts = [
            call
            for call in calls(start_transaction, "execute")
            if call.args
            and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str)
            and "INSERT INTO scans" in call.args[0].value
        ]
        self.assertEqual(len(scan_inserts), 1)
        self.assertLess(target_revalidation[0].lineno, scan_inserts[0].lineno)

        progress = function(ScanLifecycleService.update_scan_progress)
        progress_lock = with_context(progress, "owned_scan_lock")
        progress_transactions = [
            node
            for node in ast.walk(progress_lock)
            if isinstance(node, ast.With)
            and any(
                calls(item.context_expr, "immediate_transaction")
                for item in node.items
            )
        ]
        self.assertEqual(len(progress_transactions), 1)
        self.assertEqual(
            len(calls(progress_transactions[0], "require_phase_exit")),
            1,
        )

        completion = function(ScanLifecycleService.complete_scan)
        completion_lock = with_context(completion, "owned_scan_lock")
        seals = calls(completion_lock, "has_sealed_manifest")
        publish_transactions = [
            node
            for node in ast.walk(completion_lock)
            if isinstance(node, ast.With)
            and any(
                calls(item.context_expr, "immediate_transaction")
                for item in node.items
            )
        ]
        self.assertEqual(len(seals), 1)
        self.assertEqual(len(publish_transactions), 1)
        self.assertLess(seals[0].lineno, publish_transactions[0].lineno)

        recovery = function(ScanLifecycleService.get_scan_context)
        recovery_lock = with_context(recovery, "scan_lock_for_id")
        self.assertEqual(len(calls(recovery_lock, "deliver_scan_recovery")), 1)


if __name__ == "__main__":
    unittest.main()
