"""Public scan-local file safety API coverage."""

import os
import tempfile
import unittest
from pathlib import Path

from kiro_security.artifacts import ArtifactContractError as ExportedArtifactError
from kiro_security.scan_files import (
    ArtifactContractError,
    atomic_write,
    read_regular_file,
    require_scan_directory,
    validate_scan_relative_path,
)


class ScanFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def test_public_api_atomically_replaces_regular_scan_file(self):
        self.assertIs(ArtifactContractError, ExportedArtifactError)
        self.assertEqual(require_scan_directory(self.root), self.root)
        self.assertEqual(
            validate_scan_relative_path("artifacts/result.json", "artifact"),
            "artifacts/result.json",
        )
        atomic_write(self.root, "artifacts/result.json", b"first")
        self.assertEqual(
            read_regular_file(self.root, "artifacts/result.json"),
            b"first",
        )
        atomic_write(self.root, "artifacts/result.json", b"second")
        self.assertEqual(
            read_regular_file(self.root, "artifacts/result.json"),
            b"second",
        )

    def test_public_api_rejects_unsafe_relative_paths(self):
        for value in ("", ".", "../escape", "/absolute", "a\\b", "a\0b"):
            with self.subTest(value=value):
                with self.assertRaises(ArtifactContractError):
                    validate_scan_relative_path(value, "artifact")
        self.assertEqual(
            validate_scan_relative_path(".", "scope", allow_dot=True),
            ".",
        )

    @unittest.skipIf(os.name == "nt", "symlink creation requires privileges on Windows")
    def test_public_api_rejects_symlink_roots_parents_and_files(self):
        outside = self.root.parent / (self.root.name + "-outside")
        outside.mkdir()
        self.addCleanup(lambda: outside.rmdir())
        root_link = self.root.parent / (self.root.name + "-link")
        root_link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(root_link.unlink)
        with self.assertRaises(ArtifactContractError):
            require_scan_directory(root_link)

        (self.root / "parent-link").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ArtifactContractError):
            atomic_write(self.root, "parent-link/output.json", b"unsafe")
        self.assertEqual(list(outside.iterdir()), [])

        outside_file = outside / "outside.json"
        outside_file.write_bytes(b"outside")
        self.addCleanup(outside_file.unlink)
        (self.root / "file-link.json").symlink_to(outside_file)
        with self.assertRaises(ArtifactContractError):
            read_regular_file(self.root, "file-link.json")


if __name__ == "__main__":
    unittest.main()
