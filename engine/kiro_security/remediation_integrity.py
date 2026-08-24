"""Digest-bound checkout and patch verification for remediation workflows."""

import hashlib
import hmac
import os
import shutil
import stat
import tempfile
from pathlib import Path

from .errors import WorkbenchError
from .models import WorkspaceSetup
from .target import Git
from .workbench_contract import optional_digest as _optional_digest


class RemediationIntegrity:
    """Verify that remediation operates on the sealed checkout and exact patch."""

    def __init__(self, targets):
        self.targets = targets

    def verify_checkout(self, scan, expected_content_digest):
        current = self.capture_target(scan)
        self.verify_identity(scan, current)
        if (
            expected_content_digest is not None
            and current.target_snapshot_digest != expected_content_digest
        ):
            raise WorkbenchError(
                "remediation_content_changed",
                "Remediation checkout content does not match the expected digest.",
            )
        return current

    def verify_applied_checkout(self, scan, expected_digest):
        current = self.capture_target(scan)
        self.verify_identity(scan, current)
        actual = self.portable_tree_digest(Path(scan["target_path"]))
        if (
            not isinstance(expected_digest, str)
            or not hmac.compare_digest(actual, expected_digest)
        ):
            raise WorkbenchError(
                "remediation_content_changed",
                "Remediation checkout content does not match the applied digest.",
            )
        return current

    @staticmethod
    def verify_identity(scan, current):
        if (
            str(current.target_device) != str(scan["target_device"])
            or str(current.target_inode) != str(scan["target_inode"])
            or current.target_revision != scan["target_revision"]
        ):
            raise WorkbenchError(
                "remediation_target_changed",
                "Remediation checkout identity or revision changed after the scan.",
            )

    def capture_target(self, scan):
        return self.targets.capture(
            WorkspaceSetup(
                target_path=scan["target_path"],
                mode="standard",
                scope=scan["scope"],
                user_context=scan["user_context"],
                diff_target=None,
            )
        )

    @staticmethod
    def verify_patch(scan, patch_path, patch_digest):
        expected_digest = _optional_digest(patch_digest)
        if not isinstance(patch_path, str) or expected_digest is None:
            raise WorkbenchError(
                "remediation_patch_required",
                "Remediation patch path and digest are required.",
            )
        try:
            scan_dir = Path(scan["scan_dir"]).resolve(strict=True)
            candidate = Path(patch_path).resolve(strict=True)
            candidate.relative_to(scan_dir)
        except (OSError, RuntimeError, ValueError) as exc:
            raise WorkbenchError(
                "remediation_patch_unsafe",
                "Remediation patch must stay inside the scan directory.",
            ) from exc
        metadata = candidate.lstat()
        if (
            candidate.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > 2 * 1024 * 1024
        ):
            raise WorkbenchError(
                "remediation_patch_unsafe",
                "Remediation patch must be a regular file no larger than 2 MiB.",
            )
        actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if not hmac.compare_digest(actual, expected_digest):
            raise WorkbenchError(
                "remediation_patch_changed",
                "Remediation patch digest does not match.",
            )
        return candidate

    @staticmethod
    def verify_patch_application(scan, patch_path, reverse):
        arguments = ["apply", "--check"]
        if reverse:
            arguments.append("--reverse")
        arguments.append(str(patch_path))
        completed = Git.run(
            Path(scan["target_path"]),
            arguments,
            True,
        )
        if completed.returncode != 0:
            raise WorkbenchError(
                "remediation_patch_not_applied"
                if reverse
                else "remediation_patch_not_applicable",
                "The digest-bound remediation patch is not in the required checkout state.",
            )

    def expected_patch_tree_digest(self, scan, patch_path):
        target = Path(scan["target_path"])
        with tempfile.TemporaryDirectory(prefix="kiro-security-remediation-") as value:
            copy_root = Path(value) / "target"
            copy_root.mkdir(mode=0o700)
            for source in self.targets._directory_snapshot_paths(target):
                relative = source.relative_to(target)
                destination = copy_root / relative
                metadata = source.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    destination.mkdir(
                        mode=stat.S_IMODE(metadata.st_mode),
                        parents=True,
                        exist_ok=True,
                    )
                elif stat.S_ISLNK(metadata.st_mode):
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    os.symlink(os.readlink(source), destination)
                elif stat.S_ISREG(metadata.st_mode):
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    shutil.copy2(source, destination, follow_symlinks=False)
            completed = Git.run(
                copy_root,
                ["apply", "--recount", str(patch_path)],
                True,
            )
            if completed.returncode != 0:
                raise WorkbenchError(
                    "remediation_patch_not_applicable",
                    "Could not derive the exact post-patch checkout.",
                )
            return self.portable_tree_digest(copy_root, use_git_inventory=False)

    def portable_tree_digest(self, root, use_git_inventory=True):
        paths = (
            self.targets._directory_snapshot_paths(root)
            if use_git_inventory
            else sorted(
                root.rglob("*"),
                key=lambda item: item.relative_to(root).as_posix(),
            )
        )
        digest = hashlib.sha256()
        digest.update(b"kiro-security-remediation-tree/v1\0")
        for path in paths:
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            relative = path.relative_to(root).as_posix().encode("utf-8")
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            mode = str(stat.S_IMODE(metadata.st_mode)).encode("ascii")
            digest.update(len(mode).to_bytes(2, "big"))
            digest.update(mode)
            if stat.S_ISLNK(metadata.st_mode):
                content = os.fsencode(os.readlink(path))
                kind = b"symlink"
            elif stat.S_ISREG(metadata.st_mode):
                content = path.read_bytes()
                kind = b"file"
            else:
                raise WorkbenchError(
                    "unsupported_target_file",
                    "Remediation snapshots do not support special files.",
                )
            digest.update(len(kind).to_bytes(1, "big"))
            digest.update(kind)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
        return digest.hexdigest()
