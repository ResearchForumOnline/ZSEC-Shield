from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "packaging" / "native_release.py"


def load_release_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("zsec_native_release", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load native release helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


release = load_release_module()


class NativePackagingTests(unittest.TestCase):
    def test_source_version_and_pyinstaller_pin_are_explicit(self) -> None:
        self.assertEqual("0.1.0", release.project_version())
        self.assertEqual("6.21.0", release.expected_pyinstaller_version())

    def test_release_tag_must_exactly_match_source_version(self) -> None:
        self.assertEqual("0.1.0", release.verify_release_tag("v0.1.0"))
        with self.assertRaises(release.ReleaseError):
            release.verify_release_tag("v0.1.1")
        with self.assertRaises(release.ReleaseError):
            release.verify_release_tag("preview-0.1.0")

    def test_source_provenance_is_available_without_global_git_configuration(self) -> None:
        self.assertRegex(release._source_revision(), r"^[0-9a-f]{40}$")
        self.assertIn(release._source_tree_state(), {"clean", "modified"})

    def test_platform_and_architecture_names_are_canonical(self) -> None:
        self.assertEqual("windows", release.normalize_system("Windows"))
        self.assertEqual("macos", release.normalize_system("Darwin"))
        self.assertEqual("linux", release.normalize_system("Linux"))
        self.assertEqual("x86_64", release.normalize_architecture("AMD64"))
        self.assertEqual("arm64", release.normalize_architecture("aarch64"))
        with self.assertRaises(release.ReleaseError):
            release.normalize_architecture("x86")

    def test_windows_version_resource_is_generated_from_package_version(self) -> None:
        with TemporaryDirectory() as temporary:
            target = Path(temporary) / "version.txt"
            release.write_windows_version_file(target, "1.2.3")
            content = target.read_text(encoding="utf-8")
        self.assertIn("filevers=(1, 2, 3, 0)", content)
        self.assertIn("ProductVersion', '1.2.3.0'", content)
        self.assertIn("OriginalFilename', 'zsec-shield.exe'", content)

    def test_manifest_file_inventory_is_sorted_and_hashed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "z.txt").write_bytes(b"z")
            (root / "a.txt").write_bytes(b"a")
            records = release._manifest_files(root)
        self.assertEqual(["a.txt", "z.txt"], [record["path"] for record in records])
        self.assertTrue(all(record["type"] == "file" for record in records))
        self.assertTrue(all(len(record["sha256"]) == 64 for record in records))

    def test_combined_checksums_include_only_distribution_archives(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "zsec-shield-0.1.0-windows-x86_64.zip").write_bytes(b"native")
            (root / "zsec_shield-0.1.0-py3-none-any.whl").write_bytes(b"wheel")
            (root / "ignored.sha256").write_text("old", encoding="utf-8")
            (root / "notes.txt").write_text("notes", encoding="utf-8")
            output = root / "SHA256SUMS.txt"
            records = release.write_checksums(root, output)
            checksum_lines = output.read_text(encoding="utf-8").splitlines()
        self.assertEqual(2, len(records))
        self.assertEqual(2, len(checksum_lines))
        self.assertTrue(all("ignored.sha256" not in line for line in checksum_lines))

    def test_manifest_schema_has_fail_closed_top_level(self) -> None:
        schema = json.loads(
            (PROJECT_ROOT / "packaging" / "native-manifest.schema.json").read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("runtime_policy", schema["required"])
        self.assertIn("source_tree_state", schema["properties"]["build"]["required"])
        policy = schema["properties"]["runtime_policy"]["properties"]
        self.assertEqual(False, policy["real_time_protection"]["const"])
        self.assertEqual(False, policy["telemetry"]["const"])

    def test_spec_uses_inspectable_onedir_without_upx_or_signing(self) -> None:
        content = (PROJECT_ROOT / "packaging" / "zsec-shield.spec").read_text(encoding="utf-8")
        self.assertIn("COLLECT(", content)
        self.assertNotIn("onefile", content.casefold())
        self.assertIn("upx=False", content)
        self.assertIn("codesign_identity=None", content)
        self.assertIn("trusted_keys.json", content)

    def test_source_archive_includes_native_rebuild_inputs(self) -> None:
        content = (PROJECT_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn("recursive-include docs *.md", content)
        self.assertIn("recursive-include packaging *.json *.md *.py *.spec", content)
        self.assertIn("include SECURITY.md", content)
        self.assertNotIn("dist/", content)
        self.assertNotIn("build/", content)

    def test_release_workflow_builds_all_targets_and_only_drafts(self) -> None:
        content = (PROJECT_ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("windows-2022", content)
        self.assertIn("macos-14", content)
        self.assertIn("ubuntu-22.04", content)
        self.assertIn("gh release create", content)
        self.assertIn("--draft", content)
        self.assertNotIn("pull_request_target", content)
        self.assertNotIn("codesign", content.casefold())


if __name__ == "__main__":
    unittest.main()
