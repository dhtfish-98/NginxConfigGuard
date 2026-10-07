"""Check that the release staging path cannot copy untracked checkout data."""

import importlib.util
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class BuildLayoutTests(unittest.TestCase):
    def setUp(self):
        builder = Path(__file__).resolve().parents[1] / "构建.py"
        spec = importlib.util.spec_from_file_location("project_builder", builder)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "checkout"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        self.output = self.base / "Build" / "source"

    def track(self, name, content="public fixture\n"):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        subprocess.run(["git", "-C", str(self.source), "add", name], check=True)
        return path

    def restore(self, stored, original="README.md", content="public fixture\n"):
        return {"original": original, "stored": stored,
                "sha256": hashlib.sha256(content.encode()).hexdigest()}

    def stage(self, restored=()):
        return self.module.stage(self.source, self.output,
                                 {"restored_inputs": list(restored)})

    def test_stage_only_tracked_regular_inputs(self):
        builder = Path(__file__).resolve().parents[1] / "构建.py"
        spec = importlib.util.spec_from_file_location("project_builder", builder)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source = base / "checkout"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            (source / "tracked.txt").write_text("public fixture\n")
            (source / "untracked-private.txt").write_text("must not stage\n")
            (source / "Build").mkdir()
            (source / "Build" / "old-output.txt").write_text("must not stage\n")
            subprocess.run(["git", "-C", str(source), "add", "tracked.txt"], check=True)
            staged = base / "Build" / "source"
            module.stage(source, staged, {"restored_inputs": []})
            self.assertEqual((staged / "tracked.txt").read_text(), "public fixture\n")
            self.assertFalse((staged / "untracked-private.txt").exists())
            self.assertFalse((staged / "Build").exists())
            self.assertFalse((staged / ".git").exists())

    def test_tracked_leaf_link_is_rejected(self):
        path = self.track("data.txt")
        external = self.base / "outside.txt"
        external.write_text("synthetic outside fixture\n")
        path.unlink()
        path.symlink_to(external)
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_tracked_parent_link_is_rejected(self):
        self.track("docs/data.txt")
        external = self.base / "outside"
        external.mkdir()
        (external / "data.txt").write_text("synthetic outside fixture\n")
        shutil.rmtree(self.source / "docs")
        (self.source / "docs").symlink_to(external, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_tracked_restored_parent_link_is_rejected(self):
        self.track("docs/README.md")
        external = self.base / "outside"
        external.mkdir()
        (external / "README.md").write_text("public fixture\n")
        shutil.rmtree(self.source / "docs")
        (self.source / "docs").symlink_to(external, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.stage([self.restore("docs/README.md")])
        self.assertFalse(self.output.exists())

    def test_restore_requires_tracked_source(self):
        self.track("tracked.txt")
        (self.source / "untracked.txt").write_text("public fixture\n")
        with self.assertRaises(ValueError):
            self.stage([self.restore("untracked.txt")])
        self.assertFalse(self.output.exists())

    def test_restore_cannot_chain_through_untracked_alias(self):
        self.track("docs/README.md")
        with self.assertRaises(ValueError):
            self.stage([self.restore("docs/README.md"),
                        self.restore("README.md", "SECOND.md")])
        self.assertFalse(self.output.exists())

    def test_restore_checks_hash_and_existing_destination(self):
        self.track("docs/README.md")
        self.track("README.md", "different fixture\n")
        with self.assertRaises(ValueError):
            self.stage([self.restore("docs/README.md")])
        with self.assertRaises(ValueError):
            self.stage([self.restore("docs/README.md", content="wrong\n")])
        self.assertFalse(self.output.exists())

    def test_restore_tracked_bytes_and_executable_mode(self):
        path = self.track("docs/README.md")
        path.chmod(0o755)
        self.stage([self.restore("docs/README.md")])
        self.assertEqual((self.output / "README.md").read_bytes(), path.read_bytes())
        self.assertEqual((self.output / "README.md").stat().st_mode & 0o777, 0o755)

    def test_stage_parent_link_is_rejected(self):
        self.track("tracked.txt")
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        (self.base / "Build").symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.stage()
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_stage_cannot_be_inside_checkout(self):
        self.track("tracked.txt")
        self.output = self.source / "Build" / "source"
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse((self.source / "Build").exists())

    def test_build_root_cannot_resolve_into_checkout(self):
        link = self.base / "linked"
        link.symlink_to(self.source, target_is_directory=True)
        for requested in (self.source, self.source / "Build", link / "Build"):
            with self.assertRaises(ValueError):
                self.module.build_root(self.source, requested)
        self.assertFalse((self.source / "Build").exists())

    def test_build_root_leaf_link_is_rejected(self):
        target = self.base / "real-output"
        target.mkdir()
        link = self.base / "linked"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.module.build_root(self.source, link)

    def test_project_directory_link_is_rejected(self):
        build = self.module.build_root(self.source, self.base / "Build")
        (build / "Project").symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.module.project_directory(build, "Project")

    def test_project_directory_name_is_bounded(self):
        build = self.module.build_root(self.source, self.base / "Build")
        for name in ("../checkout", "/absolute", "one/two", ".git", "Build"):
            with self.assertRaises(ValueError):
                self.module.project_directory(build, name)

    def test_cache_directory_parent_link_is_rejected(self):
        build = self.module.build_root(self.source, self.base / "Build")
        (build / "缓存").symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.module.environment(build)
        self.assertFalse((self.source / "python").exists())

    def test_cache_directory_leaf_link_is_rejected(self):
        build = self.module.build_root(self.source, self.base / "Build")
        (build / "缓存").mkdir()
        (build / "缓存" / "pip").symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.module.environment(build)

    def test_existing_stage_is_not_reused(self):
        self.track("tracked.txt")
        self.output.mkdir(parents=True)
        marker = self.output / "marker.txt"
        marker.write_text("retained fixture\n")
        with self.assertRaises(ValueError):
            self.stage()
        self.assertEqual(marker.read_text(), "retained fixture\n")


if __name__ == "__main__":
    unittest.main()
