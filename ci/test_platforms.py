"""Guard catalog drift failures and safe regeneration without touching the checkout."""

import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import platforms


class PlatformTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        (root / "ci").mkdir()
        workflows = root / ".github/workflows"
        workflows.mkdir(parents=True)
        for filename in platforms.CONSUMERS:
            shutil.copy(platforms.ROOT / ".github/workflows" / filename, workflows)
        for path in (platforms.ROOT / "ci").glob("freebsd*.env"):
            shutil.copy(path, root / "ci")
        shutil.copy(platforms.CATALOG, root / "ci/platforms.toml")
        self.enterContext(patch.object(platforms, "ROOT", root))
        self.enterContext(
            patch.object(platforms, "CATALOG", root / "ci/platforms.toml")
        )
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.workflow = workflows / "ci.yml"

    def test_drift_fails_then_regeneration_preserves_surrounding_workflow(self) -> None:
        original = self.workflow.read_text()
        changed = original.replace('"x86_64-unknown-linux-musl"', '"wrong-target"', 1)
        self.workflow.write_text(changed)
        data = platforms.catalog()
        self.assertEqual(platforms.sync(data, False), 1)
        self.assertEqual(self.workflow.read_text(), changed, "check must be read-only")
        self.assertEqual(platforms.sync(data, True), 0)
        self.assertEqual(self.workflow.read_text(), original)
        self.assertEqual(platforms.sync(data, False), 0)

    def test_deleting_a_whole_catalog_block_cannot_hide_drift(self) -> None:
        self.workflow.write_text(
            platforms.BLOCK.sub("", self.workflow.read_text(), count=1)
        )
        with self.assertRaises(ValueError):
            platforms.sync(platforms.catalog(), False)

    def test_a_retired_package_pin_cannot_silently_keep_an_abi_active(self) -> None:
        (platforms.ROOT / "ci/freebsd13-opnsense.env").touch()
        with self.assertRaises(ValueError):
            platforms.catalog()

    def test_every_shipped_target_has_lint_and_miri_coverage(self) -> None:
        views = platforms.views(platforms.catalog())
        shipped = {row["target"] for row in views["release"]["include"]}
        self.assertEqual(shipped, set(views["lint"]["target"]))
        self.assertLessEqual(shipped, set(views["miri"]["target"]))


if __name__ == "__main__":
    unittest.main()
