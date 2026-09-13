"""Lane verdicts for representative changes, and the invariant behind the safe default."""

import subprocess
import sys
import unittest
from pathlib import Path

import changed_areas as ca

NONE = {"code": False, "opnsense": False, "port": False, "supply-chain": False}


def only(*lanes: str) -> dict[str, bool]:
    return {**NONE, **{lane: True for lane in lanes}}


class ChangedAreas(unittest.TestCase):
    def test_markdown_alone_runs_nothing(self) -> None:
        self.assertEqual(ca.areas(["README.md", "docs/DEVELOP.md"]), NONE)
        self.assertEqual(ca.areas([]), NONE)

    def test_code_and_unclaimed_paths_run_the_code_lanes(self) -> None:
        self.assertEqual(ca.areas(["src/lib.rs"]), only("code"))
        self.assertEqual(ca.areas([".github/workflows/ci.yml"]), only("code"))
        self.assertEqual(ca.areas(["tools/new-thing.sh"]), only("code"))

    def test_pipeline_files_run_their_pipeline_alone(self) -> None:
        self.assertEqual(ca.areas(["dist/opnsense/net/netflector/Makefile"]), only("opnsense"))
        for pin in ca.PACKAGE_PINS:
            self.assertEqual(ca.areas([pin]), only("opnsense"), pin)
        self.assertEqual(ca.areas(["dist/freebsd/net/netflector/Makefile"]), only("port"))
        self.assertEqual(ca.areas([".github/workflows/ci-supply-chain.yml"]), only("supply-chain"))

    def test_shared_files_run_every_consumer(self) -> None:
        self.assertEqual(ca.areas(["ci/platforms.toml"]), only("code", "opnsense", "port"))
        self.assertEqual(ca.areas(["Cargo.lock"]), only("code", "supply-chain"))
        self.assertEqual(ca.areas(["ci/port-sync.py"]), only("code", "port"))
        self.assertEqual(ca.areas(["ci/freebsd-vm.sh"]), only("code", "opnsense"))

    def test_a_mixed_change_runs_each_touched_lane(self) -> None:
        self.assertEqual(ca.areas(["README.md", "src/main.rs", "dist/opnsense/x"]), only("code", "opnsense"))

    def test_every_ignored_path_belongs_to_a_pipeline(self) -> None:
        # The code lanes ignore a path only because a pipeline runs for it instead; a path ignored
        # by everyone would merge untested.
        for entry in ca.CODE_IGNORES:
            sample = entry + "x" if entry.endswith("/") else entry
            self.assertTrue(
                ca.matches(sample, ca.OPNSENSE) or ca.matches(sample, ca.PORT) or ca.matches(sample, ca.SUPPLY_CHAIN),
                sample,
            )

    def test_the_command_line_prints_one_line_per_lane(self) -> None:
        out = subprocess.run(
            [sys.executable, str(Path(ca.__file__))],
            input="src/lib.rs\n\nCargo.lock\n",
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertEqual(out, "code=true\nopnsense=false\nport=false\nsupply-chain=true\n")


if __name__ == "__main__":
    unittest.main()
