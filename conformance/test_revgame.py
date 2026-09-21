import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from conformance.process import digest
from integrations.revgame.build import prepare, V4_OPTIONS
from integrations.revgame.check import actions_match, run


class RevGameTests(unittest.TestCase):
    def test_process_output_and_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "output.log"
            code, output, elapsed = run(Path(sys.executable), ["-c", "print('ready')"], log)
            self.assertEqual((code, output), (0, b"ready\n"))
            self.assertEqual(log.read_bytes(), output)
            self.assertGreaterEqual(elapsed, 0)
            with self.assertRaises(subprocess.TimeoutExpired):
                run(Path(sys.executable), ["-c", "import time; time.sleep(10)"],
                    log, timeout=0.05)

    @unittest.skipUnless(Path("/usr/bin/script").exists(), "requires util-linux script")
    def test_terminal_does_not_echo_injected_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "terminal.log"
            code, output, _ = run(Path(sys.executable), ["-c", "print(input())"],
                                  log, keys=b"input-line\n", timeout=5)
            self.assertEqual((code, output), (0, b"input-line\r\n"))

    def test_full_v4_profile(self):
        for option in ("--fusion", "--values", "--memory", "--coupled-state",
                       "--bundles", "--object-bundles", "--encoded-calls",
                       "--call-policy", "--scale-budget", "--scale-structure"):
            self.assertIn(option, V4_OPTIONS)
        self.assertEqual(V4_OPTIONS[V4_OPTIONS.index("--region-plan") + 1], "connected")

    def test_recording_requires_the_expected_actions(self):
        expected = [{"type": "move", "dir": "south"}] * 2
        self.assertTrue(actions_match({"runs": [{"actions": expected}]}, expected))
        for bad in (None, [], {}, {"runs": []}, {"runs": [None]},
                    {"runs": [{"actions": []}]},
                    {"runs": [{"actions": [{"type": "move"}] * 2}]}):
            self.assertFalse(actions_match(bad, expected))

    def test_snapshot_uses_make_sources_without_mutating_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, out = root / "game", root / "out"
            croot = source / "c"
            croot.mkdir(parents=True)
            out.mkdir()
            manual = source / "go/cmd/crypts/game-manual.md"
            manual.parent.mkdir(parents=True)
            manual.write_text("manual\n")
            (croot / "main.c").write_text("int main(void) { return 0; }\n")
            (croot / "future.c").write_text("int future;\n")
            (croot / "build").mkdir()
            (croot / "build/stale.c").write_text("must not copy\n")
            (croot / "Makefile").write_text(
                "PROD_LIB_SRCS = future.c\nCRYPTS_MAIN = main.c\n"
                "PROD_ONLY_GEN_SRCS = build/generated/messages.c\n"
                "build/generated/game_manual_embed.c build/generated/messages.c "
                "build/generated/obfconst.c:\n\t@mkdir -p build/generated\n\t@touch $@\n")
            before = {str(p.relative_to(source)): digest(p)
                      for p in source.rglob("*") if p.is_file()}
            copied, sources = prepare(source, out)
            self.assertEqual([p.name for p in sources], ["future.c", "messages.c", "main.c"])
            self.assertFalse((copied / "build/stale.c").exists())
            self.assertTrue(all(p.is_relative_to(copied) for p in sources))
            after = {str(p.relative_to(source)): digest(p)
                     for p in source.rglob("*") if p.is_file()}
            self.assertEqual(before, after)
            manifest = json.loads((out / "source-manifest.json").read_text())
            self.assertEqual(manifest["source"], str(source))
            self.assertNotIn("c/build/stale.c", [r["path"] for r in manifest["files"]])


if __name__ == "__main__":
    unittest.main()
