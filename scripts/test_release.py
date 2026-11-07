#!/usr/bin/env python3
# Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
# See LICENSE for the applicable license.
"""Black-box script regressions in disposable copies; never build or publish a release."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


class ReleaseScriptsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="decryptor-release-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("scripts", "capi", "bin"):
            (self.root / directory).mkdir()
        for name in ("version.sh", "release.sh", "build-multiplatform.sh"):
            shutil.copy2(ROOT / "scripts" / name, self.root / "scripts" / name)
        shutil.copy2(ROOT / "capi/main.go", self.root / "capi/main.go")
        shutil.copy2(ROOT / "CHANGELOG.md", self.root / "CHANGELOG.md")
        self.env = os.environ.copy()
        for name in ("GOOS", "GOARCH", "MOCK_PLATFORM", "FAIL_APT", "FAIL_DOCKER"):
            self.env.pop(name, None)
        self.env["PATH"] = str(self.root / "bin") + os.pathsep + self.env["PATH"]
        self.env["TEST_LOG"] = str(self.root / "calls.jsonl")

    def run_script(self, name, *args):
        return subprocess.run(
            ["bash", str(self.root / "scripts" / name), *args],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=10,
        )

    def snapshot(self):
        return [(self.root / p).read_bytes() for p in ("capi/main.go", "CHANGELOG.md")]

    def assert_version(self, version):
        result = self.run_script("version.sh", "show")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Current version: v" + version, result.stdout)
        self.assertIn('C.CString("eCapture Decryptor v' + version + " -", (self.root / "capi/main.go").read_text())

    def executable(self, path, body):
        target = self.root / path
        target.write_text(body)
        target.chmod(0o755)

    def calls(self):
        path = Path(self.env["TEST_LOG"])
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def mock_builds(self):
        self.executable("scripts/release.sh", """#!/usr/bin/env python3
import json, os, pathlib, sys
with open(os.environ['TEST_LOG'], 'a') as log:
    log.write(json.dumps(['release', os.environ.get('MOCK_PLATFORM', 'native'), sys.argv[1:]]) + '\\n')
pathlib.Path('dist').mkdir(exist_ok=True)
pathlib.Path('dist/mock.tar.gz').touch()
""")
        self.executable("bin/docker", """#!/usr/bin/env python3
import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ['TEST_LOG'], 'a') as log:
    log.write(json.dumps(['docker', args]) + '\\n')
if os.environ.get('FAIL_DOCKER'):
    sys.exit(19)
env = os.environ.copy()
env['MOCK_PLATFORM'] = args[args.index('--platform') + 1] if '--platform' in args else 'linux/arm64'
sys.exit(subprocess.run(args[args.index('bash'):], env=env).returncode)
""")
        self.executable("bin/apt-get", "#!/bin/bash\nif [ -n \"$FAIL_APT\" ]; then exit 17; fi\n")

    def test_show_and_source_are_read_only(self):
        before = self.snapshot()
        result = self.run_script("version.sh", "show")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"Current version: v\d+\.\d+\.\d+")
        sourced = subprocess.run(
            ["bash", "-c", 'source scripts/version.sh; get_current_version'],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(sourced.returncode, 0, sourced.stderr)
        self.assertIn("Current version: v" + sourced.stdout.strip(), result.stdout)
        self.assertEqual(self.snapshot(), before)

    def test_set_round_trip_and_preserves_history(self):
        original, history = self.snapshot()
        marker = re.search(rb'eCapture Decryptor v[^ ]+ -', original).group()
        for version in ("2.3.4", "v2.4.0-rc.1+build.7", "v3.1.0"):
            with self.subTest(version=version):
                result = self.run_script("version.sh", "set", version)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_version(version.removeprefix("v"))
                self.assertIn(history, (self.root / "CHANGELOG.md").read_bytes())
        self.assertEqual(original.replace(marker, b"eCapture Decryptor v3.1.0 -"), (self.root / "capi/main.go").read_bytes())

    def test_bump_components(self):
        for kind, expected in (("major", "3.0.0"), ("minor", "2.4.0"), ("patch", "2.3.5")):
            with self.subTest(kind=kind):
                result = self.run_script("version.sh", "set", "v2.3.4")
                self.assertEqual(result.returncode, 0, result.stderr)
                result = self.run_script("version.sh", "bump", kind)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_version(expected)
        before = self.snapshot()
        self.assertNotEqual(self.run_script("version.sh", "bump", "unknown").returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_idempotent_set_and_missing_changelog(self):
        self.assertEqual(self.run_script("version.sh", "set", "v2.3.4").returncode, 0)
        before = self.snapshot()
        self.assertEqual(self.run_script("version.sh", "set", "2.3.4").returncode, 0)
        self.assertEqual(self.snapshot(), before)
        (self.root / "CHANGELOG.md").unlink()
        for args in (("set", "v2.3.5"), ("bump", "patch")):
            self.assertNotEqual(self.run_script("version.sh", *args).returncode, 0)
            self.assertEqual((self.root / "capi/main.go").read_bytes(), before[0])

    def test_invalid_versions_do_not_modify_files(self):
        before = self.snapshot()
        for version in ("1.2", "v01.2.3", "1.2.3-01", "1.2.3-rc..1", "1.2.3; touch injected"):
            with self.subTest(version=version):
                result = self.run_script("version.sh", "set", version)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.snapshot(), before)
                self.assertFalse((self.root / "capi/main.go.bak").exists())
                self.assertFalse((self.root / "injected").exists())

    def test_missing_or_duplicate_marker_fails_before_mutation(self):
        main = self.root / "capi/main.go"
        original = main.read_text()
        marker = next(line for line in original.splitlines() if 'C.CString("eCapture Decryptor v' in line)
        for source in (original.replace("eCapture Decryptor v", "old-name v"), original + "\n" + marker + "\n"):
            main.write_text(source)
            for args in (("show",), ("set", "v2.3.4"), ("bump", "patch")):
                with self.subTest(source=source == original, args=args):
                    before = self.snapshot()
                    result = self.run_script("version.sh", *args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.snapshot(), before)
                    self.assertFalse((self.root / "capi/main.go.bak").exists())

    def test_bump_suffix_and_invalid_kind_fail_without_mutation(self):
        self.assertEqual(self.run_script("version.sh", "set", "v2.3.4-beta.1").returncode, 0)
        for kind in ("patch", "unknown"):
            before = self.snapshot()
            self.assertNotEqual(self.run_script("version.sh", "bump", kind).returncode, 0)
            self.assertEqual(self.snapshot(), before)

    def test_release_updates_version_before_mock_build(self):
        # Stop at build-static: no library build, packaging, tag or publication.
        self.executable("bin/make", "#!/bin/bash\n[ \"$1\" = clean ] && exit 0\nexit 91\n")
        self.env.update(GOOS="linux", GOARCH="amd64")
        for version in ("2.3.4-beta.1+build.7", "v2.3.5"):
            result = self.run_script("release.sh", version)
            self.assertEqual(result.returncode, 91, result.stdout + result.stderr)
            self.assert_version(version.removeprefix("v"))
            self.assertIn("ecapture_decryptor-v" + version.removeprefix("v") + "-linux-amd64", result.stdout)
        backup = self.root / "capi/main.go.bak"
        backup.write_text("existing backup")
        self.assertEqual(self.run_script("release.sh", "v2.3.5").returncode, 91)
        self.assertEqual(backup.read_text(), "existing backup")

    def test_release_preflight_does_not_clean_or_write(self):
        self.executable("bin/make", "#!/bin/bash\ntouch make-called\nexit 91\n")
        main = self.root / "capi/main.go"
        for version in ("v1.2; touch injected", "v2.3.4"):
            if version == "v2.3.4":
                main.write_text(main.read_text().replace("eCapture Decryptor v", "old-name v"))
            before = self.snapshot()
            result = self.run_script("release.sh", version)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.root / "make-called").exists())
            self.assertFalse((self.root / "dist").exists())
            self.assertEqual(self.snapshot(), before)

    def test_multiplatform_dispatches_explicit_targets_and_version(self):
        self.mock_builds()
        result = self.run_script("build-multiplatform.sh", "2.3.4-rc.1+build.7")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual([c for c in calls if c[0] == "release"], [
            ["release", platform, ["v2.3.4-rc.1+build.7"]]
            for platform in ("native", "linux/amd64", "linux/arm64")
        ])
        docker = [c[1] for c in calls if c[0] == "docker"]
        self.assertEqual(len(docker), 2)
        for args, platform in zip(docker, ("linux/amd64", "linux/arm64")):
            self.assertEqual(args[args.index("--platform") + 1], platform)
            self.assertIn("golang:1.26", args)

    def test_release_rejects_incomplete_or_unsupported_targets(self):
        self.executable("bin/make", "#!/bin/bash\ntouch make-called\nexit 91\n")
        for target in ({"GOARCH": "amd64"}, {"GOOS": "linux"}, {"GOOS": "windows", "GOARCH": "amd64"}, {"GOOS": "linux", "GOARCH": "riscv64"}):
            with self.subTest(target=target):
                self.env.pop("GOOS", None)
                self.env.pop("GOARCH", None)
                (self.root / "make-called").unlink(missing_ok=True)
                self.env.update(target)
                before = self.snapshot()
                self.assertNotEqual(self.run_script("release.sh", "v2.3.4").returncode, 0)
                self.assertFalse((self.root / "make-called").exists())
                self.assertFalse((self.root / "dist").exists())
                self.assertEqual(self.snapshot(), before)

    def test_multiplatform_rejects_invalid_input_before_dispatch(self):
        self.mock_builds()
        result = self.run_script("build-multiplatform.sh", "v1.2.3; touch injected")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.root / "injected").exists())

    def test_multiplatform_stops_on_docker_or_dependency_failure(self):
        self.mock_builds()
        for flag, code in (("FAIL_DOCKER", 19), ("FAIL_APT", 17)):
            with self.subTest(flag=flag):
                Path(self.env["TEST_LOG"]).unlink(missing_ok=True)
                self.env[flag] = "1"
                result = self.run_script("build-multiplatform.sh", "v2.3.4")
                self.env.pop(flag)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                self.assertEqual(len([c for c in self.calls() if c[0] == "release"]), 1)
                self.assertEqual(len([c for c in self.calls() if c[0] == "docker"]), 1)


if __name__ == "__main__":
    unittest.main()
