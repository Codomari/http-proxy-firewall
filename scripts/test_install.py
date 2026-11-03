#!/usr/bin/env python3
"""Exercise installation in disposable staging roots; never write to /etc."""

import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parent.parent


def fingerprint(path):
    metadata = path.stat()
    return (
        hashlib.sha256(path.read_bytes()).hexdigest(),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_mtime_ns,
        metadata.st_ino,
    )


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="proxy-firewall-install-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.stage = self.base / "stage with spaces"
        self.root = self.stage / "etc/proxy-firewall"
        self.unit = self.stage / "etc/systemd/system/proxy-firewall.service"
        self.commands = self.base / "commands"
        self.commands.mkdir()
        self.protected = {
            path: fingerprint(path)
            for name in ("proxy-firewall.override.yaml", ".creds")
            if (path := PROJECT / name).is_file()
        }
        self.addCleanup(self.assert_protected)

    def assert_protected(self):
        for path, expected in self.protected.items():
            self.assertEqual(fingerprint(path), expected, f"Protected source changed: {path.name}")

    def install(self, threads=8, make=False):
        getconf = self.commands / "getconf"
        getconf.write_text(f"#!/bin/sh\nprintf '%s\\n' '{threads}'\n")
        getconf.chmod(0o755)
        environment = dict(os.environ, PATH=f"{self.commands}{os.pathsep}{os.environ['PATH']}")
        if make:
            command = ["make", "install", f"DESTDIR={self.stage}"]
        else:
            command = ["sh", "scripts/install.sh", str(self.stage)]
        result = subprocess.run(command, cwd=PROJECT, env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = max(1, threads * 2 // 5)
        self.assertIn(
            f"ExecStart=/usr/bin/env GOMAXPROCS={expected} /etc/proxy-firewall/bin/proxy-firewall",
            self.unit.read_text(),
        )
        return result

    def test_fresh_make_install(self):
        self.install(make=True)
        for name in ("bin", "log", "files", ".cache", ".certs"):
            self.assertTrue((self.root / name).is_dir())
        self.assertEqual((self.root / "proxy-firewall.default.yaml").read_bytes(), (PROJECT / "proxy-firewall.default.yaml").read_bytes())
        self.assertEqual((self.root / "proxy-firewall.override.yaml").read_text(), "env: []\nrules: []\ndebug: []\n")
        self.assertFalse((self.root / ".env").exists())
        self.assertFalse((self.root / "proxy-firewall.conf").exists())
        self.assertEqual((self.root / ".creds").read_bytes(), (PROJECT / ".creds.example").read_bytes())
        self.assertEqual((self.root / "LICENSE").read_bytes(), (PROJECT / "LICENSE").read_bytes())
        self.assertEqual((self.root / "log/proxy-firewall.log").read_bytes(), b"")
        self.assertEqual((self.root / "bin/proxy-firewall").read_bytes(), (PROJECT / "bin/proxy-firewall").read_bytes())
        for name in ("proxy-firewall.override.yaml", ".creds", "log/proxy-firewall.log"):
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.root / "bin/proxy-firewall").stat().st_mode), 0o755)
        unit = self.unit.read_text()
        for stream in ("StandardOutput", "StandardError"):
            self.assertIn(f"{stream}=append:/etc/proxy-firewall/log/proxy-firewall.log", unit)
        self.assertIn("/etc/proxy-firewall/.certs", unit)
        self.assertIn("ReadWritePaths=/etc/proxy-firewall ", unit)
        self.assertIn("ReadOnlyPaths=/etc/proxy-firewall/bin", unit)
        for protected in (".creds", "proxy-firewall.default.yaml", "LICENSE"):
            self.assertIn(f"-/etc/proxy-firewall/{protected}", unit)
        self.assertNotIn("-v2", unit)

    def test_reinstall_preserves_everything_except_binary(self):
        self.install()
        for directory in ("bin", "log", "files", ".cache", ".certs"):
            folder = self.root / directory
            folder.chmod(0o751)
            (folder / "keep nested").mkdir()
            (folder / "keep nested/sentinel").write_bytes(b"existing deployment data\x00\xff")
        for name in ("proxy-firewall.override.yaml", ".creds", "log/proxy-firewall.log"):
            path = self.root / name
            path.write_text(f"existing {name}\nGOMAXPROCS=99\n")
            path.chmod(0o640)
        binary = self.root / "bin/proxy-firewall"
        binary.write_bytes(b"old binary")
        preserved = {p: fingerprint(p) for p in self.root.rglob("*") if p.is_file() and p not in (binary, self.root / "proxy-firewall.default.yaml")}
        directories = {p: stat.S_IMODE(p.stat().st_mode) for p in self.root.rglob("*") if p.is_dir()}
        self.install(threads=16)
        for path, expected in preserved.items():
            self.assertEqual(fingerprint(path), expected, f"Existing file changed: {path}")
        for path, expected in directories.items():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected)
        self.assertEqual(binary.read_bytes(), (PROJECT / "bin/proxy-firewall").read_bytes())

    def test_existing_config_and_log_symlinks_are_preserved(self):
        self.root.mkdir(parents=True)
        (self.root / "log").mkdir()
        for name in ("proxy-firewall.override.yaml", ".creds", "log/proxy-firewall.log"):
            target = self.base / Path(name).name
            target.write_text("keep linked deployment data\n")
            link = self.root / name
            link.symlink_to(target)
        expected = {p: fingerprint(p) for p in self.root.rglob("*") if p.is_file()}
        self.install()
        for path, before in expected.items():
            self.assertTrue(path.is_symlink())
            self.assertEqual(fingerprint(path), before)

    def test_legacy_configuration_is_migrated_before_removal(self):
        self.root.mkdir(parents=True)
        (self.root / ".env").write_text("REDIS_PASSWORD=private-fixture-value\nPF_PROXY_TO=http://127.0.0.1:7000\n")
        (self.root / "proxy-firewall.conf").write_text("PF_PROXY_TO=--proxy-to=127.0.0.1:8000\n")
        self.install()
        override = self.root / "proxy-firewall.override.yaml"
        text = override.read_text()
        self.assertIn("private-fixture-value", text)
        self.assertIn("127.0.0.1:8000", text)
        self.assertIn("127.0.0.1:7000", text)
        self.assertFalse((self.root / ".env").exists())
        self.assertFalse((self.root / "proxy-firewall.conf").exists())
        before = fingerprint(override)
        self.install()
        self.assertEqual(fingerprint(override), before)

    def test_cpu_fraction_and_single_cpu_minimum(self):
        for threads in (1, 2, 3, 4, 5, 8, 16, 64):
            with self.subTest(threads=threads):
                self.install(threads=threads)


if __name__ == "__main__":
    unittest.main()
