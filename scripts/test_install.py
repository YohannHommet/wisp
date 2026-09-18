#!/usr/bin/env python3
"""Exercise the Unix installer with local download fixtures and temporary paths."""

import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


INSTALLER = Path(__file__).resolve().with_name("install.sh")
BINARY = b"#!/bin/sh\nprintf 'wisp installer fixture\\n'\n"
PREVIOUS_BINARY = b"previous installed binary\n"


@unittest.skipUnless(sys.platform in ("linux", "darwin"), "Unix installer tests")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which("bash"), "bash is required")
        temporary = tempfile.TemporaryDirectory(prefix="wisp-install-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.install_dir = self.root / "install with spaces"
        self.install_dir.mkdir()
        self.destination = self.install_dir / "wisp"
        fixtures = self.root / "fixtures"
        fixtures.mkdir()
        (fixtures / "binary").write_bytes(BINARY)
        mock_bin = self.root / "mock-bin"
        mock_bin.mkdir()
        curl = mock_bin / "curl"
        curl.write_text(
            "#!/usr/bin/env python3\n"
            + textwrap.dedent(
                """\
                import hashlib
                import os
                from pathlib import Path
                import sys

                arguments = sys.argv[1:]
                destination = Path(arguments[arguments.index('-o') + 1])
                url = next(arg for arg in arguments if arg.startswith('https://'))
                prefix = 'https://github.com/YohannHommet/wisp/releases/download/v0.2.0/'
                if not url.startswith(prefix):
                    sys.exit('Unexpected download URL: ' + url)
                asset = url[len(prefix):]
                binary = (Path(os.environ['WISP_TEST_FIXTURES']) / 'binary').read_bytes()
                assets = ('wisp-linux-amd64', 'wisp-linux-arm64', 'wisp-macos-universal')
                if asset == 'SHA256SUMS':
                    mode = os.environ['WISP_TEST_CHECKSUM']
                    digest = hashlib.sha256(binary).hexdigest()
                    if mode == 'bad':
                        digest = '0' * 64
                    lines = [] if mode == 'missing' else [digest + '  ' + name for name in assets]
                    destination.write_text('\\n'.join(lines) + '\\n')
                elif asset in assets:
                    destination.write_bytes(binary)
                else:
                    sys.exit('Unexpected asset: ' + asset)
                """
            )
        )
        curl.chmod(0o755)
        self.environment = os.environ | {
            "PATH": str(mock_bin) + os.pathsep + os.environ.get("PATH", ""),
            "WISP_VERSION": "v0.2.0",
            "WISP_INSTALL_DIR": str(self.install_dir),
            "WISP_TEST_FIXTURES": str(fixtures),
            "WISP_TEST_CHECKSUM": "good",
        }

    def run_installer(self, checksum="good"):
        result = subprocess.run(
            ["bash", str(INSTALLER)],
            env=self.environment | {"WISP_TEST_CHECKSUM": checksum},
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(list(self.install_dir.glob(".wisp-install.*")), [])
        return result

    def assert_installed(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.destination.read_bytes(), BINARY)
        self.assertTrue(self.destination.stat().st_mode & stat.S_IXUSR)
        self.assertIn("Installed v0.2.0", result.stdout)

    def assert_refused(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("Installed v0.2.0", result.stdout)

    def test_fresh_install(self):
        self.assert_installed(self.run_installer())

    def test_replaces_existing_binary(self):
        self.destination.write_bytes(PREVIOUS_BINARY)
        self.assert_installed(self.run_installer())

    def test_bad_checksum_preserves_existing_binary(self):
        self.destination.write_bytes(PREVIOUS_BINARY)
        result = self.run_installer("bad")
        self.assert_refused(result)
        self.assertIn("Checksum mismatch", result.stderr)
        self.assertEqual(self.destination.read_bytes(), PREVIOUS_BINARY)

    def test_missing_checksum_preserves_existing_binary(self):
        self.destination.write_bytes(PREVIOUS_BINARY)
        result = self.run_installer("missing")
        self.assert_refused(result)
        self.assertIn("Missing or ambiguous release checksum", result.stderr)
        self.assertEqual(self.destination.read_bytes(), PREVIOUS_BINARY)

    def test_directory_destination_is_refused(self):
        self.destination.mkdir()
        result = self.run_installer()
        self.assert_refused(result)
        self.assertTrue(self.destination.is_dir())
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_symlink_to_directory_destination_is_refused(self):
        other_directory = self.root / "unrelated directory"
        other_directory.mkdir()
        self.destination.symlink_to(other_directory, target_is_directory=True)
        result = self.run_installer()
        self.assert_refused(result)
        self.assertTrue(self.destination.is_symlink())
        self.assertEqual(self.destination.resolve(), other_directory.resolve())
        self.assertEqual(list(other_directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
