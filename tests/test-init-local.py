"""Exercise the real entrypoint and Git without requiring Docker."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

INIT = str(Path(__file__).resolve().parents[1] / "scripts/init-git.sh")


class IdentityTests(unittest.TestCase):
    def test_real_commit_and_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, HOME=directory, GIT_USER_NAME="Example Developer", GIT_USER_EMAIL="developer@example.com")
            script = "git init -q; git -c core.hooksPath=/dev/null commit -qm test --allow-empty; git log -1 --format='%an <%ae>|%cn <%ce>'"
            result = subprocess.run([INIT, "--exec", "sh", "-eu", "-c", script], env=env, cwd=directory, check=True, capture_output=True, text=True)
            self.assertEqual(result.stdout.strip(), "Example Developer <developer@example.com>|Example Developer <developer@example.com>")
            result = subprocess.run([INIT, "--exec", "sh", "-eu", "-c", "git config user.name 'Local Developer'; git config user.name"], env=env, cwd=directory, check=True, capture_output=True, text=True)
            self.assertEqual(result.stdout.strip(), "Local Developer")

    def test_invalid_identity(self):
        for name, email in [("Only", ""), ("", "a@example.com"), ("X\n[user]", "a@example.com"), ("X\r", "a@example.com"), ("X <evil>", "a@example.com"), ("  ", "a@example.com"), ("X", "bad email"), ("X", "a@example.com\n[user]"), ("X" * 257, "a@example.com")]:
            with self.subTest(name=name, email=email):
                env = dict(os.environ, GIT_USER_NAME=name, GIT_USER_EMAIL=email)
                result = subprocess.run([INIT, "--exec", "true"], env=env, capture_output=True)
                self.assertEqual(result.returncode, 64)

    def test_absent_preserves_environment(self):
        env = {key: value for key, value in os.environ.items() if key not in {"GIT_USER_NAME", "GIT_USER_EMAIL", "GIT_CONFIG_SYSTEM"}}
        subprocess.run([INIT, "--exec", "sh", "-eu", "-c", 'test -z "${GIT_CONFIG_SYSTEM:-}"'], env=env, check=True)


if __name__ == "__main__":
    unittest.main()
