import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from lupa.lua51 import LuaRuntime


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src" / "tpddns_security.lua"
PATCH = ROOT / "patches" / "0001-fix-tpddns-second-order-command-injection.patch"


class TpddnsSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lua = LuaRuntime(unpack_returned_tuples=True)
        cls.security = cls.lua.execute(MODULE.read_text(encoding="utf-8"))

    def assert_invalid(self, value):
        result = self.security.validate_username(value)
        if isinstance(result, tuple):
            valid, reason = result
        else:
            valid, reason = result, None
        self.assertIsNone(valid)
        self.assertIsInstance(reason, str)
        self.assertTrue(reason)

    def test_accepts_normal_cloud_identifiers(self):
        valid_values = (
            "user@example.com",
            "13800138000",
            "alice.smith+router@example.co.uk",
            "name with space",
            "o'hara@example.com",
            "测试@example.com",
        )
        for value in valid_values:
            with self.subTest(value=value):
                self.assertTrue(self.security.validate_username(value))

    def test_rejects_invalid_types_and_boundaries(self):
        for value in (None, 123, {}, "", "-help", "a\nvalue", "a\rvalue", "a\x00value", "a" * 256):
            with self.subTest(value=repr(value)):
                self.assert_invalid(value)

    def test_allows_maximum_length(self):
        self.assertTrue(self.security.validate_username("a" * 255))

    def test_quotes_apostrophes_and_shell_metacharacters(self):
        value = "o'hara;$(touch sentinel)`touch sentinel`@example.com"
        quoted = self.security.shell_quote(value)
        self.assertEqual(
            quoted,
            "'o'\\''hara;$(touch sentinel)`touch sentinel`@example.com'",
        )

    def test_command_has_one_quoted_argument(self):
        self.assertEqual(
            self.security.build_get_domain_list_command("alice@example.com"),
            "getDomainList 'alice@example.com'",
        )


class ShellBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lua = LuaRuntime(unpack_returned_tuples=True)
        cls.security = cls.lua.execute(MODULE.read_text(encoding="utf-8"))
        cls.shell = cls.find_shell()

    @staticmethod
    def find_shell():
        candidates = [
            os.environ.get("TPDDNS_TEST_SHELL"),
            shutil.which("sh"),
            "/bin/sh",
            r"C:\Program Files\Git\usr\bin\sh.exe",
        ]
        for candidate in candidates:
            if candidate and Path(candidate).is_file():
                return candidate
        raise unittest.SkipTest("no POSIX-compatible shell is available")

    def test_payloads_remain_literal_single_argument(self):
        payloads = (
            "$(touch sentinel)",
            "`touch sentinel`",
            "alice; touch sentinel; #",
            "alice && touch sentinel",
            "alice | touch sentinel",
            "alice > sentinel",
            "o'hara; touch sentinel; #",
            "*.example.com",
            "name with spaces",
            "测试@example.com",
            "prefix" + "".join(chr(code) for code in range(32, 127)),
        )

        for payload in payloads:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as tmp:
                command = self.security.build_get_domain_list_command(payload)
                script = (
                    "getDomainList() { printf '%s' \"$1\" > capture.txt; }\n"
                    + command
                )
                completed = subprocess.run(
                    [self.shell, "-c", script],
                    cwd=tmp,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(
                    Path(tmp, "capture.txt").read_text(encoding="utf-8"),
                    payload,
                )
                self.assertFalse(Path(tmp, "sentinel").exists())


class PatchConsistencyTests(unittest.TestCase):
    def test_patch_embeds_complete_security_module(self):
        patch_text = PATCH.read_text(encoding="utf-8")
        module_diff = patch_text.split(
            "diff --git a/usr/lib/lua/luci/controller/admin/tpddns_security.lua",
            1,
        )[1]
        hunk = module_diff.split("@@ -0,0 +1,61 @@", 1)[1].split("\n-- \n", 1)[0]
        embedded = "\n".join(
            line[1:] for line in hunk.splitlines() if line.startswith("+")
        )
        self.assertEqual(embedded.strip(), MODULE.read_text(encoding="utf-8").strip())

    def test_integration_revalidates_at_execution_sink(self):
        patch_text = PATCH.read_text(encoding="utf-8")
        self.assertIn(
            "+    local command = tpddns_security.build_get_domain_list_command(username)",
            patch_text,
        )
        self.assertNotIn(
            '+    d.fork_exec("getDomainList " .. username)',
            patch_text,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
