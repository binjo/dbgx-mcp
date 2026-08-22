import unittest
import sys
import os

# Add dbgx-mcp folder to sys.path so we can import windbg-bridge
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import importlib
bridge = importlib.import_module("windbg-bridge")

class TestBridge(unittest.TestCase):
    def test_validate_command_simple(self):
        is_safe, err = bridge.validate_command("r")
        self.assertTrue(is_safe)
        self.assertEqual(err, "")

    def test_validate_command_dangerous(self):
        is_safe, err = bridge.validate_command("q")
        self.assertFalse(is_safe)
        self.assertIn("prohibited", err)

    def test_validate_command_chained_safe(self):
        is_safe, err = bridge.validate_command("r; bl; lm")
        self.assertTrue(is_safe)
        self.assertEqual(err, "")

    def test_validate_command_chained_dangerous(self):
        is_safe, err = bridge.validate_command("r; q")
        self.assertFalse(is_safe)
        self.assertIn("prohibited", err)

        is_safe, err = bridge.validate_command("r; .kill")
        self.assertFalse(is_safe)
        self.assertIn("prohibited", err)

    def test_get_timeout_for_request_eval_quick(self):
        req = {
            "method": "tools/call",
            "params": {
                "name": "windbg.eval",
                "arguments": {"command": "version"}
            }
        }
        t = bridge.get_timeout_for_request(req)
        self.assertEqual(t, 10.0)

    def test_get_timeout_for_request_eval_reload(self):
        req = {
            "method": "tools/call",
            "params": {
                "name": "windbg.eval",
                "arguments": {"command": ".reload /f"}
            }
        }
        t = bridge.get_timeout_for_request(req)
        self.assertEqual(t, 1200.0)

    def test_get_timeout_for_request_eval_process(self):
        req = {
            "method": "tools/call",
            "params": {
                "name": "windbg.eval",
                "arguments": {"command": "!process 0 0"}
            }
        }
        t = bridge.get_timeout_for_request(req)
        self.assertEqual(t, 480.0)

    def test_get_timeout_for_request_carve(self):
        req = {
            "method": "tools/call",
            "params": {
                "name": "windbg.carve_pe",
                "arguments": {"address": "0x7ff7a1230000", "length": 1000}
            }
        }
        t = bridge.get_timeout_for_request(req)
        self.assertEqual(t, 300.0)

    def test_validate_command_braces_allowed(self):
        is_safe, err = bridge.validate_command(".if (eax == 1) { r ebx }")
        self.assertTrue(is_safe)
        self.assertEqual(err, "")

    def test_validate_command_file_nesting_blocked(self):
        is_safe, err = bridge.validate_command("$$><d:\\t\\recovery.cmd")
        self.assertFalse(is_safe)
        self.assertIn("Sourcing or nesting", err)

    def test_validate_command_extended_dangerous(self):
        for cmd in [".crash", ".shell", "!shell", ".server", ".remote"]:
            is_safe, err = bridge.validate_command(cmd)
            self.assertFalse(is_safe)
            self.assertIn("prohibited", err)

if __name__ == "__main__":
    unittest.main()
