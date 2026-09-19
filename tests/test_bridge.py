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

    def test_validate_command_semicolon_in_quotes(self):
        is_safe, err = bridge.validate_command('dx @$calls("ntdll!foo;bar")')
        self.assertTrue(is_safe)
        self.assertEqual(err, "")

    def test_get_timeout_for_request_ttd_and_resolve(self):
        t_ttd = bridge.get_timeout_for_request({"method": "tools/call", "params": {"name": "windbg.ttd_position", "arguments": {}}})
        self.assertEqual(t_ttd, 60.0)

        t_res = bridge.get_timeout_for_request({"method": "tools/call", "params": {"name": "windbg.resolve", "arguments": {"query": "main"}}})
        self.assertEqual(t_res, 30.0)

        t_step = bridge.get_timeout_for_request({"method": "tools/call", "params": {"name": "windbg.step", "arguments": {"count": 10}}})
        self.assertEqual(t_step, 30.0)

    def test_is_process_alive_current(self):
        self.assertTrue(bridge.is_process_alive(os.getpid()))

    def test_is_process_alive_invalid(self):
        self.assertFalse(bridge.is_process_alive(9999999))

if __name__ == "__main__":
    unittest.main()
