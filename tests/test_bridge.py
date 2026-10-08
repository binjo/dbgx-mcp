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

    def test_pipe_full_path_normalisation(self):
        self.assertEqual(bridge._pipe_full_path("dbgx-mcp-1"), r"\\.\pipe\dbgx-mcp-1")
        self.assertEqual(bridge._pipe_full_path(r"\\.\pipe\x"), r"\\.\pipe\x")

    def test_auth_headers(self):
        orig = bridge.AUTH_TOKEN
        try:
            bridge.AUTH_TOKEN = ""
            self.assertEqual(bridge.auth_headers(), {})
            self.assertEqual(bridge.auth_headers({"port": 5678}), {})
            self.assertEqual(
                bridge.auth_headers({"port": 5678, "token": "abc"}),
                {"Authorization": "Bearer abc"},
            )
            bridge.AUTH_TOKEN = "envtok"
            self.assertEqual(bridge.auth_headers(), {"Authorization": "Bearer envtok"})
            # Per-session token from the local registry wins over the environment.
            self.assertEqual(
                bridge.auth_headers({"token": "abc"}), {"Authorization": "Bearer abc"}
            )
            self.assertEqual(bridge.auth_headers(5678), {"Authorization": "Bearer envtok"})
        finally:
            bridge.AUTH_TOKEN = orig


class TestPersistentPipeClient(unittest.TestCase):
    """Exercises forward_pipe() reuse/reconnect logic with the Win32 layer stubbed out."""

    def setUp(self):
        self._orig_platform = sys.platform
        self._orig_open = bridge._open_pipe_handle
        self._orig_round_trip = bridge._pipe_round_trip
        self._orig_close = bridge._close_pipe_handle
        sys.platform = "win32"
        bridge._pipe_handles.clear()
        self.opened = []
        self.closed = []

        def fake_open(path, timeout):
            handle = 100 + len(self.opened)
            self.opened.append(handle)
            return handle

        def fake_close(path):
            with bridge._pipe_handles_lock:
                h = bridge._pipe_handles.pop(path, None)
            if h is not None:
                self.closed.append(h)

        bridge._open_pipe_handle = fake_open
        bridge._close_pipe_handle = fake_close

    def tearDown(self):
        sys.platform = self._orig_platform
        bridge._open_pipe_handle = self._orig_open
        bridge._pipe_round_trip = self._orig_round_trip
        bridge._close_pipe_handle = self._orig_close
        bridge._pipe_handles.clear()

    def test_handle_is_reused_across_requests(self):
        bridge._pipe_round_trip = lambda h, p, b: b'{"ok":%d}' % h
        r1, _ = bridge.forward_pipe("p", b"{}")
        r2, _ = bridge.forward_pipe("p", b"{}")
        self.assertEqual(r1, b'{"ok":100}')
        self.assertEqual(r2, b'{"ok":100}')
        self.assertEqual(self.opened, [100])
        self.assertEqual(self.closed, [])

    def test_reconnects_once_on_broken_pipe(self):
        calls = []

        def flaky(h, p, b):
            calls.append(h)
            if len(calls) == 1:
                raise OSError(109, "broken")
            return b"ok"

        bridge._pipe_round_trip = flaky
        data, status = bridge.forward_pipe("p", b"{}")
        self.assertEqual((data, status), (b"ok", 200))
        self.assertEqual(calls, [100, 101])
        self.assertEqual(self.closed, [100])
        self.assertEqual(bridge._pipe_handles[r"\\.\pipe\p"], 101)

    def test_does_not_retry_on_other_errors(self):
        def always_fail(h, p, b):
            raise OSError(5, "access denied")

        bridge._pipe_round_trip = always_fail
        with self.assertRaises(IOError):
            bridge.forward_pipe("p", b"{}")
        self.assertEqual(self.opened, [100])
        self.assertEqual(self.closed, [100])
        self.assertNotIn(r"\\.\pipe\p", bridge._pipe_handles)

    def test_requests_to_same_pipe_are_serialized(self):
        import threading
        import time

        in_flight = 0
        max_in_flight = 0
        guard = threading.Lock()

        def slow(h, p, b):
            nonlocal in_flight, max_in_flight
            with guard:
                in_flight += 1
                max_in_flight = max(max_in_flight, in_flight)
            time.sleep(0.02)
            with guard:
                in_flight -= 1
            return b"ok"

        bridge._pipe_round_trip = slow
        threads = [threading.Thread(target=bridge.forward_pipe, args=("p", b"{}")) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(max_in_flight, 1)
        self.assertEqual(self.opened, [100])


if __name__ == "__main__":
    unittest.main()
