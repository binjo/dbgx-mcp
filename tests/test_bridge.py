import json
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


class TestGuestHostSwitching(unittest.TestCase):
    """windbg.set_guest_host / env-file configuration."""

    def setUp(self):
        import tempfile as _tf
        self._saved = {k: getattr(bridge, k) for k in ("GUEST_IP", "BASE_PORT", "ALLOW_PUBLIC_HOST", "ENV_FILE", "_current_port")}
        self._orig_get_sessions = bridge.get_sessions
        self._tmpdir = _tf.mkdtemp()
        bridge.ENV_FILE = os.path.join(self._tmpdir, "bridge.env")
        bridge.GUEST_IP = "127.0.0.1"
        bridge.BASE_PORT = 5678
        bridge.ALLOW_PUBLIC_HOST = False
        bridge.get_sessions = lambda: []

    def tearDown(self):
        import shutil
        for k, v in self._saved.items():
            setattr(bridge, k, v)
        bridge.get_sessions = self._orig_get_sessions
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_validate_guest_host_accepts_lab_addresses(self):
        for h in ["127.0.0.1", "localhost", "192.168.56.101", "10.0.0.5", "172.16.3.4", "169.254.1.1", "fe80::1", "::1"]:
            self.assertEqual(bridge.validate_guest_host(f"  {h} "), h)

    def test_validate_guest_host_rejects_public_and_malformed(self):
        for h in ["8.8.8.8", "1.1.1.1", "http://10.0.0.1", "10.0.0.1/mcp", "", "   ", "10.0.0.1 ; rm"]:
            with self.assertRaises(ValueError, msg=h):
                bridge.validate_guest_host(h)

    def test_validate_guest_host_public_override(self):
        bridge.ALLOW_PUBLIC_HOST = True
        self.assertEqual(bridge.validate_guest_host("8.8.8.8"), "8.8.8.8")

    def test_set_guest_host_switches_and_resets_state(self):
        bridge._connections["127.0.0.1:5678"] = type("C", (), {"close": lambda self: None})()
        bridge._session_map[5678] = {"port": 5678}
        bridge._command_cache[(5678, "r")] = (0, {})
        res = bridge.set_guest_host("192.168.56.101")
        self.assertTrue(res["changed"])
        self.assertEqual(bridge.GUEST_IP, "192.168.56.101")
        self.assertEqual(res["guest_host"], "192.168.56.101")
        self.assertEqual(res["transport"], "http")
        self.assertEqual(bridge._connections, {})
        self.assertEqual(bridge._session_map, {})
        self.assertEqual(bridge._command_cache, {})
        self.assertIn("hint", res)  # no sessions found -> actionable hint
        self.assertIsNone(res["persisted_to"])

    def test_set_guest_host_same_host_is_noop(self):
        bridge._session_map[5678] = {"port": 5678}
        res = bridge.set_guest_host("127.0.0.1")
        self.assertFalse(res["changed"])
        self.assertEqual(bridge._session_map, {5678: {"port": 5678}})

    def test_set_guest_host_port_validation(self):
        for bad in [0, 70000, "5678", True]:
            with self.assertRaises(ValueError):
                bridge.set_guest_host("10.0.0.1", port=bad)
        res = bridge.set_guest_host("10.0.0.1", port=6000)
        self.assertEqual((bridge.GUEST_IP, bridge.BASE_PORT), ("10.0.0.1", 6000))
        self.assertEqual(res["base_port"], 6000)

    def test_set_guest_host_persist_writes_env_file(self):
        with open(bridge.ENV_FILE, "w", encoding="utf-8") as f:
            f.write("# comment\nWINDBG_MCP_HOST=10.9.9.9\nWINDBG_MCP_TRANSPORT=http\n")
        res = bridge.set_guest_host("192.168.56.7", port=5700, persist=True)
        self.assertEqual(res["persisted_to"], bridge.ENV_FILE)
        cfg = bridge.load_env_file(bridge.ENV_FILE)
        self.assertEqual(cfg["windbg_mcp_host"], "192.168.56.7")
        self.assertEqual(cfg["windbg_mcp_port"], "5700")
        self.assertEqual(cfg["windbg_mcp_transport"], "http")
        with open(bridge.ENV_FILE, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("# comment", text)
        self.assertEqual(text.count("WINDBG_MCP_HOST="), 1)

    def test_load_env_file_missing_and_quoted(self):
        self.assertEqual(bridge.load_env_file(os.path.join(self._tmpdir, "nope")), {})
        with open(bridge.ENV_FILE, "w", encoding="utf-8") as f:
            f.write('WINDBG_MCP_TOKEN="s3cret"\nbad line\nWINDBG_MCP_HOST = \'10.1.1.1\'\n')
        cfg = bridge.load_env_file(bridge.ENV_FILE)
        self.assertEqual(cfg, {"windbg_mcp_token": "s3cret", "windbg_mcp_host": "10.1.1.1"})

    def test_setting_precedence_env_over_file(self):
        orig_file = bridge._FILE_SETTINGS
        bridge._FILE_SETTINGS = {"windbg_mcp_host": "10.0.0.2"}
        try:
            os.environ.pop("WINDBG_MCP_HOST", None)
            self.assertEqual(bridge._setting(("windbg_mcp_host",), "127.0.0.1"), "10.0.0.2")
            os.environ["WINDBG_MCP_HOST"] = "10.0.0.3"
            self.assertEqual(bridge._setting(("windbg_mcp_host",), "127.0.0.1"), "10.0.0.3")
            self.assertEqual(bridge._setting(("windbg_mcp_other",), "dflt"), "dflt")
        finally:
            os.environ.pop("WINDBG_MCP_HOST", None)
            bridge._FILE_SETTINGS = orig_file

    def test_handle_set_guest_host_tool_response_and_notification(self):
        import io
        out = io.StringIO()
        resp = bridge.handle_set_guest_host(7, {"host": "192.168.56.2"}, out)
        self.assertEqual(resp["id"], 7)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(payload["guest_host"], "192.168.56.2")
        self.assertIn("notifications/tools/list_changed", out.getvalue())

        err = bridge.handle_set_guest_host(8, {"host": "8.8.8.8"}, io.StringIO())
        self.assertTrue(err["result"]["isError"])
        payload = json.loads(err["result"]["content"][0]["text"])
        self.assertEqual(payload["error"], "invalid_host")
        self.assertIn("ALLOW_PUBLIC_HOST", payload["message"])
        self.assertTrue(payload["next_steps"])

    def test_list_sessions_reports_gateway(self):
        bridge.get_sessions = lambda: [{"port": 5678}]
        resp = bridge.handle_list_sessions(1)
        payload = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(payload["guest_host"], "127.0.0.1")
        self.assertEqual(payload["sessions"], [{"port": 5678}])

    def test_bridge_local_tools_advertised(self):
        names = {t["name"] for t in bridge.get_default_tools_list()}
        self.assertIn("windbg.set_guest_host", names)
        self.assertIn("windbg.list_sessions", names)
        self.assertIn("windbg.discover_guests", names)

    def test_set_guest_host_persist_warns_when_env_var_shadows(self):
        os.environ["WINDBG_MCP_HOST"] = "10.0.0.9"
        try:
            res = bridge.set_guest_host("192.168.56.7", persist=True)
        finally:
            os.environ.pop("WINDBG_MCP_HOST", None)
        self.assertEqual(res["persisted_to"], bridge.ENV_FILE)
        self.assertTrue(any("WINDBG_MCP_HOST" in w for w in res["warnings"]))

    def test_set_guest_host_auto_uses_discovery(self):
        import ipaddress as _ip
        orig = bridge.discover_guests
        bridge.discover_guests = lambda port=None: {
            "scanned_networks": ["192.168.56.0/24"], "hosts_probed": 254, "port": 5678, "elapsed_seconds": 1.0,
            "candidates": [
                {"host": "192.168.56.5", "port": 5678, "sessions": [], "is_dbgx_mcp": False},
                {"host": "192.168.56.101", "port": 5678, "sessions": [{"port": 5678}], "is_dbgx_mcp": True},
            ],
        }
        try:
            res = bridge.set_guest_host("auto")
            self.assertEqual(res["guest_host"], "192.168.56.101")
            self.assertEqual(res["discovery"]["hosts_probed"], 254)

            bridge.discover_guests = lambda port=None: {
                "scanned_networks": [], "hosts_probed": 0, "port": 5678, "elapsed_seconds": 0.0, "candidates": []}
            with self.assertRaises(ValueError):
                bridge.set_guest_host("auto")
        finally:
            bridge.discover_guests = orig


class TestCommandClassification(unittest.TestCase):
    """First-token classification used for cache invalidation, retry safety and timeouts."""

    def test_first_token(self):
        for cmd, tok in [("r", "r"), ("r@rax", "r"), ("dd@rsp L4", "dd"), ("~1s", "~"), ("|0s", "|"),
                         ("k=rbp rsp rip", "k"), ("!peb", "!peb"), (".reload /f", ".reload"), ("? 1+1", "?"),
                         ("?? sizeof(int)", "??"), ("$$>< foo", "$$><"), ("lmvm ntdll", "lmvm")]:
            self.assertEqual(bridge._first_token(cmd), tok, cmd)

    def test_read_only_commands_do_not_mutate(self):
        for cmd in ["r", "r rax", "r @rax", "k", "kb 20", "kvn", "lm", "lmvm ntdll", "dd @rsp L4", "dps rsp",
                    "dt nt!_EPROCESS", "u rip", "uf main", "x nt!*", "!peb", "!analyze -v", "!process 0 0",
                    "dx @$curprocess", "bl", "~", "~*k", "version", "? 1+1", ".lastevent", "s -a 0 L1000 \"x\"",
                    "!ttdext.calls", "r; k; lm"]:
            self.assertFalse(bridge.command_mutates(cmd), cmd)

    def test_mutating_commands(self):
        for cmd in ["g", "p", "t", "gu", "bp main", "bc *", "ed @rsp 0", "eb 401000 90", "r rax=5", "r@rax=5",
                    "~1s", "|1s", ".reload", ".reload /f", ".sympath srv*", ".frame 3", ".process /p 0",
                    ".thread 1", "wt", "!tt 1B:0", ".load foo", ".scriptrun x.js", "ba e1 main",
                    "r; g", "k; .reload", ".if (1) { r }"]:
            self.assertTrue(bridge.command_mutates(cmd), cmd)

    def test_cache_ttl_token_based(self):
        self.assertEqual(bridge.get_cache_ttl("lm"), 120.0)
        self.assertEqual(bridge.get_cache_ttl("lmvm ntdll"), 120.0)
        self.assertEqual(bridge.get_cache_ttl("r"), 5.0)
        self.assertEqual(bridge.get_cache_ttl("r rax"), 5.0)
        self.assertEqual(bridge.get_cache_ttl("version"), 300.0)
        self.assertEqual(bridge.get_cache_ttl("x nt!Ke*"), 120.0)
        # never cached
        for cmd in ["r rax=5", "r@rax=5", "x", "!dlls -c kernel32", "dd @rsp", "version; r", "g", "lm; .reload"]:
            self.assertEqual(bridge.get_cache_ttl(cmd), 0.0, cmd)

    def _t(self, command):
        return bridge.get_timeout_for_request({"method": "tools/call", "params": {"name": "windbg.eval", "arguments": {"command": command}}})

    def test_timeouts_no_substring_false_positives(self):
        # These used to match 'r' / '?' / 'lm' as substrings.
        self.assertEqual(self._t("dt nt!_EPROCESS"), 90.0)
        self.assertEqual(self._t("bp kernel32!CreateFileW"), 60.0)
        self.assertEqual(self._t("dps rsp"), 90.0)
        self.assertEqual(self._t("!dlls"), 180.0)
        self.assertEqual(self._t("lmvm ntdll"), 180.0)
        self.assertEqual(self._t("r"), 10.0)
        self.assertEqual(self._t("version"), 10.0)
        self.assertEqual(self._t(".reload -f"), 1200.0)
        self.assertEqual(self._t(".reload /f ntdll.dll"), 1200.0)
        self.assertEqual(self._t(".reload"), 300.0)
        self.assertEqual(self._t("!process 0 1f"), 480.0)
        self.assertEqual(self._t("!process -1 0"), 300.0)
        self.assertEqual(self._t("!analyze -v"), 300.0)
        self.assertEqual(self._t("!analyze"), 120.0)
        self.assertEqual(self._t("!for_each_module .echo @#ModuleName"), 900.0)
        self.assertEqual(self._t("some_unknown_cmd"), 60.0)
        # chained -> longest wins
        self.assertEqual(self._t("r; .reload /f"), 1200.0)

    def test_guardrail_uses_first_token(self):
        ok, _ = bridge.validate_command("qd")
        self.assertFalse(ok)
        ok, _ = bridge.validate_command(".kill")
        self.assertFalse(ok)
        ok, _ = bridge.validate_command("dx @$queue")  # starts with 'q' but is not 'q'
        self.assertTrue(ok)
        ok, _ = bridge.validate_command("!shell")
        self.assertFalse(ok)
        detail = bridge.validate_command_detail(".detach")
        self.assertEqual(detail["blocked"], ".detach")
        self.assertIn("windbg.continue", detail["alternative"])

    def test_tool_traits(self):
        self.assertFalse(bridge.tool_mutates("windbg.get_context", {}))
        self.assertTrue(bridge.tool_mutates("windbg.step", {}))
        self.assertTrue(bridge.tool_mutates("windbg.eval", {"command": "g"}))
        self.assertFalse(bridge.tool_mutates("windbg.eval", {"command": "k"}))
        self.assertFalse(bridge.tool_mutates("windbg.ttd_position", {}))
        self.assertTrue(bridge.tool_mutates("windbg.ttd_position", {"position": "1B:0"}))
        self.assertTrue(bridge.tool_mutates("windbg.totally_new", {}))

        self.assertTrue(bridge.tool_is_retry_safe("windbg.read_memory", {}))
        self.assertTrue(bridge.tool_is_retry_safe("windbg.eval", {"command": "lm"}))
        self.assertFalse(bridge.tool_is_retry_safe("windbg.eval", {"command": "p"}))
        self.assertFalse(bridge.tool_is_retry_safe("windbg.step", {}))
        self.assertFalse(bridge.tool_is_retry_safe("windbg.continue", {}))
        self.assertFalse(bridge.tool_is_retry_safe("windbg.set_breakpoint", {}))
        self.assertTrue(bridge.tool_is_retry_safe("windbg.clear_breakpoint", {}))
        self.assertTrue(bridge.tool_is_retry_safe("windbg.write_memory", {}))
        self.assertFalse(bridge.tool_is_retry_safe("windbg.totally_new", {}))

    def test_annotations_cover_every_default_tool(self):
        for tool in bridge.get_default_tools_list():
            bridge.annotate_tool(tool)
            self.assertIn("annotations", tool, tool["name"])
            self.assertIn("readOnlyHint", tool["annotations"])
        self.assertTrue(bridge.TOOL_TRAITS["windbg.get_modules"]["readOnlyHint"])
        self.assertTrue(bridge.TOOL_TRAITS["windbg.write_memory"]["destructiveHint"])


class _FakeConn:
    """Stand-in for http.client.HTTPConnection with scripted failures."""

    def __init__(self, script, sent):
        self.script = script          # list of callables run per request() / getresponse()
        self.sent = sent              # shared list of bodies that reached the "server"
        self.sock = None
        self.timeout = None

    def request(self, method, path, body=None, headers=None):
        action = self.script.pop(0) if self.script else None
        if action == "send_fail":
            raise ConnectionRefusedError(111, "refused")
        self.sock = object()
        self.sent.append(body)
        self._next = action

    def getresponse(self):
        if self._next == "timeout":
            import socket as _s
            raise _s.timeout("timed out")
        if self._next == "remote_disconnected":
            import http.client as _h
            raise _h.RemoteDisconnected("closed")

        class R:
            status = 200

            def read(self_inner):
                return b'{"jsonrpc":"2.0","id":1,"result":{}}'
        return R()

    def close(self):
        self.sock = None


class TestRetryPolicy(unittest.TestCase):
    """forward_post must never re-send a request that may have executed."""

    def setUp(self):
        self._orig_get_connection = bridge.get_connection
        bridge._connections.clear()
        self.sent = []

    def tearDown(self):
        bridge.get_connection = self._orig_get_connection
        bridge._connections.clear()

    def _install(self, scripts):
        conns = [(_FakeConn(s, self.sent)) for s in scripts]
        it = iter(conns)
        cache = {}

        def fake_get_connection(host, port, timeout=60.0):
            key = f"{host}:{port}"
            if key not in bridge._connections:
                bridge._connections[key] = next(it)
            return bridge._connections[key]
        bridge.get_connection = fake_get_connection
        return conns

    def test_timeout_is_never_retried(self):
        self._install([["timeout"], ["timeout"], [None]])
        with self.assertRaises(bridge.BackendTimeout):
            bridge.forward_post("h", 1, "/mcp", b"g", retry_safe=False)
        self.assertEqual(self.sent, [b"g"])
        with self.assertRaises(bridge.BackendTimeout):
            bridge.forward_post("h", 1, "/mcp", b"lm", retry_safe=True)
        self.assertEqual(self.sent, [b"g", b"lm"])

    def test_send_failure_is_retried_for_everyone(self):
        self._install([["send_fail"], [None]])
        data, status = bridge.forward_post("h", 1, "/mcp", b"p", retry_safe=False)
        self.assertEqual(status, 200)
        self.assertEqual(self.sent, [b"p"])  # reached the server exactly once

    def test_stale_keepalive_retried_only_when_safe(self):
        conns = self._install([[None, "remote_disconnected"], [None]])
        bridge.forward_post("h", 1, "/mcp", b"lm", retry_safe=True)       # warms the keep-alive
        self.assertIs(bridge._connections["h:1"], conns[0])
        bridge.forward_post("h", 1, "/mcp", b"lm", retry_safe=True)       # stale -> retried
        self.assertEqual(self.sent, [b"lm", b"lm", b"lm"])

        self.sent.clear()
        bridge._connections.clear()
        conns = self._install([[None, "remote_disconnected"], [None]])
        bridge.forward_post("h", 1, "/mcp", b"lm", retry_safe=True)
        with self.assertRaises(Exception):
            bridge.forward_post("h", 1, "/mcp", b"g", retry_safe=False)  # stale -> NOT retried
        self.assertEqual(self.sent, [b"lm", b"g"])


class TestDispatch(unittest.TestCase):
    """handle_request end-to-end with a scripted backend."""

    def setUp(self):
        import io
        self.out = io.StringIO()
        self._saved = {k: getattr(bridge, k) for k in ("forward_mcp_message", "get_sessions", "_current_port", "GUEST_IP", "BASE_PORT")}
        bridge.GUEST_IP = "127.0.0.1"
        bridge.BASE_PORT = 5678
        bridge._current_port = 5678
        bridge._command_cache.clear()
        bridge._session_map.clear()
        self.sessions = [{"port": 5678, "pid": 4242, "pipe_name": "dbgx-mcp-5678"}]
        bridge.get_sessions = lambda: bridge._publish_sessions([dict(s) for s in self.sessions])
        self.forwarded = []
        self.backend = lambda body: {"jsonrpc": "2.0", "id": json.loads(body)["id"], "result": {"content": [{"type": "text", "text": "ok"}]}}

        def fake_forward(session, body_bytes, timeout=60.0, retry_safe=False):
            self.forwarded.append((session.get("port"), json.loads(body_bytes), timeout, retry_safe))
            r = self.backend(body_bytes)
            if isinstance(r, Exception):
                raise r
            return json.dumps(r).encode(), 200
        bridge.forward_mcp_message = fake_forward

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(bridge, k, v)
        bridge._command_cache.clear()
        bridge._session_map.clear()

    def _call(self, req_id, name, args=None, extra_params=None):
        params = {"name": name, "arguments": args or {}}
        if extra_params:
            params.update(extra_params)
        bridge.handle_request(json.dumps({"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": params}), self.out)
        lines = [json.loads(l) for l in self.out.getvalue().splitlines() if l.strip()]
        return [l for l in lines if l.get("id") == req_id][-1]

    def _payload(self, resp):
        return json.loads(resp["result"]["content"][0]["text"])

    def test_parse_error_gets_reply(self):
        bridge.handle_request("{not json", self.out)
        resp = json.loads(self.out.getvalue())
        self.assertEqual(resp["error"]["code"], -32700)

    def test_guardrail_is_iserror_with_alternative(self):
        resp = self._call(1, "windbg.eval", {"command": "r; .kill"})
        self.assertTrue(resp["result"]["isError"])
        p = self._payload(resp)
        self.assertEqual(p["error"], "command_blocked")
        self.assertEqual(p["blocked"], ".kill")
        self.assertTrue(p["next_steps"])
        self.assertEqual(self.forwarded, [])

    def test_cache_invalidated_by_mutating_tool(self):
        self._call(1, "windbg.eval", {"command": "r"})
        self._call(2, "windbg.eval", {"command": "r"})
        self.assertEqual(len(self.forwarded), 1)  # second 'r' served from cache
        self._call(3, "windbg.step", {})
        self._call(4, "windbg.eval", {"command": "r"})
        self.assertEqual(len(self.forwarded), 3)  # step + fresh 'r'
        self._call(5, "windbg.eval", {"command": "r rax=1"})
        self._call(6, "windbg.eval", {"command": "r"})
        self.assertEqual(len(self.forwarded), 5)  # register write flushed the cache

    def test_cache_is_session_scoped(self):
        self._call(1, "windbg.eval", {"command": "lm"})
        self.sessions[0]["pid"] = 9999  # WinDbg restarted on the same port
        bridge._session_map.clear()
        self._call(2, "windbg.eval", {"command": "lm"})
        self.assertEqual(len(self.forwarded), 2)

    def test_session_id_routing_and_unknown_session(self):
        self.sessions.append({"port": 5679, "pid": 4343})
        resp = self._call(1, "windbg.get_context", {"session_id": 5679})
        self.assertNotIn("isError", resp["result"])
        self.assertEqual(self.forwarded[-1][0], 5679)
        self.assertNotIn("session_id", self.forwarded[-1][1]["params"]["arguments"])

        resp = self._call(2, "windbg.get_context", {"session_id": 7000})
        p = self._payload(resp)
        self.assertEqual(p["error"], "unknown_session")
        self.assertEqual([s["port"] for s in p["sessions_now"]], [5678, 5679])

    def test_backend_timeout_is_not_retried_and_explained(self):
        self.backend = lambda body: bridge.BackendTimeout("no response within 60s")
        resp = self._call(1, "windbg.continue", {})
        p = self._payload(resp)
        self.assertEqual(p["error"], "backend_timeout")
        self.assertTrue(any("NOT retried" in s for s in p["next_steps"]))
        self.assertEqual(len(self.forwarded), 1)

    def test_backend_unreachable_payload(self):
        self.backend = lambda body: ConnectionRefusedError("refused")
        resp = self._call(1, "windbg.get_modules", {})
        p = self._payload(resp)
        self.assertEqual(p["error"], "backend_unreachable")
        self.assertEqual(p["guest_host"], "127.0.0.1")
        self.assertTrue(p["next_steps"])

    def test_retry_safe_flag_passed_per_call(self):
        self._call(1, "windbg.eval", {"command": "k"})
        self._call(2, "windbg.eval", {"command": "g"})
        self._call(3, "windbg.step", {})
        self.assertEqual([f[3] for f in self.forwarded], [True, False, False])

    def test_initialize_without_sessions_is_instant_and_has_instructions(self):
        self.sessions.clear()
        bridge.handle_request(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}), self.out)
        resp = json.loads(self.out.getvalue())
        self.assertEqual(resp["result"]["protocolVersion"], "2025-03-26")
        self.assertIn("windbg.list_sessions", resp["result"]["instructions"])
        self.assertEqual(self.forwarded, [])

    def test_initialize_with_session_injects_instructions(self):
        self.backend = lambda body: {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "dbgx-mcp"}}}
        bridge.handle_request(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}), self.out)
        resp = json.loads(self.out.getvalue())
        self.assertIn("instructions", resp["result"])
        self.assertEqual(resp["result"]["capabilities"]["tools"], {"listChanged": True})

    def test_tools_list_annotated_and_local_tools_added(self):
        self.backend = lambda body: {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "windbg.write_memory", "inputSchema": {"type": "object", "properties": {}}}]}}
        bridge.handle_request(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}), self.out)
        tools = {t["name"]: t for t in json.loads(self.out.getvalue())["result"]["tools"]}
        self.assertTrue(tools["windbg.write_memory"]["annotations"]["destructiveHint"])
        self.assertIn("session_id", tools["windbg.write_memory"]["inputSchema"]["properties"])
        self.assertIn("windbg.discover_guests", tools)
        self.assertTrue(tools["windbg.list_sessions"]["annotations"]["readOnlyHint"])

    def test_progress_heartbeat_emitted_with_token(self):
        import time as _time
        orig = bridge.PROGRESS_INTERVAL_SECONDS
        bridge.PROGRESS_INTERVAL_SECONDS = 0.05

        def slow(body):
            _time.sleep(0.2)
            return {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}
        self.backend = slow
        try:
            self._call(1, "windbg.eval", {"command": ".reload"}, extra_params={"_meta": {"progressToken": "tok1"}})
        finally:
            bridge.PROGRESS_INTERVAL_SECONDS = orig
        notes = [json.loads(l) for l in self.out.getvalue().splitlines() if '"notifications/progress"' in l]
        self.assertGreaterEqual(len(notes), 2)
        self.assertEqual(notes[0]["params"]["progressToken"], "tok1")
        self.assertEqual(notes[0]["params"]["total"], 300.0)

    def test_no_progress_without_token(self):
        self._call(1, "windbg.eval", {"command": "k"})
        self.assertNotIn("notifications/progress", self.out.getvalue())


class TestDiscovery(unittest.TestCase):
    def test_discover_guests_with_stubbed_network(self):
        import ipaddress as _ip
        orig_open, orig_scan = bridge._tcp_open, bridge.scan_port
        bridge._tcp_open = lambda h, p, t: h in ("192.168.56.101", "192.168.56.7")
        bridge.scan_port = lambda port, host=None, timeout=0.3: [{"port": port}] if host == "192.168.56.101" else []
        try:
            res = bridge.discover_guests(port=5678, networks=[_ip.ip_network("192.168.56.0/24")])
        finally:
            bridge._tcp_open, bridge.scan_port = orig_open, orig_scan
        self.assertEqual(res["hosts_probed"], 254)
        self.assertEqual([c["host"] for c in res["candidates"]], ["192.168.56.101", "192.168.56.7"])
        self.assertTrue(res["candidates"][0]["is_dbgx_mcp"])
        self.assertFalse(res["candidates"][1]["is_dbgx_mcp"])

    def test_discovery_budget(self):
        import ipaddress as _ip
        orig_open = bridge._tcp_open
        bridge._tcp_open = lambda h, p, t: False
        try:
            res = bridge.discover_guests(port=5678, networks=[_ip.ip_network("10.0.0.0/16")])
        finally:
            bridge._tcp_open = orig_open
        self.assertEqual(res["hosts_probed"], bridge.DISCOVERY_MAX_HOSTS)

    def test_local_lab_networks_are_private_only(self):
        for net in bridge.local_lab_networks():
            self.assertTrue(net.is_private or net.is_link_local, str(net))


if __name__ == "__main__":
    unittest.main()
