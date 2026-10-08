"""Guard against schema drift between the C++ server and the Python bridge.

The DLL advertises its tool roster via the string literal in
``HandleToolsList()`` (src/mcp/json_rpc.cpp).  The bridge ships a fallback
roster in ``get_default_tools_list()`` that is served to clients before any
WinDbg session is reachable.  If the two disagree, clients get a schema that
the server will reject (e.g. a wrong required-parameter name).

This test extracts the C++ string literal, decodes it as JSON, and compares
tool names, ``required`` lists and property keys against the bridge list.
"""

import importlib
import json
import os
import re
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(ROOT)
bridge = importlib.import_module("windbg-bridge")

JSON_RPC_CPP = os.path.join(ROOT, "src", "mcp", "json_rpc.cpp")

# Tools that only exist on the bridge side (synthesised locally, never
# forwarded) or that the server accepts as aliases without advertising.
BRIDGE_ONLY_TOOLS = {"windbg.list_sessions", "windbg.set_guest_host"}
SERVER_ALIASES = {"windbg.get_catalog_entry": "windbg.get_command_docs"}

# Parameter injected by the bridge for multi-session routing.
BRIDGE_INJECTED_PROPS = {"session_id"}


def _decode_cpp_string_literal(body: str) -> str:
  """Concatenate adjacent C++ string literals and unescape them."""
  pieces = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
  raw = "".join(pieces)
  # Handle the C escapes used in json_rpc.cpp: \" \\ \n \t
  return (
      raw.replace("\\\\", "\x00")
      .replace('\\"', '"')
      .replace("\\n", "\n")
      .replace("\\t", "\t")
      .replace("\x00", "\\")
  )


def load_server_tools() -> dict:
  with open(JSON_RPC_CPP, "r", encoding="utf-8") as f:
    src = f.read()
  start = src.index("MethodOutcome HandleToolsList()")
  lit_start = src.index("outcome.result_json =", start)
  # Descriptions may contain ';', so bound the literal by the next statement.
  lit_end = src.index("return outcome;", lit_start)
  literal = src[lit_start + len("outcome.result_json ="):lit_end]
  decoded = _decode_cpp_string_literal(literal)
  doc = json.loads(decoded)
  return {t["name"]: t for t in doc["tools"]}


def load_bridge_tools() -> dict:
  return {t["name"]: t for t in bridge.get_default_tools_list()}


class TestSchemaDrift(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.server = load_server_tools()
    cls.bridge = load_bridge_tools()

  def test_server_literal_is_valid_json(self):
    self.assertGreater(len(self.server), 20)

  def test_tool_rosters_match(self):
    server_names = set(self.server)
    bridge_names = set(self.bridge) - BRIDGE_ONLY_TOOLS - set(SERVER_ALIASES)
    self.assertEqual(
        server_names,
        bridge_names,
        f"missing in bridge: {sorted(server_names - bridge_names)}; "
        f"missing in server: {sorted(bridge_names - server_names)}",
    )

  def test_required_params_match(self):
    for name, server_tool in self.server.items():
      with self.subTest(tool=name):
        bridge_tool = self.bridge[name]
        s_req = set(server_tool["inputSchema"].get("required", []))
        b_req = set(bridge_tool["inputSchema"].get("required", []))
        self.assertEqual(s_req, b_req)

  def test_property_keys_match(self):
    for name, server_tool in self.server.items():
      with self.subTest(tool=name):
        bridge_tool = self.bridge[name]
        s_props = set(server_tool["inputSchema"].get("properties", {}))
        b_props = (
            set(bridge_tool["inputSchema"].get("properties", {}))
            - BRIDGE_INJECTED_PROPS
        )
        self.assertEqual(s_props, b_props)

  def test_property_types_match(self):
    for name, server_tool in self.server.items():
      with self.subTest(tool=name):
        s_props = server_tool["inputSchema"].get("properties", {})
        b_props = self.bridge[name]["inputSchema"].get("properties", {})
        for prop, spec in s_props.items():
          self.assertEqual(spec.get("type"), b_props[prop].get("type"), prop)

  def test_aliases_resolve_to_server_tools(self):
    for alias, target in SERVER_ALIASES.items():
      self.assertIn(alias, self.bridge)
      self.assertIn(target, self.server)
      a_req = set(self.bridge[alias]["inputSchema"].get("required", []))
      t_req = set(self.server[target]["inputSchema"].get("required", []))
      self.assertEqual(a_req, t_req)


if __name__ == "__main__":
  unittest.main()
