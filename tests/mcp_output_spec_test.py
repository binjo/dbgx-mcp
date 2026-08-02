#!/usr/bin/env python3
"""Validate MCP JSON-RPC output shapes from the running extension.

Usage:
  python tests/mcp_output_spec_test.py
  python tests/mcp_output_spec_test.py --base-url http://127.0.0.1:5678/mcp --command "r eax"

The target MCP server must already be running.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any, Callable, cast


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def post_json(
    url: str,
    payload: Any,
    timeout: float,
    protocol_version: str,
    *,
    raw: bool = False,
) -> tuple[int, str]:
    if raw:
        body_bytes = str(payload).encode("utf-8")
    else:
        body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "MCP-Protocol-Version": protocol_version,
    }
    request = urllib.request.Request(
        url, data=body_bytes, headers=headers, method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read().decode(
                "utf-8", errors="replace"
            )
    except urllib.error.HTTPError as error:
        return int(error.code), error.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as error:
        raise RuntimeError(f"Failed to reach MCP server at {url}: {error}") from error


def parse_json(body: str) -> dict[str, Any]:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"Response is not valid JSON: {error}. Body: {body!r}"
        ) from error

    expect(isinstance(parsed, dict), "Top-level response must be a JSON object")
    return cast(dict[str, Any], parsed)


def validate_success_envelope(
    payload: dict[str, Any], expected_id: Any
) -> dict[str, Any]:
    expect(payload.get("jsonrpc") == "2.0", "jsonrpc must be '2.0'")
    expect(payload.get("id") == expected_id, f"id must equal {expected_id!r}")
    expect("result" in payload, "Successful response must include result")
    expect("error" not in payload, "Successful response must not include error")
    result = payload["result"]
    expect(isinstance(result, dict), "result must be a JSON object")
    return cast(dict[str, Any], result)


def validate_error_envelope(
    payload: dict[str, Any], expected_id: Any, expected_code: int
) -> dict[str, Any]:
    expect(payload.get("jsonrpc") == "2.0", "jsonrpc must be '2.0'")
    expect(payload.get("id") == expected_id, f"id must equal {expected_id!r}")
    error = payload.get("error")
    expect(isinstance(error, dict), "Error response must include object field 'error'")
    error_dict = cast(dict[str, Any], error)
    expect(
        error_dict.get("code") == expected_code, f"error.code must be {expected_code}"
    )
    expect(isinstance(error_dict.get("message"), str), "error.message must be a string")
    return error_dict


def case_initialize(
    base_url: str, timeout: float, protocol_version: str, _: str
) -> None:
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": protocol_version},
    }
    status, body = post_json(base_url, request, timeout, protocol_version)

    expect(status == 200, f"initialize should return HTTP 200, got {status}")
    payload = parse_json(body)
    result = validate_success_envelope(payload, 1)

    expect(
        isinstance(result.get("protocolVersion"), str),
        "initialize.result.protocolVersion must be a string",
    )

    capabilities = result.get("capabilities")
    expect(
        isinstance(capabilities, dict),
        "initialize.result.capabilities must be an object",
    )
    capabilities_dict = cast(dict[str, Any], capabilities)
    tools = capabilities_dict.get("tools")
    expect(
        isinstance(tools, dict),
        "initialize.result.capabilities.tools must be an object",
    )
    tools_dict = cast(dict[str, Any], tools)
    expect(
        isinstance(tools_dict.get("listChanged"), bool),
        "initialize.result.capabilities.tools.listChanged must be bool",
    )

    available_tools = tools_dict.get("availableTools")
    expect(
        isinstance(available_tools, list),
        "initialize.result.capabilities.tools.availableTools must be a list",
    )
    available_tools_list = cast(list[Any], available_tools)
    expect(
        "windbg.eval" in available_tools_list,
        "initialize must advertise windbg.eval in availableTools",
    )
    expect(
        "windbg.dx" in available_tools_list,
        "initialize must advertise windbg.dx in availableTools",
    )
    expect(
        "windbg.get_context" in available_tools_list,
        "initialize must advertise windbg.get_context in availableTools",
    )
    expect(
        "windbg.read_memory" in available_tools_list,
        "initialize must advertise windbg.read_memory in availableTools",
    )
    expect(
        "windbg.carve_pe" in available_tools_list,
        "initialize must advertise windbg.carve_pe in availableTools",
    )
    expect(
        "windbg.search" in available_tools_list,
        "initialize must advertise windbg.search in availableTools",
    )
    expect(
        "windbg.get_execution_state" in available_tools_list,
        "initialize must advertise windbg.get_execution_state in availableTools",
    )
    expect(
        "windbg.interrupt" in available_tools_list,
        "initialize must advertise windbg.interrupt in availableTools",
    )
    expect(
        "windbg.search_catalog" in available_tools_list,
        "initialize must advertise windbg.search_catalog in availableTools",
    )
    expect(
        "windbg.get_command_docs" in available_tools_list,
        "initialize must advertise windbg.get_command_docs in availableTools",
    )
    expect(
        "windbg.get_session_metadata" in available_tools_list,
        "initialize must advertise windbg.get_session_metadata in availableTools",
    )
    expect(
        "windbg.write_memory" in available_tools_list,
        "initialize must advertise windbg.write_memory in availableTools",
    )
    expect(
        "windbg.get_threads" in available_tools_list,
        "initialize must advertise windbg.get_threads in availableTools",
    )
    expect(
        "windbg.apply_synthetic_type" in available_tools_list,
        "initialize must advertise windbg.apply_synthetic_type in availableTools",
    )
    expect(
        "windbg.apply_struct" in available_tools_list,
        "initialize must advertise windbg.apply_struct in availableTools",
    )
    expect(
        "windbg.write_file" in available_tools_list,
        "initialize must advertise windbg.write_file in availableTools",
    )

    server_info = result.get("serverInfo")
    expect(
        isinstance(server_info, dict), "initialize.result.serverInfo must be an object"
    )
    server_info_dict = cast(dict[str, Any], server_info)
    expect(
        isinstance(server_info_dict.get("name"), str)
        and bool(server_info_dict.get("name")),
        "serverInfo.name must be non-empty string",
    )
    expect(
        isinstance(server_info_dict.get("version"), str)
        and bool(server_info_dict.get("version")),
        "serverInfo.version must be non-empty string",
    )


def case_tools_list(
    base_url: str, timeout: float, protocol_version: str, _: str
) -> None:
    request = {
        "jsonrpc": "2.0",
        "id": "tools-list",
        "method": "tools/list",
        "params": {},
    }
    status, body = post_json(base_url, request, timeout, protocol_version)

    expect(status == 200, f"tools/list should return HTTP 200, got {status}")
    payload = parse_json(body)
    result = validate_success_envelope(payload, "tools-list")

    tools = result.get("tools")
    expect(isinstance(tools, list), "tools/list.result.tools must be a list")
    tools_list = cast(list[Any], tools)
    expect(len(tools_list) > 0, "tools/list.result.tools must not be empty")

    windbg_eval: dict[str, Any] | None = None
    for tool in tools_list:
        if isinstance(tool, dict) and tool.get("name") == "windbg.eval":
            windbg_eval = cast(dict[str, Any], tool)
            break
    expect(windbg_eval is not None, "tools/list must include tool named windbg.eval")
    windbg_eval_dict = cast(dict[str, Any], windbg_eval)

    expect(
        isinstance(windbg_eval_dict.get("description"), str),
        "windbg.eval.description must be a string",
    )
    description_value = windbg_eval_dict.get("description")
    description_text = (
        cast(str, description_value)
        if isinstance(description_value, str)
        else ""
    )
    expect(
        "serial" in description_text.lower(),
        "windbg.eval.description must require serial execution semantics",
    )
    expect(
        "wait" in description_text.lower() and "next" in description_text.lower(),
        "windbg.eval.description must require waiting before next command",
    )
    input_schema = windbg_eval_dict.get("inputSchema")
    expect(isinstance(input_schema, dict), "windbg.eval.inputSchema must be an object")
    input_schema_dict = cast(dict[str, Any], input_schema)
    expect(
        input_schema_dict.get("type") == "object",
        "windbg.eval.inputSchema.type must be 'object'",
    )

    properties = input_schema_dict.get("properties")
    expect(
        isinstance(properties, dict),
        "windbg.eval.inputSchema.properties must be an object",
    )
    properties_dict = cast(dict[str, Any], properties)
    command_schema = properties_dict.get("command")
    expect(
        isinstance(command_schema, dict),
        "windbg.eval.inputSchema.properties.command must be an object",
    )
    command_schema_dict = cast(dict[str, Any], command_schema)
    expect(
        command_schema_dict.get("type") == "string",
        "windbg.eval.inputSchema.properties.command.type must be 'string'",
    )
    command_description = command_schema_dict.get("description")
    command_description_text = (
        cast(str, command_description)
        if isinstance(command_description, str)
        else ""
    )
    expect(
        "one by one" in command_description_text.lower(),
        "command description must require one-by-one execution",
    )
    expect(
        "wait" in command_description_text.lower()
        and "before" in command_description_text.lower(),
        "command description must require waiting before the next command",
    )

    required = input_schema_dict.get("required")
    expect(
        isinstance(required, list), "windbg.eval.inputSchema.required must be a list"
    )
    required_list = cast(list[Any], required)
    expect(
        "command" in required_list,
        "windbg.eval.inputSchema.required must include 'command'",
    )
    expect(
        input_schema_dict.get("additionalProperties") is False,
        "windbg.eval.inputSchema.additionalProperties must be false",
    )


def case_tools_call_success_shape(
    base_url: str, timeout: float, protocol_version: str, command: str
) -> None:
    request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "windbg.eval",
            "arguments": {"command": command},
        },
    }
    status, body = post_json(base_url, request, timeout, protocol_version)

    expect(status == 200, f"tools/call should return HTTP 200, got {status}")
    payload = parse_json(body)
    result = validate_success_envelope(payload, 2)

    content = result.get("content")
    expect(isinstance(content, list), "tools/call.result.content must be a list")
    content_list = cast(list[Any], content)
    expect(len(content_list) > 0, "tools/call.result.content must not be empty")
    first = content_list[0]
    expect(isinstance(first, dict), "tools/call.result.content[0] must be an object")
    first_dict = cast(dict[str, Any], first)
    expect(
        first_dict.get("type") == "text",
        "tools/call.result.content[0].type must be 'text'",
    )
    expect(
        isinstance(first_dict.get("text"), str),
        "tools/call.result.content[0].text must be a string",
    )
    expect(
        isinstance(result.get("isError"), bool),
        "tools/call.result.isError must be bool",
    )


def case_tools_call_missing_command(
    base_url: str, timeout: float, protocol_version: str, _: str
) -> None:
    request = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "windbg.eval",
            "arguments": {},
        },
    }
    status, body = post_json(base_url, request, timeout, protocol_version)

    expect(
        status == 200,
        f"tools/call missing command should return HTTP 200, got {status}",
    )
    payload = parse_json(body)
    validate_error_envelope(payload, 3, -32602)


def case_unknown_method(
    base_url: str, timeout: float, protocol_version: str, _: str
) -> None:
    request = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "unknown/method",
        "params": {},
    }
    status, body = post_json(base_url, request, timeout, protocol_version)

    expect(status == 200, f"unknown method should return HTTP 200, got {status}")
    payload = parse_json(body)
    validate_error_envelope(payload, 4, -32601)


def case_parse_error(
    base_url: str, timeout: float, protocol_version: str, _: str
) -> None:
    status, body = post_json(
        base_url, "this-is-not-json", timeout, protocol_version, raw=True
    )

    expect(status == 400, f"invalid JSON should return HTTP 400, got {status}")
    payload = parse_json(body)
    validate_error_envelope(payload, None, -32700)


def case_notification_no_id(
    base_url: str, timeout: float, protocol_version: str, _: str
) -> None:
    request = {
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {},
    }
    status, body = post_json(base_url, request, timeout, protocol_version)

    expect(
        status == 202, f"notification without id should return HTTP 202, got {status}"
    )
    expect(body == "", "notification response body must be empty")


def case_initialized_notification(
    base_url: str, timeout: float, protocol_version: str, _: str
) -> None:
    request = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }
    status, body = post_json(base_url, request, timeout, protocol_version)

    expect(
        status == 202,
        f"initialized notification should return HTTP 202, got {status}",
    )
    expect(body == "", "initialized notification response body must be empty")


def run_case(
    name: str,
    case: Callable[[str, float, str, str], None],
    base_url: str,
    timeout: float,
    protocol_version: str,
    command: str,
) -> bool:
    try:
        case(base_url, timeout, protocol_version, command)
    except Exception as error:  # noqa: BLE001
        print(f"[FAIL] {name}: {error}")
        return False

    print(f"[PASS] {name}")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate MCP output specification from a running endpoint"
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:5678/mcp",
        help="MCP endpoint URL (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP timeout seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--protocol-version",
        default="2025-11-25",
        help="Value for MCP-Protocol-Version request header (default: %(default)s)",
    )
    parser.add_argument(
        "--command",
        default="version",
        help="WinDbg command used in tools/call shape test (default: %(default)s)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    cases: list[tuple[str, Callable[[str, float, str, str], None]]] = [
        ("initialize response shape", case_initialize),
        ("tools/list response shape", case_tools_list),
        ("tools/call result shape", case_tools_call_success_shape),
        ("tools/call invalid params shape", case_tools_call_missing_command),
        ("unknown method error shape", case_unknown_method),
        ("invalid JSON parse error shape", case_parse_error),
        ("notification without id behavior", case_notification_no_id),
        ("initialized notification behavior", case_initialized_notification),
    ]

    passed = 0
    failed = 0
    for name, case in cases:
        if run_case(
            name, case, args.base_url, args.timeout, args.protocol_version, args.command
        ):
            passed += 1
        else:
            failed += 1

    print()
    print(f"Summary: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
