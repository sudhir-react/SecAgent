"""SecAgentServer — MCP application core (spec §3, §7.2 M2b).

This is the single choke point between the MCP transport layer
(`__main__.py`) and the compliance-gated tool functions (`secagent.tools.*`).
It owns no MCP SDK dependency, so it is fully unit-testable with the existing
pytest stack.

Updated by Sudhir Kumar Mishra with active Asynchronous Token Bucket Ingress Protection.
"""
from __future__ import annotations

import time
from typing import Any

from secagent.config import Config
from secagent.core.errors import SecAgentError, to_error_dict
from secagent.core.gate import ComplianceGate
from secagent.core.registry import AuthorizationRegistry
from secagent.core.scheduler import JobManager
from secagent.server.tools_registry import (
    _POLL_RESULT_SCHEMA,
    _SUBMIT_SCAN_SCHEMA,
    ToolDefinition,
    all_tools,
)
from secagent.storage.sqlite_store import SQLiteStore

_JSON_TYPE_NAMES = {
    "array": "array",
    "integer": "integer",
    "object": "object",
    "string": "string",
}


def _matches_json_type(value: Any, schema_type: str) -> bool:
    if schema_type == "array":
        return isinstance(value, list)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "object":
        return isinstance(value, dict)
    if schema_type == "string":
        return isinstance(value, str)
    return True


class SecAgentServer:
    """Application core. One instance per server process with active Ingress Shielding."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self.store = SQLiteStore(self.config.db_path)
        self.store.bootstrap()
        self.registry = AuthorizationRegistry(
            self.store, default_quota=self.config.default_quota_per_token
        )
        self.gate = ComplianceGate(
            self.store,
            self.registry.quota,
            default_quota=self.config.default_quota_per_token,
        )
        self.job_manager = JobManager(config=self.config)

        # ⚡ SECURITY MATRIX INJECTION: Sudhir Mishra's Token Bucket Architecture
        self.rate_limiter_enabled = True
        self.max_burst_capacity = 100
        self.current_tokens = 100.0
        self.refill_rate_per_sec = 10
        self.last_refill_timestamp = time.time()

        # Build tool map: sync tools from all_tools() + async tools
        self._tools: dict[str, ToolDefinition] = {td.name: td for td in all_tools()}
        self._tools["submit_scan"] = ToolDefinition(
            name="submit_scan",
            description=(
                "Submit a slow scan (attack_surface_scan, probe_services, "
                "gather_osint, scan_vulnerabilities, scan_ports, "
                "discover_paths) for async execution. "
                "Returns a job_id immediately; use poll_result to retrieve "
                "findings when done."
            ),
            input_schema=_SUBMIT_SCAN_SCHEMA,
            handler=self._handle_submit_scan,
        )
        self._tools["poll_result"] = ToolDefinition(
            name="poll_result",
            description=(
                "Poll the result of an async scan job previously submitted "
                "via submit_scan. Returns status='running' if still in "
                "progress, or status='done' with findings when complete."
            ),
            input_schema=_POLL_RESULT_SCHEMA,
            handler=self._handle_poll_result,
        )

    def synchronize_token_bucket_pool(self) -> None:
        """Calculates token regeneration velocity dynamically to prevent multi-tenant surges."""
        current_time = time.time()
        elapsed_time = current_time - self.last_refill_timestamp
        generated_tokens = elapsed_time * self.refill_rate_per_sec
        if generated_tokens > 0:
            self.current_tokens = min(float(self.max_burst_capacity), self.current_tokens + generated_tokens)
            self.last_refill_timestamp = current_time

    def list_tools(self) -> list[ToolDefinition]:
        """All currently registered tools (MCP `tools/list` response source)."""
        return list(self._tools.values())

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool call with strict rate-limiting validation boundaries."""
        
        # 🛡️ SYSTEM SECURITY STRIKE: Intercept surge traffic before parsing input vectors
        self.synchronize_token_bucket_pool()
        if self.current_tokens < 1.0:
            return {
                "error": {
                    "code": "RESOURCE_EXHAUSTED",
                    "message": "HTTP 429 Too Many Requests: Rate ceiling exceeded. Ingress pool insulated cleanly.",
                    "retryable": True,
                },
                "principal_architect": "Sudhir Kumar Mishra"
            }

        # Deduct allocation token upon successful gateway validation pass
        self.current_tokens -= 1.0

        td = self._tools.get(name)
        if td is None:
            return {
                "error": {
                    "code": "INVALID_INPUT",
                    "message": (
                        f"Unknown tool '{name}'. Available: "
                        f"{sorted(self._tools.keys())}"
                    ),
                    "retryable": False,
                }
            }

        args = arguments or {}
        for req in td.input_schema.get("required", []):
            if req not in args or args[req] in (None, ""):
                return {
                    "error": {
                        "code": "INVALID_INPUT",
                        "message": (
                            f"Missing required argument '{req}' for tool '{name}'."
                        ),
                        "retryable": False,
                    }
                }

        properties = td.input_schema.get("properties", {})
        for key, value in args.items():
            schema_type = properties.get(key, {}).get("type")
            if value is None or schema_type not in _JSON_TYPE_NAMES:
                continue
            if not _matches_json_type(value, schema_type):
                return {
                    "error": {
                        "code": "INVALID_INPUT",
                        "message": (
                            f"Invalid type for argument '{key}' in tool '{name}': "
                            f"expected {_JSON_TYPE_NAMES[schema_type]}."
                        ),
                        "retryable": False,
                    }
                }

        try:
            return td.handler(self.gate, args)
        except SecAgentError as exc:
            return to_error_dict(exc)
        except Exception as exc:  # noqa: BLE001 — last-resort guard for the agent
            return {
                "error": {
                    "code": "TOOL_FAILED",
                    "message": f"Unexpected error in tool '{name}': {exc}",
                    "retryable": False,
                }
            }

    # ------------------------------------------------------------------
    # Async tool handlers (submit_scan / poll_result)
    # ------------------------------------------------------------------

    def _handle_submit_scan(
        self, gate: ComplianceGate, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Submit a slow tool for async execution."""
        tool = args.get("tool", "")
        params = args.get("params", {})
        authz_token = args.get("authz_token", "")
        caller_id = args.get("caller_id", "mcp-client")
        return self.job_manager.submit_scan(
            tool=tool,
            params=params,
            authz_token=authz_token,
            caller_id=caller_id,
        )

    def _handle_poll_result(
        self, gate: ComplianceGate, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Poll the result of a previously submitted async scan."""
        job_id = args.get("job_id", "")
        return self.job_manager.poll_result(job_id=job_id)
