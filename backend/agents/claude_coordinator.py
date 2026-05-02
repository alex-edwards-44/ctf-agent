"""Claude Agent SDK coordinator for vuln-triage."""

from __future__ import annotations

import logging
from typing import Any

from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
    ResultMessage,
    create_sdk_mcp_server,
    tool,
)

from backend.agents.coordinator_core import (
    do_broadcast,
    do_bump_solver,
    do_get_triage_status,
    do_kill_swarm,
    do_read_solver_trace,
    do_spawn_swarm,
)
from backend.agents.coordinator_loop import build_deps, run_triage_loop
from backend.config import Settings
from backend.deps import CoordinatorDeps
from backend.output_types import SemgrepFinding
from backend.prompts import build_coordinator_prompt

logger = logging.getLogger(__name__)


def _text(s: str) -> dict:
    return {"content": [{"type": "text", "text": s}]}


def _build_coordinator_mcp(deps: CoordinatorDeps):
    """Build MCP server with triage coordinator tools."""

    @tool("get_triage_status", "List all findings with their current triage status.", {})
    async def get_triage_status(args: dict) -> dict:
        return _text(await do_get_triage_status(deps))

    @tool("spawn_swarm", "Launch solvers to triage a finding.", {"finding_id": str})
    async def spawn_swarm(args: dict) -> dict:
        return _text(await do_spawn_swarm(deps, args["finding_id"]))

    @tool("kill_swarm", "Cancel all solvers for a finding.", {"finding_id": str})
    async def kill_swarm(args: dict) -> dict:
        return _text(await do_kill_swarm(deps, args["finding_id"]))

    @tool("bump_solver", "Send targeted insights to a stuck solver.", {"finding_id": str, "model_spec": str, "insights": str})
    async def bump_solver(args: dict) -> dict:
        return _text(await do_bump_solver(deps, args["finding_id"], args["model_spec"], args["insights"]))

    @tool("broadcast", "Broadcast a hint to all solvers on a finding.", {"finding_id": str, "message": str})
    async def broadcast(args: dict) -> dict:
        return _text(await do_broadcast(deps, args["finding_id"], args["message"]))

    @tool("read_solver_trace", "Read recent trace events from a solver.", {"finding_id": str, "model_spec": str, "last_n": int})
    async def read_solver_trace(args: dict) -> dict:
        return _text(await do_read_solver_trace(deps, args["finding_id"], args["model_spec"], args.get("last_n", 20)))

    return create_sdk_mcp_server(
        name="coordinator", version="1.0.0",
        tools=[get_triage_status, spawn_swarm, kill_swarm, bump_solver, broadcast, read_solver_trace],
    )


async def run_claude_coordinator(
    settings: Settings,
    findings: list[SemgrepFinding],
    target_dir: str,
    model_specs: list[str] | None = None,
    coordinator_model: str | None = None,
    msg_port: int = 0,
) -> dict[str, Any]:
    """Run the Claude Agent SDK coordinator over the findings queue."""
    cost_tracker, deps = build_deps(settings, findings, target_dir, model_specs)
    deps.msg_port = msg_port

    mcp_server = _build_coordinator_mcp(deps)
    resolved_model = coordinator_model or "claude-opus-4-6"
    system_prompt = build_coordinator_prompt(len(findings))

    allowed = {
        "mcp__coordinator__get_triage_status",
        "mcp__coordinator__spawn_swarm",
        "mcp__coordinator__kill_swarm",
        "mcp__coordinator__bump_solver",
        "mcp__coordinator__broadcast",
        "mcp__coordinator__read_solver_trace",
        "ToolSearch",
        "TaskCreate", "TaskUpdate", "TaskGet", "TaskList", "TaskOutput", "TaskStop",
    }

    async def enforce_allowlist(input_data, tool_use_id, context):
        if input_data.get("hook_event_name") != "PreToolUse":
            return {}
        t = input_data.get("tool_name", "")
        if t in allowed:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"{t} not available to coordinator.",
            }
        }

    options = ClaudeAgentOptions(
        model=resolved_model,
        system_prompt=system_prompt,
        env={"CLAUDECODE": ""},
        mcp_servers={"coordinator": mcp_server},
        allowed_tools=list(allowed),
        permission_mode="bypassPermissions",
        hooks={
            "PreToolUse": [HookMatcher(hooks=[enforce_allowlist])],
        },
    )

    async with ClaudeSDKClient(options=options) as client:
        async def turn_fn(msg: str) -> None:
            logger.debug("Coordinator query: %s", msg[:200])
            await client.query(msg)
            msg_count = 0
            async for message in client.receive_response():
                msg_count += 1
                if isinstance(message, ResultMessage):
                    cost = getattr(message, "total_cost_usd", 0)
                    session = getattr(message, "session_id", None)
                    logger.info(
                        "Coordinator turn done (messages=%d, cost=$%.4f, session=%s)",
                        msg_count, cost, session,
                    )
            if msg_count == 0:
                logger.warning("Coordinator turn produced no messages!")

        return await run_triage_loop(deps, cost_tracker, turn_fn)
