"""Claude Agent SDK solver — intercepts bash commands into Docker sandbox.

Uses Claude's native Bash tool but rewrites every command to run inside the
vuln-sandbox container via `docker exec`. The solver triages a single Semgrep
finding; when done it calls `submit_triage '{...}'` which is intercepted here.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shlex
import time

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
    ResultMessage,
    TextBlock,
)

from backend.cost_tracker import CostTracker
from backend.loop_detect import LoopDetector
from backend.models import effort_from_spec, model_id_from_spec
from backend.output_types import SemgrepFinding, TriageVerdict, solver_output_json_schema
from backend.prompts import build_solver_prompt
from backend.sandbox import DockerSandbox
from backend.solver_base import (
    CANCELLED,
    ERROR,
    GAVE_UP,
    QUOTA_ERROR,
    STEP_LIMIT,
    TRIAGE_DONE,
    SolverResult,
)
from backend.tracing import SolverTracer

logger = logging.getLogger(__name__)


class ClaudeSolver:
    """Claude Agent SDK solver using native tools redirected to Docker sandbox."""

    def __init__(
        self,
        model_spec: str,
        finding: SemgrepFinding,
        target_dir: str,
        finding_json_path: str,
        cost_tracker: CostTracker,
        settings: object,
        cancel_event: asyncio.Event | None = None,
        message_bus=None,
        notify_coordinator=None,
    ) -> None:
        self.model_spec = model_spec
        self.model_id = model_id_from_spec(model_spec)
        self.finding = finding
        self.target_dir = target_dir
        self.finding_json_path = finding_json_path
        self.cost_tracker = cost_tracker
        self.settings = settings
        self.cancel_event = cancel_event or asyncio.Event()
        self.message_bus = message_bus
        self.notify_coordinator = notify_coordinator

        self.sandbox = DockerSandbox(
            image=getattr(settings, "sandbox_image", "vuln-sandbox"),
            target_dir=target_dir,
            finding_json_path=finding_json_path,
            memory_limit=getattr(settings, "container_memory_limit", "8g"),
            no_network=True,
        )
        self.loop_detector = LoopDetector()
        self.tracer = SolverTracer(finding.finding_id, self.model_id)
        self.agent_name = f"{finding.finding_id}/{self.model_id}"

        self._client: ClaudeSDKClient | None = None
        self._session_id: str | None = None
        self._container_id: str = ""
        self._step_count = 0
        self._verdict: TriageVerdict | None = None
        self._findings_summary = ""
        self._cost_usd = 0.0
        self._bump_insights: str | None = None
        self._budget_exceeded = False

    async def start(self) -> None:
        await self.sandbox.start()
        self._container_id = self.sandbox.container_id

        system_prompt = (
            "IMPORTANT: You are running inside a Docker sandbox (--network none). "
            "The target repo is at /target (read-only). "
            "The Semgrep finding is at /finding.json (read-only). "
            "A writable scratch area is at /workspace. "
            "All bash commands run inside this container via docker exec. "
            "Use bash for all file operations: cat/head/grep/rg/find/jq. "
            "submit_triage '<json>' to submit your verdict. "
            "notify_coordinator 'MSG' to send a message to the coordinator.\n\n"
        ) + build_solver_prompt(self.finding)

        async def sandbox_redirect(input_data, tool_use_id, context):
            try:
                return await _sandbox_redirect_inner(input_data, tool_use_id, context)
            except Exception as e:
                logger.warning("[%s] PreToolUse hook error: %s", self.agent_name, e)
                return {}

        async def _sandbox_redirect_inner(input_data, tool_use_id, context):
            if input_data.get("hook_event_name") != "PreToolUse":
                return {}

            tool_name = input_data.get("tool_name", "")
            tool_input = input_data.get("tool_input", {})

            self._step_count += 1
            self.tracer.tool_call(tool_name, tool_input, self._step_count)

            # STRATEGY: per-solver step budget
            max_steps = getattr(self.settings, "max_solver_steps", 30)
            if max_steps > 0 and self._step_count >= max_steps:
                if not self._budget_exceeded:
                    self._budget_exceeded = True
                    logger.info(
                        "[%s] Step budget of %d reached — stopping solver",
                        self.agent_name, max_steps,
                    )
                    self.tracer.event("step_budget_exceeded", step=self._step_count, max_steps=max_steps)
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"Step budget of {max_steps} reached ({self._step_count} steps used). "
                            "No more tool calls — submit your verdict now using submit_triage."
                        ),
                    }
                }

            from backend.loop_detect import LOOP_WARNING_MESSAGE
            loop_status = self.loop_detector.check(tool_name, str(tool_input)[:200])
            if loop_status == "break":
                self.tracer.event("loop_break", tool=tool_name, step=self._step_count)
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": "Loop detected — try a different approach.",
                    }
                }
            warn_msg = LOOP_WARNING_MESSAGE if loop_status == "warn" else ""

            if tool_name == "Bash":
                command = tool_input.get("command", "")

                # Intercept submit_triage
                triage_match = re.match(
                    r"submit_triage\s+(.+)$", command.strip(), re.DOTALL
                )
                if triage_match:
                    raw = triage_match.group(1).strip()
                    # Strip surrounding quotes
                    if (raw.startswith("'") and raw.endswith("'")) or (
                        raw.startswith('"') and raw.endswith('"')
                    ):
                        raw = raw[1:-1]
                    try:
                        data = json.loads(raw)
                        self._verdict = TriageVerdict(
                            finding_id=self.finding.finding_id,
                            verdict=data["verdict"],
                            confidence=float(data.get("confidence", 0.5)),
                            reasoning=data.get("reasoning", ""),
                            exploitability=data.get("exploitability", "n/a"),
                            proof_of_concept=data.get("proof_of_concept"),
                            remediation=data.get("remediation"),
                        )
                        result_msg = (
                            f"Triage verdict recorded: {self._verdict.verdict} "
                            f"(confidence={self._verdict.confidence:.2f})"
                        )
                        self.tracer.event(
                            "triage_submitted",
                            verdict=self._verdict.verdict,
                            confidence=self._verdict.confidence,
                            step=self._step_count,
                        )
                    except Exception as e:
                        result_msg = f"Error parsing triage JSON: {e}. Check your JSON syntax and retry."
                    return {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "allow",
                            "updatedInput": {
                                **tool_input,
                                "command": f"echo {shlex.quote(result_msg)}",
                            },
                        }
                    }

                # Intercept notify_coordinator
                notify_match = re.match(
                    r"notify_coordinator\s+['\"]?(.+?)['\"]?\s*$", command.strip()
                )
                if notify_match and self.notify_coordinator:
                    msg = notify_match.group(1).strip()
                    await self.notify_coordinator(msg)
                    return {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "allow",
                            "updatedInput": {
                                **tool_input,
                                "command": "echo 'Message sent to coordinator.'",
                            },
                        }
                    }

                # Rewrite command to run in container
                escaped = shlex.quote(command)
                rewritten = f"docker exec -i {self._container_id} bash -c {escaped}"
                result = {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "updatedInput": {**tool_input, "command": rewritten},
                    }
                }
                if warn_msg:
                    result["systemMessage"] = warn_msg
                return result

            # Block all non-Bash tools — model uses bash for everything
            redirect_hint = ""
            if tool_name in ("Glob", "Grep"):
                redirect_hint = " Use `find`/`rg` via bash instead."
            elif tool_name in ("Read", "Write", "Edit", "NotebookEdit"):
                redirect_hint = " Use cat/head/rg/tee via bash."

            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        f"{tool_name} blocked — use bash for all sandbox operations.{redirect_hint}"
                    ),
                }
            }

        async def trace_post_tool(input_data, tool_use_id, context):
            try:
                return await _trace_post_tool_inner(input_data, tool_use_id, context)
            except Exception as e:
                logger.warning("[%s] PostToolUse hook error: %s", self.agent_name, e)
                return {}

        async def _trace_post_tool_inner(input_data, tool_use_id, context):
            if input_data.get("hook_event_name") != "PostToolUse":
                return {}
            response_str = str(input_data.get("tool_response", ""))[:2000]
            self.tracer.tool_result(
                input_data.get("tool_name", "?"), response_str[:500], self._step_count
            )
            if self._step_count % 5 == 0 and self.message_bus:
                from backend.tools.core import do_check_findings
                insights = await do_check_findings(self.message_bus, self.model_spec)
                if insights and "No new findings" not in insights:
                    return {
                        "hookSpecificOutput": {
                            "hookEventName": "PostToolUse",
                            "additionalContext": insights,
                        }
                    }
            return {}

        effort = effort_from_spec(self.model_spec)
        options = ClaudeAgentOptions(
            model=self.model_id,
            system_prompt=system_prompt,
            effort=effort,
            env={"CLAUDECODE": ""},
            allowed_tools=["Bash"],
            permission_mode="bypassPermissions",
            output_format={"type": "json_schema", "schema": solver_output_json_schema()},
            hooks={
                "PreToolUse": [HookMatcher(hooks=[sandbox_redirect])],
                "PostToolUse": [HookMatcher(hooks=[trace_post_tool])],
            },
        )

        self._client = ClaudeSDKClient(options=options)
        await self._client.__aenter__()
        self.tracer.event("start", finding_id=self.finding.finding_id, model=self.model_id)
        logger.info("[%s] ClaudeSolver started", self.agent_name)

    async def run_until_done_or_gave_up(self) -> SolverResult:
        if not self._client:
            await self.start()
        assert self._client is not None

        t0 = time.monotonic()
        cost_before = self._cost_usd
        steps_before = self._step_count

        try:
            if self._bump_insights:
                prompt = (
                    "Your previous investigation did not reach a verdict. "
                    f"Insights from other agents:\n\n{self._bump_insights}\n\n"
                    "Try a different investigation angle. Do NOT repeat what was tried."
                )
                self._bump_insights = None
            elif self._session_id:
                prompt = "Continue your investigation. Try a different approach."
            else:
                prompt = "Investigate this finding and submit your triage verdict."

            await self._client.query(prompt)

            async for message in self._client.receive_response():
                if self.cancel_event.is_set():
                    break

                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            self._findings_summary = block.text[:2000]

                elif isinstance(message, ResultMessage):
                    self._session_id = message.session_id
                    turn_cost = getattr(message, "total_cost_usd", 0.0)
                    self._cost_usd += turn_cost
                    msg_usage = getattr(message, "usage", None) or {}
                    if not isinstance(msg_usage, dict):
                        msg_usage = vars(msg_usage) if hasattr(msg_usage, "__dict__") else {}
                    self.cost_tracker.record_tokens(
                        self.agent_name, self.model_id,
                        input_tokens=msg_usage.get("input_tokens", 0),
                        output_tokens=msg_usage.get("output_tokens", 0),
                        cache_read_tokens=msg_usage.get(
                            "cache_read_input_tokens", msg_usage.get("cache_read_tokens", 0)
                        ),
                        provider_spec="claude-sdk",
                        duration_seconds=time.monotonic() - t0,
                    )
                    # Structured output fallback
                    output = getattr(message, "structured_output", None)
                    if output and self._verdict is None:
                        try:
                            self._verdict = TriageVerdict(
                                finding_id=self.finding.finding_id,
                                verdict=output["verdict"],
                                confidence=float(output.get("confidence", 0.5)),
                                reasoning=output.get("reasoning", ""),
                                exploitability=output.get("exploitability", "n/a"),
                                proof_of_concept=output.get("proof_of_concept"),
                                remediation=output.get("remediation"),
                            )
                            self.tracer.event(
                                "triage_submitted_via_schema",
                                verdict=self._verdict.verdict,
                            )
                        except Exception as e:
                            logger.warning("[%s] Failed to parse structured output: %s", self.agent_name, e)

            self.tracer.event(
                "turn_complete",
                duration=round(time.monotonic() - t0, 1),
                cost=round(self._cost_usd, 4),
            )

            run_steps = self._step_count - steps_before
            run_cost = self._cost_usd - cost_before

            if self._verdict is not None:
                return self._result(TRIAGE_DONE, run_steps=run_steps, run_cost=run_cost)
            if self._budget_exceeded:
                return self._result(STEP_LIMIT, run_steps=run_steps, run_cost=run_cost)
            return self._result(GAVE_UP, run_steps=run_steps, run_cost=run_cost)

        except asyncio.CancelledError:
            return self._result(CANCELLED)
        except Exception as e:
            error_str = str(e)
            logger.error("[%s] Error: %s", self.agent_name, e, exc_info=True)
            self._findings_summary = f"Error: {e}"
            self.tracer.event("error", error=error_str)
            if "quota" in error_str.lower() or "rate" in error_str.lower() or "overloaded" in error_str.lower():
                return self._result(QUOTA_ERROR)
            return self._result(ERROR)

    def bump(self, insights: str) -> None:
        self._bump_insights = insights
        self.loop_detector.reset()
        self.tracer.event("bump", insights=insights[:500])
        logger.info("[%s] Bumped with insights", self.agent_name)

    def _result(
        self,
        status: str,
        run_steps: int | None = None,
        run_cost: float | None = None,
    ) -> SolverResult:
        self.tracer.event(
            "finish",
            status=status,
            verdict=self._verdict.verdict if self._verdict else None,
            cost_usd=round(self._cost_usd, 4),
        )
        return SolverResult(
            verdict=self._verdict,
            status=status,
            findings_summary=self._findings_summary[:2000],
            step_count=run_steps if run_steps is not None else self._step_count,
            cost_usd=run_cost if run_cost is not None else self._cost_usd,
            log_path=self.tracer.path,
        )

    async def stop(self) -> None:
        self.tracer.event("stop", step_count=self._step_count)
        self.tracer.close()
        if self._client:
            try:
                await self._client.__aexit__(None, None, None)
            except Exception:
                pass
            self._client = None
        if self.sandbox:
            await self.sandbox.stop()
