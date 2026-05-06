"""OpenAI solver — manual function-calling loop into Docker sandbox.

Uses the official openai Python SDK with AsyncOpenAI.  The solver implements
the same public interface as ClaudeSolver so FindingSwarm treats it uniformly.
submit_triage / notify_coordinator are intercepted before commands reach the
container.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time

import openai

from backend.cost_tracker import CostTracker
from backend.loop_detect import LOOP_WARNING_MESSAGE, LoopDetector
from backend.models import model_id_from_spec
from backend.output_types import SemgrepFinding, TriageVerdict
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

_BASH_TOOL_DEF: dict = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": (
            "Execute a bash command in the Docker sandbox. "
            "The target repo is at /target (read-only). "
            "The Semgrep finding is at /finding.json (read-only). "
            "Scratch space is at /workspace (read-write). "
            "Use 'submit_triage <json>' as the command to submit your verdict. "
            "Use 'notify_coordinator <msg>' as the command to message the coordinator."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": (
                        "Bash command to run, or 'submit_triage <json>', "
                        "or 'notify_coordinator <msg>'"
                    ),
                }
            },
            "required": ["command"],
            "additionalProperties": False,
        },
        "strict": True,
    },
}


class OpenAISolver:
    """OpenAI solver using a manual function-calling loop into Docker sandbox."""

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

        api_key = getattr(settings, "openai_api_key", "") or os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            raise ValueError("OPENAI_API_KEY is not set — cannot create OpenAISolver")
        self._client = openai.AsyncOpenAI(api_key=api_key)

        self._messages: list[dict] = []
        self._started = False
        self._step_count = 0
        self._verdict: TriageVerdict | None = None
        self._findings_summary = ""
        self._cost_usd = 0.0
        self._bump_insights: str | None = None
        self._budget_exceeded = False

    async def start(self) -> None:
        await self.sandbox.start()
        system_content = (
            "IMPORTANT: You are running inside a Docker sandbox (--network none). "
            "The target repo is at /target (read-only). "
            "The Semgrep finding is at /finding.json (read-only). "
            "A writable scratch area is at /workspace. "
            "Use the bash tool for ALL file operations and code execution. "
            "To submit your verdict call bash with: submit_triage '{\"verdict\": ...}'. "
            "To message the coordinator call bash with: notify_coordinator 'msg'.\n\n"
        ) + build_solver_prompt(self.finding)
        self._messages = [{"role": "system", "content": system_content}]
        self._started = True
        self.tracer.event(
            "start", finding_id=self.finding.finding_id, model=self.model_id, provider="openai"
        )
        logger.info("[%s] OpenAISolver started", self.agent_name)

    async def _handle_bash(self, command: str) -> str:
        """Intercept submit_triage / notify_coordinator; exec everything else in sandbox."""

        # submit_triage is always allowed even after budget exhaustion
        triage_match = re.match(r"submit_triage\s+(.+)$", command.strip(), re.DOTALL)
        if triage_match:
            raw = triage_match.group(1).strip()
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
                self.tracer.event(
                    "triage_submitted",
                    verdict=self._verdict.verdict,
                    confidence=self._verdict.confidence,
                    step=self._step_count,
                )
                return f"Verdict recorded: {self._verdict.verdict} (confidence={self._verdict.confidence:.2f})"
            except Exception as exc:
                return f"Error parsing triage JSON: {exc}. Check your JSON syntax and retry."

        # notify_coordinator is always allowed
        notify_match = re.match(r"notify_coordinator\s+['\"]?(.+?)['\"]?\s*$", command.strip())
        if notify_match and self.notify_coordinator:
            await self.notify_coordinator(notify_match.group(1).strip())
            return "Message sent to coordinator."

        # Step budget check (sandbox-bound commands only)
        self._step_count += 1
        self.tracer.tool_call("bash", {"command": command[:200]}, self._step_count)

        max_steps = getattr(self.settings, "max_solver_steps", 30)
        if max_steps > 0 and self._step_count >= max_steps:
            self._budget_exceeded = True
            self.tracer.event("step_budget_exceeded", step=self._step_count, max_steps=max_steps)
            return (
                f"Step budget of {max_steps} reached ({self._step_count} steps used). "
                "Do NOT call any more bash commands. "
                "Call bash immediately with: submit_triage '{\"verdict\": ..., \"confidence\": ..., "
                "\"reasoning\": ..., \"exploitability\": ...}'"
            )

        # Loop detection
        loop_status = self.loop_detector.check("bash", command[:200])
        if loop_status == "break":
            self.tracer.event("loop_break", step=self._step_count)
            return (
                "Loop detected — you have run this exact command several times with the same result. "
                "Try a completely different approach, or submit your verdict if you have enough information."
            )
        extra_context = LOOP_WARNING_MESSAGE if loop_status == "warn" else ""

        # Periodic sibling insights injection
        if self._step_count % 5 == 0 and self.message_bus:
            from backend.tools.core import do_check_findings
            insights = await do_check_findings(self.message_bus, self.model_spec)
            if insights and "No new findings" not in insights:
                extra_context = (extra_context + f"\n\n[Sibling insight]: {insights}").strip()

        # Execute in sandbox
        try:
            result = await self.sandbox.exec(command, timeout_s=120)
            output = result.stdout
            if result.stderr:
                output += "\n[stderr]: " + result.stderr
            output = output[:8000]
            self.tracer.tool_result("bash", output[:500], self._step_count)
            if extra_context:
                output = output + f"\n\n{extra_context}"
            return output
        except Exception as exc:
            return f"Execution error: {exc}"

    async def run_until_done_or_gave_up(self) -> SolverResult:
        if not self._started:
            await self.start()

        t0 = time.monotonic()
        steps_before = self._step_count
        cost_before = self._cost_usd

        try:
            if self._bump_insights:
                self._messages.append({
                    "role": "user",
                    "content": (
                        "Your previous investigation did not reach a verdict. "
                        f"Insights from other agents:\n\n{self._bump_insights}\n\n"
                        "Try a different investigation angle. Do NOT repeat what was tried before."
                    ),
                })
                self._bump_insights = None
            elif len(self._messages) > 1:
                # Continuing an existing session
                self._messages.append({
                    "role": "user",
                    "content": "Continue your investigation. Try a different approach.",
                })
            else:
                self._messages.append({
                    "role": "user",
                    "content": "Investigate this finding and submit your triage verdict.",
                })

            while not self.cancel_event.is_set():
                response = await self._client.chat.completions.create(
                    model=self.model_id,
                    messages=self._messages,
                    tools=[_BASH_TOOL_DEF],
                    tool_choice="auto",
                    max_completion_tokens=8192,
                )

                # Track token usage
                usage = response.usage
                if usage:
                    in_tok = usage.prompt_tokens or 0
                    out_tok = usage.completion_tokens or 0
                    details = getattr(usage, "prompt_tokens_details", None)
                    cached = getattr(details, "cached_tokens", 0) or 0
                    self.cost_tracker.record_tokens(
                        self.agent_name,
                        self.model_id,
                        input_tokens=in_tok,
                        output_tokens=out_tok,
                        cache_read_tokens=cached,
                        provider_spec="openai",
                        duration_seconds=time.monotonic() - t0,
                    )
                    agent_usage = self.cost_tracker.by_agent.get(self.agent_name)
                    if agent_usage:
                        self._cost_usd = agent_usage.cost_usd

                choice = response.choices[0]
                msg = choice.message

                if msg.content:
                    self._findings_summary = msg.content[:2000]

                # Append assistant turn (serialise to dict so we can send back later)
                assistant_entry: dict = {"role": "assistant"}
                if msg.content:
                    assistant_entry["content"] = msg.content
                if msg.tool_calls:
                    assistant_entry["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in msg.tool_calls
                    ]
                self._messages.append(assistant_entry)

                if not msg.tool_calls:
                    break  # model finished without calling a tool → GAVE_UP

                # Execute all tool calls (OpenAI may batch multiple in one response)
                for tc in msg.tool_calls:
                    if tc.function.name == "bash":
                        try:
                            args = json.loads(tc.function.arguments)
                            command = args.get("command", "")
                        except json.JSONDecodeError:
                            command = tc.function.arguments
                        output = await self._handle_bash(command)
                    else:
                        output = f"Unknown tool '{tc.function.name}'. Only 'bash' is available."

                    self._messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": output,
                    })

                if self._verdict is not None:
                    break

                # Periodic sibling insights as a user message (between turns)
                if self._step_count > 0 and self._step_count % 5 == 0 and self.message_bus:
                    from backend.tools.core import do_check_findings
                    insights = await do_check_findings(self.message_bus, self.model_spec)
                    if insights and "No new findings" not in insights:
                        self._messages.append({
                            "role": "user",
                            "content": f"[Coordinator update]: {insights}",
                        })

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
        except Exception as exc:
            error_str = str(exc)
            logger.error("[%s] Error: %s", self.agent_name, exc, exc_info=True)
            self._findings_summary = f"Error: {exc}"
            self.tracer.event("error", error=error_str[:500])
            if any(kw in error_str.lower() for kw in ("quota", "rate", "429", "too many")):
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
        try:
            await self._client.close()
        except Exception:
            pass
        if self.sandbox:
            await self.sandbox.stop()
