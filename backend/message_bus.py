"""Per-finding message bus for inter-solver communication."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class SolverMessage:
    model: str
    content: str
    timestamp: float = field(default_factory=time.time)


MAX_MESSAGES = 200


@dataclass
class FindingMessageBus:
    """Append-only shared message list with per-model cursors."""

    messages: list[SolverMessage] = field(default_factory=list)
    cursors: dict[str, int] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def post(self, model: str, content: str) -> None:
        """Post a message from a solver."""
        async with self._lock:
            self.messages.append(SolverMessage(model=model, content=content))
            if len(self.messages) > MAX_MESSAGES:
                trim = len(self.messages) - MAX_MESSAGES
                self.messages = self.messages[trim:]
                self.cursors = {k: max(0, v - trim) for k, v in self.cursors.items()}

    async def check(self, model: str) -> list[SolverMessage]:
        """Get unread messages from other models. Advances the cursor."""
        async with self._lock:
            cursor = self.cursors.get(model, 0)
            unread = [m for m in self.messages[cursor:] if m.model != model]
            self.cursors[model] = len(self.messages)
            return unread

    async def broadcast(self, content: str, source: str = "coordinator") -> None:
        """Coordinator broadcasts a message to all solvers."""
        await self.post(source, content)

    def format_unread(self, messages: list[SolverMessage]) -> str:
        """Format messages for injection into a solver prompt."""
        if not messages:
            return ""
        parts = [f"[{m.model}] {m.content}" for m in messages]
        return "**Insights from other agents:**\n\n" + "\n\n".join(parts)


# Alias for code that still uses the old name
ChallengeMessageBus = FindingMessageBus
