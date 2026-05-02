"""Shared tool helpers — used by solver agents."""

from __future__ import annotations


async def do_check_findings(message_bus, model_spec: str) -> str:
    """Get unread insight messages from sibling solvers."""
    if not message_bus:
        return "No message bus available."
    messages = await message_bus.check(model_spec)
    if not messages:
        return "No new findings from other agents."
    return message_bus.format_unread(messages)
