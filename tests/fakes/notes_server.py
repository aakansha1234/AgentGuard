"""A small upstream MCP server (stdio) for proxy tests.

Tools: read_notes (read-only), add_note (changes state), whoami (reports whether
the credential AgentGuard passed is present), fail (always errors).
"""

from __future__ import annotations

import os

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

server = MCPServer("notes")
NOTES: list[str] = []


@server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
def read_notes() -> str:
    """Return every note."""
    return "\n".join(NOTES) or "(no notes)"


@server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
def add_note(text: str, priority: int = 1) -> str:
    """Add a note."""
    NOTES.append(f"[p{priority}] {text}")
    return f"saved note {len(NOTES)}"


@server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
def whoami() -> str:
    """Report the credential this server was started with."""
    token = os.environ.get("NOTES_TOKEN", "")
    leaked = "PARENT_SECRET" in os.environ
    return f"token={'set' if token else 'missing'} len={len(token)} leaked_parent={leaked}"


@server.tool()
def fail() -> str:
    """Always fails."""
    raise RuntimeError("upstream exploded")


if __name__ == "__main__":
    server.run("stdio")
