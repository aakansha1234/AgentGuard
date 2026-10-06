"""How to point each kind of agent at an AgentGuard run (`agentguard connect --client ...`).

Every client gets the same thing: the MCP endpoint and the run's bearer token.
What differs is how to keep the agent from acting *around* AgentGuard: only
calls to AgentGuard's tools are checked, so an agent's own built-in tools
(shell, file edits, web, code execution) must be turned off or contained.
"""

from __future__ import annotations

import json
import shlex

CLIENTS = ("claude", "codex", "api")

# Codex features that give the model tools outside AgentGuard. Code mode can't be
# turned off: in current Codex versions MCP tool calls go through it.
CODEX_DISABLED_FEATURES = (
    "shell_tool",
    "unified_exec",
    "unified_exec_tty",
    "apply_patch_freeform",
    "browser_use",
    "browser_use_external",
    "computer_use",
    "plugins",
    "apps",
    "goals",
    "image_generation",
    "multi_agent",
    "view_image",
    "skill_search",
    "tool_suggest",
    "hooks",
    "remote_plugin",
    "in_app_browser",
    "worktrees",
)


def claude_code(url: str, token: str) -> str:
    server = {"type": "http", "url": url, "headers": {"Authorization": f"Bearer {token}"}}
    config = json.dumps({"mcpServers": {"agentguard": server}}, separators=(",", ":"))
    return f"""Claude Code, interactive (adds AgentGuard to your MCP servers):
  claude mcp add --transport http agentguard {url} --header "Authorization: Bearer {token}"

Claude Code, headless and locked down to AgentGuard's tools (what the dashboard's Live mode runs):
  echo {shlex.quote(config)} > agentguard-mcp.json
  CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT=600000 claude -p \\
    --mcp-config agentguard-mcp.json --strict-mcp-config \\
    --tools "" --allowedTools "mcp__agentguard__*" \\
    --permission-mode dontAsk --setting-sources "" \\
    "Investigate Alice's failed logins and summarize."

  --tools "" removes Claude Code's built-in tools (shell, files, web), so every action goes
  through AgentGuard. The idle timeout must exceed the approval time limit."""


def codex(url: str, token: str) -> str:
    disabled = " ".join(f"--disable {f}" for f in CODEX_DISABLED_FEATURES)
    return f"""Codex (codex exec), with every AgentGuard tool call checked:
  export AGENTGUARD_RUN_TOKEN={token}
  codex exec --ephemeral --ignore-user-config --skip-git-repo-check -s read-only \\
    {disabled} \\
    -c 'web_search="disabled"' \\
    -c 'mcp_servers.agentguard.url="{url}"' \\
    -c 'mcp_servers.agentguard.bearer_token_env_var="AGENTGUARD_RUN_TOKEN"' \\
    -c 'mcp_servers.agentguard.default_tools_approval_mode="approve"' \\
    -c 'mcp_servers.agentguard.tool_timeout_sec=600' \\
    "Investigate Alice's failed logins and summarize."

  default_tools_approval_mode="approve" hands approval to AgentGuard (codex exec would
  otherwise reject every MCP call); AgentGuard still holds what its policy says to hold.

  Limit: Codex routes MCP calls through its own code-execution mode, which can't be turned
  off, and its read-only sandbox can still read files. Run Codex on a machine or account that
  can't read AgentGuard's .env or data directory."""


def api(url: str, token: str) -> str:
    return f"""Your own agent on the Claude API or the OpenAI API (see examples/):
  export AGENTGUARD_MCP_URL={url}
  export AGENTGUARD_RUN_TOKEN={token}
  uv sync --extra examples
  uv run python examples/claude_api_agent.py "Investigate Alice's failed logins and summarize."
  uv run python examples/openai_api_agent.py "Investigate Alice's failed logins and summarize."

  Both connect to AgentGuard as MCP clients from your machine and give the model only
  AgentGuard's tools. Each also shows the hosted alternative (Anthropic's MCP connector,
  OpenAI's remote MCP tool), which needs AgentGuard on a public HTTPS URL."""


def instructions(client: str, url: str, token: str) -> str:
    return {"claude": claude_code, "codex": codex, "api": api}[client](url, token)
