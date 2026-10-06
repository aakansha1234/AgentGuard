# Connecting agents to AgentGuard

AgentGuard is an MCP server. Any agent that speaks MCP over streamable HTTP can use
it: it gets a run's tools, and every call it makes is checked against the policy
before anything runs. One rule applies to every agent below:

> **AgentGuard only checks calls to its own tools.** An agent's built-in tools
> (shell, file edits, web, code execution) act around it. Turn them off, or run the
> agent somewhere they can't reach anything that matters.

## 1. Create a run

Each agent session needs a run. A run fixes the task, the tools the agent may use,
and holds a one-time bearer token:

```bash
uv run agentguard connect --task "Investigate Alice's failed logins" --client claude
uv run agentguard connect --task "..." --client codex --tools get_user_logins,cloudflare__block_ip
uv run agentguard connect --task "..." --client api
```

It prints the MCP URL, the token (shown once), ready-to-run commands for that kind
of agent, and a dashboard link where you watch the run and approve held actions.
`--tools` limits what the agent sees; `--shadow` records what would be blocked
without blocking it.

## 2. Claude Code

Status: **verified live** (the dashboard's Live mode runs exactly this).

Interactive: `claude mcp add --transport http agentguard <url> --header "Authorization: Bearer <token>"`.

Headless and locked down, as `connect --client claude` prints:

```bash
CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT=600000 claude -p \
  --mcp-config agentguard-mcp.json --strict-mcp-config \
  --tools "" --allowedTools "mcp__agentguard__*" \
  --permission-mode dontAsk --setting-sources "" "<task>"
```

- `--tools ""` removes Claude Code's own tools, so AgentGuard's are the only way to act.
- `--strict-mcp-config` and `--setting-sources ""` stop other MCP servers and settings loading.
- The idle timeout must exceed the approval time limit, or Claude Code gives up on a held call.
- With an API key instead of a claude.ai login, set `ANTHROPIC_API_KEY`; nothing else changes.

## 3. Codex

Status: **verified live** with Codex CLI 0.159: a read was allowed, a firewall block
was held for a human, and Codex accepted the human's denial without retrying.

`connect --client codex` prints a `codex exec` command that:

- disables Codex's shell, patching, browser, computer-use, plugin, sub-agent and image tools,
- turns off web search and runs the sandbox read-only,
- points `mcp_servers.agentguard` at the run with `bearer_token_env_var`,
- sets `default_tools_approval_mode="approve"`: `codex exec` otherwise rejects every MCP
  call. Approval belongs to AgentGuard, which still holds what its policy says to hold,
- sets `tool_timeout_sec=600` so a held call can wait for a human.

**Limit:** current Codex versions route MCP calls through Codex's own code-execution
mode, which can't be turned off, and the read-only sandbox can still read files.
So Codex can't be locked down to AgentGuard's tools alone the way Claude Code can.
Run it on a machine or account that can't read AgentGuard's `.env` or data
directory. For the same reason the dashboard doesn't offer a "Live: Codex" mode.

## 4. Your own agent on the Claude API

Status: **tested against a scripted model API** (no API key on the build machine).
The SDK, MCP client and AgentGuard are real; only the model's replies are scripted.

[`examples/claude_api_agent.py`](../examples/claude_api_agent.py): the script is the
MCP client. It lists the run's tools, converts them with the SDK's `async_mcp_tool`,
and lets the tool runner call them, so AgentGuard can stay on a private network.

```bash
export AGENTGUARD_MCP_URL=... AGENTGUARD_RUN_TOKEN=... ANTHROPIC_API_KEY=...
uv run python examples/claude_api_agent.py "Investigate Alice's failed logins and summarize."
```

It uses `claude-opus-5-5` with server-side refusal fallbacks on (`fallbacks: "default"`).
`--connector` uses Anthropic's MCP connector instead (`mcp_servers` + an `mcp_toolset`,
beta `mcp-client-2025-11-20`): Anthropic calls AgentGuard directly, so AgentGuard must
be on a public HTTPS URL, and a call held for a human can outlast the request.

## 5. Your own agent on the OpenAI API

Status: **tested against a scripted model API**, as above.

[`examples/openai_api_agent.py`](../examples/openai_api_agent.py) offers the run's tools
to the Responses API as functions and forwards each call to AgentGuard.
`--remote-mcp` uses OpenAI's hosted MCP tool (`type: "mcp"`, `authorization` = run
token, `require_approval: "never"` because AgentGuard does the approving); like the
connector it needs a public URL.

## 6. Anything else

Any MCP client works: point it at the run's URL with `Authorization: Bearer <token>`.
The token works only on the MCP endpoint, so an agent holding it can't approve its
own requests or read the dashboard API.
