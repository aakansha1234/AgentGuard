"""Proxy tools from upstream MCP servers through the gate.

AgentGuard connects to the MCP servers listed in the upstreams file, offers their
tools to the agent as `<server>__<tool>`, and forwards a call only after the gate
allowed (or a human approved) it. Credentials for those servers live in
AgentGuard's environment and are referenced as ${VAR} in the file: the agent
never holds them, so it cannot reach the server any other way.

    servers:
      cloudflare:
        command: uv
        args: [run, python, -m, agentguard_integrations.cloudflare_firewall]
        env:
          CLOUDFLARE_API_TOKEN: ${CLOUDFLARE_FIREWALL_TOKEN}
        tools:                       # optional allowlist; omit to expose every tool
          block_ip: {labels: [side_effect]}
      github:
        url: https://example.com/mcp
        headers: {Authorization: "Bearer ${GITHUB_TOKEN}"}

Labels not set here are derived from the tool's MCP annotations, defaulting to
the most cautious reading (the MCP defaults: may change things, may reach the
outside world). The policy denies any tool no rule allows.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import threading
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
import yaml
from mcp import Client, StdioServerParameters
from mcp import types as mcp_types
from mcp.client.streamable_http import streamable_http_client
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agentguard.tools.base import ToolContext, ToolSpec

SEPARATOR = "__"
SERVER_NAME = re.compile(r"^[a-z][a-z0-9_]{0,23}$")
TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
# Variables an stdio server inherits from AgentGuard. Everything else must be listed under `env`.
BASE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")
MAX_RESULT_CHARS = 20_000


class UpstreamError(RuntimeError):
    """Configuration or connection problem with an upstream MCP server."""


class UpstreamToolError(RuntimeError):
    """The upstream server reported that the tool call failed."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolConfig(_Strict):
    labels: list[str] | None = None


class ServerConfig(_Strict):
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    tools: dict[str, ToolConfig] | None = None
    timeout_seconds: float = Field(default=30.0, gt=0, le=600)

    @model_validator(mode="after")
    def _one_transport(self) -> ServerConfig:
        if (self.command is None) == (self.url is None):
            raise ValueError("give exactly one of `command` (stdio) or `url` (streamable HTTP)")
        if self.url is None and self.headers:
            raise ValueError("`headers` only apply to `url` servers")
        if self.command is None and (self.args or self.env or self.cwd):
            raise ValueError("`args`, `env` and `cwd` only apply to `command` servers")
        return self


class UpstreamsFile(_Strict):
    servers: dict[str, ServerConfig] = Field(default_factory=dict)


def expand(value: str, environ: dict[str, str], where: str) -> str:
    def one(m: re.Match[str]) -> str:
        name = m.group(1)
        found = environ.get(name, "")
        if not found:
            raise UpstreamError(f"{where} needs {name}, which is not set (set it in the environment or .env)")
        return found

    return _VAR.sub(one, value)


@dataclass(frozen=True)
class Upstream:
    """A server from the upstreams file with its ${VAR}s resolved."""

    name: str
    config: ServerConfig
    env: dict[str, str]
    headers: dict[str, str]
    url: str | None
    args: list[str]

    def connect(self) -> Client:
        if self.url is not None:
            http = httpx2.AsyncClient(headers=self.headers, timeout=httpx2.Timeout(30.0, read=None))
            return Client(streamable_http_client(self.url, http_client=http))
        assert self.config.command is not None
        return Client(
            StdioServerParameters(
                command=self.config.command, args=self.args, env=self.env, cwd=self.config.cwd
            )
        )


def load_upstreams(path: Path, environ: dict[str, str] | None = None) -> list[Upstream]:
    environ = dict(os.environ) if environ is None else environ
    try:
        doc = UpstreamsFile.model_validate(yaml.safe_load(path.read_text()) or {})
    except (yaml.YAMLError, ValidationError) as exc:
        raise UpstreamError(f"{path}: {exc}") from exc
    upstreams = []
    for name, cfg in doc.servers.items():
        if not SERVER_NAME.match(name):
            raise UpstreamError(f"{path}: server name {name!r} must match {SERVER_NAME.pattern}")
        where = f"upstream {name!r}"
        env = {k: environ[k] for k in BASE_ENV if environ.get(k)}
        env.update({k: expand(v, environ, where) for k, v in cfg.env.items()})
        upstreams.append(
            Upstream(
                name=name,
                config=cfg,
                env=env,
                headers={k: expand(v, environ, where) for k, v in cfg.headers.items()},
                url=expand(cfg.url, environ, where) if cfg.url else None,
                args=[expand(a, environ, where) for a in cfg.args],
            )
        )
    return upstreams


def labels_from_annotations(annotations: mcp_types.ToolAnnotations | None) -> frozenset[str]:
    """Cautious labels from MCP tool hints. Missing hints take the MCP defaults
    (not read-only, may be destructive, open world)."""
    a = annotations or mcp_types.ToolAnnotations()
    read_only = a.read_only_hint is True
    open_world = a.open_world_hint is not False
    labels = {"read_only"} if read_only else {"side_effect"}
    if open_world:
        labels.add("ingests_untrusted" if read_only else "egress")
    return frozenset(labels)


def schema_fingerprint(tool: mcp_types.Tool) -> str:
    return hashlib.sha256(json.dumps(tool.input_schema, sort_keys=True).encode()).hexdigest()[:16]


def result_to_dict(result: mcp_types.CallToolResult) -> dict[str, Any]:
    """Flatten an MCP tool result into JSON for the gate (redaction, flagging, audit)."""
    texts: list[str] = []
    other: list[dict[str, Any]] = []
    for item in result.content:
        if isinstance(item, mcp_types.TextContent):
            texts.append(item.text)
        else:
            other.append({"type": item.type})
    out: dict[str, Any] = {}
    if result.structured_content is not None:
        out["structured"] = result.structured_content
    if texts:
        text = "\n".join(texts)
        if len(text) > MAX_RESULT_CHARS:
            text = text[:MAX_RESULT_CHARS] + f"\n[truncated: {len(text)} characters]"
        out["text"] = text
    if other:
        out["other_content"] = other
    return out


class UpstreamPool:
    """Long-lived sessions to every upstream server, opened in the app's event loop."""

    def __init__(self, upstreams: list[Upstream], discovered: dict[str, list[mcp_types.Tool]]) -> None:
        self.upstreams = {u.name: u for u in upstreams}
        self._expected = {
            name: {t.name: schema_fingerprint(t) for t in tools} for name, tools in discovered.items()
        }
        self._clients: dict[str, Client] = {}
        self._stack: contextlib.AsyncExitStack | None = None

    async def open(self) -> None:
        self._stack = contextlib.AsyncExitStack()
        for name, upstream in self.upstreams.items():
            try:
                client = await self._stack.enter_async_context(upstream.connect())
                tools = await _list_all(client)
            except Exception as exc:
                await self.close()
                raise UpstreamError(f"upstream {name!r}: could not connect: {exc}") from exc
            now = {t.name: schema_fingerprint(t) for t in tools}
            changed = sorted(t for t, fp in self._expected[name].items() if now.get(t) != fp)
            if changed:
                await self.close()
                raise UpstreamError(f"upstream {name!r} changed tools since discovery: {changed}; restart")
            self._clients[name] = client

    async def close(self) -> None:
        stack, self._stack = self._stack, None
        self._clients.clear()
        if stack is not None:
            await stack.aclose()

    async def call(self, server: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        client = self._clients.get(server)
        if client is None:
            raise UpstreamError(f"upstream {server!r} is not connected")
        timeout = self.upstreams[server].config.timeout_seconds
        result = await asyncio.wait_for(client.call_tool(tool, args), timeout)
        out = result_to_dict(result)
        if result.is_error:
            raise UpstreamToolError(out.get("text") or "the upstream tool reported an error")
        return out


async def _list_all(client: Client) -> list[mcp_types.Tool]:
    tools: list[mcp_types.Tool] = []
    cursor: str | None = None
    while True:
        page = await client.list_tools(cursor=cursor)
        tools.extend(page.tools)
        cursor = page.next_cursor
        if not cursor:
            return tools


async def _discover_async(upstreams: list[Upstream]) -> dict[str, list[mcp_types.Tool]]:
    found: dict[str, list[mcp_types.Tool]] = {}
    for upstream in upstreams:
        try:
            async with upstream.connect() as client:
                found[upstream.name] = await asyncio.wait_for(
                    _list_all(client), upstream.config.timeout_seconds
                )
        except Exception as exc:
            raise UpstreamError(f"upstream {upstream.name!r}: could not list tools: {exc}") from exc
    return found


def run_sync[T](make: Callable[[], Coroutine[Any, Any, T]]) -> T:
    """Run a coroutine to completion from sync code, even if an event loop is running here."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = asyncio.run(make())
        except BaseException as exc:
            box["error"] = exc

    thread = threading.Thread(target=target, name="agentguard-upstream-discovery")
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


def discover(upstreams: list[Upstream]) -> dict[str, list[mcp_types.Tool]]:
    return run_sync(lambda: _discover_async(upstreams))


def build_specs(
    upstreams: list[Upstream], discovered: dict[str, list[mcp_types.Tool]], pool: UpstreamPool
) -> list[ToolSpec]:
    specs: list[ToolSpec] = []
    for upstream in upstreams:
        tools = {t.name: t for t in discovered[upstream.name]}
        wanted = upstream.config.tools
        if wanted is not None:
            missing = sorted(set(wanted) - set(tools))
            if missing:
                raise UpstreamError(f"upstream {upstream.name!r} has no tools named {missing}")
        for tool in tools.values():
            if wanted is not None and tool.name not in wanted:
                continue
            if not TOOL_NAME.match(tool.name):
                raise UpstreamError(f"upstream {upstream.name!r}: tool name {tool.name!r} is not supported")
            configured = wanted.get(tool.name) if wanted is not None else None
            labels = (
                frozenset(configured.labels)
                if configured is not None and configured.labels is not None
                else labels_from_annotations(tool.annotations)
            )
            schema = dict(tool.input_schema) or {"type": "object"}
            schema.pop("title", None)
            # Rules can only reason about declared arguments, so undeclared ones are refused
            # unless the server explicitly accepts extra properties.
            schema.setdefault("additionalProperties", False)
            specs.append(
                ToolSpec(
                    name=f"{upstream.name}{SEPARATOR}{tool.name}",
                    description=f"[{upstream.name}] {tool.description or tool.name}",
                    labels=labels,
                    handler=_forwarder(pool, upstream.name, tool.name),
                    schema=schema,
                    source=upstream.name,
                )
            )
    return specs


def _forwarder(pool: UpstreamPool, server: str, tool: str) -> Callable[[ToolContext, Any], Any]:
    async def forward(_ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
        return await pool.call(server, tool, args)

    return forward


def load_upstream_tools(path: Path | None) -> tuple[UpstreamPool | None, list[ToolSpec]]:
    """Read the upstreams file, list each server's tools, and return the pool and tool specs."""
    if path is None:
        return None, []
    if not path.exists():
        raise UpstreamError(f"upstreams file {path} does not exist")
    upstreams = load_upstreams(path)
    if not upstreams:
        return None, []
    discovered = discover(upstreams)
    pool = UpstreamPool(upstreams, discovered)
    return pool, build_specs(upstreams, discovered, pool)
