"""Cloudflare firewall as an MCP server: block an IP for a limited time.

Run it behind AgentGuard (see upstreams.example.yaml), never directly by an
agent: AgentGuard holds the token and checks every call against the policy
(protected networks, evidence, duration, human approval) before it gets here.

Blocks are account-level IP Access Rules
(https://developers.cloudflare.com/waf/tools/ip-access-rules/). Cloudflare rules
don't expire on their own, so each rule's note records its expiry and a sweeper
deletes expired rules every minute. The server only touches rules whose note
starts with "agentguard", never rules people created.

Environment:
    CLOUDFLARE_ACCOUNT_ID   the account the rules belong to
    CLOUDFLARE_API_TOKEN    a token with Account Firewall Access Rules Read + Write
    CLOUDFLARE_API_BASE     optional, for tests (default: https://api.cloudflare.com/client/v4)

    python -m agentguard.integrations.cloudflare_firewall
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import httpx2
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

API_BASE = "https://api.cloudflare.com/client/v4"
NOTE_PREFIX = "agentguard"
NOTE = re.compile(r"^agentguard \| expires (?P<expires>\S+) \| (?P<reason>.*)$", re.S)
MAX_MINUTES = 24 * 60
SWEEP_SECONDS = 60.0


class FirewallError(RuntimeError):
    pass


def canonical_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(value.strip())
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        raise FirewallError(f"refusing to block {ip}")
    return ip


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_note(note: str | None) -> tuple[datetime, str] | None:
    m = NOTE.match(note or "")
    if not m:
        return None
    try:
        expires = datetime.fromisoformat(m.group("expires").replace("Z", "+00:00"))
    except ValueError:
        return None
    return expires, m.group("reason")


class Firewall:
    """Cloudflare IP Access Rules created and owned by AgentGuard."""

    def __init__(self, account_id: str, token: str, *, http: httpx2.AsyncClient | None = None) -> None:
        base = os.environ.get("CLOUDFLARE_API_BASE", API_BASE).rstrip("/")
        self._url = f"{base}/accounts/{account_id}/firewall/access_rules/rules"
        self._http = http or httpx2.AsyncClient(timeout=20)
        self._headers = {"Authorization": f"Bearer {token}"}

    async def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        r = await self._http.request(method, url, headers=self._headers, **kwargs)
        try:
            body = r.json()
        except ValueError:
            body = {}
        if r.status_code != 200 or not body.get("success", False):
            errors = "; ".join(e.get("message", "") for e in body.get("errors", [])) or r.text[:200]
            raise FirewallError(f"Cloudflare API {r.status_code}: {errors}")
        return body["result"]

    async def _ours(self) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        page = 1
        while True:
            result = await self._request(
                "GET",
                self._url,
                params={"notes": NOTE_PREFIX, "mode": "block", "per_page": 100, "page": page},
            )
            rules.extend(r for r in result if parse_note(r.get("notes")) is not None)
            if len(result) < 100:
                return rules
            page += 1

    @staticmethod
    def _view(rule: dict[str, Any]) -> dict[str, Any]:
        parsed = parse_note(rule.get("notes"))
        assert parsed is not None
        return {
            "rule_id": rule["id"],
            "ip": rule["configuration"]["value"],
            "mode": rule["mode"],
            "expires_at": _iso(parsed[0]),
            "reason": parsed[1],
        }

    async def block(
        self, ip: str, minutes: int, reason: str, *, now: datetime | None = None
    ) -> dict[str, Any]:
        addr = canonical_ip(ip)
        if not 1 <= minutes <= MAX_MINUTES:
            raise FirewallError(f"duration must be 1-{MAX_MINUTES} minutes")
        expires = (now or datetime.now(UTC)) + timedelta(minutes=minutes)
        note = f"{NOTE_PREFIX} | expires {_iso(expires)} | {reason.strip()[:200]}"
        existing = [r for r in await self._ours() if r["configuration"]["value"] == str(addr)]
        if existing:  # extend instead of creating a duplicate
            rule = await self._request("PATCH", f"{self._url}/{existing[0]['id']}", json={"notes": note})
            return {**self._view(rule), "status": "extended"}
        rule = await self._request(
            "POST",
            self._url,
            json={
                "mode": "block",
                "configuration": {"target": "ip" if addr.version == 4 else "ip6", "value": str(addr)},
                "notes": note,
            },
        )
        return {**self._view(rule), "status": "blocked"}

    async def unblock(self, ip: str) -> dict[str, Any]:
        addr = str(canonical_ip(ip))
        removed = [r["id"] for r in await self._ours() if r["configuration"]["value"] == addr]
        for rule_id in removed:
            await self._request("DELETE", f"{self._url}/{rule_id}")
        return {"ip": addr, "removed_rules": removed, "status": "unblocked" if removed else "not blocked"}

    async def list(self) -> list[dict[str, Any]]:
        return [self._view(r) for r in await self._ours()]

    async def sweep(self, *, now: datetime | None = None) -> list[str]:
        """Delete AgentGuard's rules whose expiry has passed. Returns the unblocked IPs."""
        now = now or datetime.now(UTC)
        expired = []
        for rule in await self._ours():
            parsed = parse_note(rule.get("notes"))
            if parsed is not None and parsed[0] <= now:
                await self._request("DELETE", f"{self._url}/{rule['id']}")
                expired.append(rule["configuration"]["value"])
        return expired

    async def aclose(self) -> None:
        await self._http.aclose()


def _from_env() -> Firewall:
    account = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not account or not token:
        raise SystemExit("cloudflare_firewall needs CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN")
    return Firewall(account, token)


_firewall: Firewall | None = None


def firewall() -> Firewall:
    if _firewall is None:
        raise FirewallError("firewall not initialised")
    return _firewall


@contextlib.asynccontextmanager
async def lifespan(_server: MCPServer[Any]) -> AsyncIterator[None]:
    global _firewall
    _firewall = _from_env()

    async def sweeper() -> None:
        while True:
            with contextlib.suppress(Exception):  # retried next minute; the server stays up
                await firewall().sweep()
            await asyncio.sleep(SWEEP_SECONDS)

    task = asyncio.create_task(sweeper())
    try:
        yield
    finally:
        task.cancel()
        await _firewall.aclose()
        _firewall = None


server: MCPServer[Any] = MCPServer(
    "cloudflare-firewall",
    instructions="Blocks IP addresses at the Cloudflare edge for a limited time.",
    lifespan=lifespan,
)


@server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
async def block_ip(
    ip: Annotated[str, Field(description="IPv4 or IPv6 address to block", max_length=64)],
    duration_minutes: Annotated[int, Field(ge=1, le=MAX_MINUTES, description="How long the block lasts")],
    reason: Annotated[str, Field(min_length=3, max_length=200, description="Why, citing evidence")],
) -> dict[str, Any]:
    """Block an IP address at the Cloudflare edge for a limited time (account-wide IP Access Rule)."""
    return await firewall().block(ip, duration_minutes, reason)


@server.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False))
async def unblock_ip(ip: Annotated[str, Field(max_length=64)]) -> dict[str, Any]:
    """Remove AgentGuard's block on an IP address. Rules created by people are never touched."""
    return await firewall().unblock(ip)


@server.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def list_blocks() -> list[dict[str, Any]]:
    """List the IP blocks AgentGuard created and when each expires."""
    return await firewall().list()


if __name__ == "__main__":
    server.run("stdio")
