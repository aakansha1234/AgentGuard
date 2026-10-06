"""API used by the dashboard. Every route except /api/health needs a signed-in user with a role (auth.py)."""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from agentguard import __version__
from agentguard.auth import (
    USER_TOKEN_PREFIX,
    Principal,
    bearer,
    hash_user_token,
    is_operator,
    trusted_proxy,
)
from agentguard.gate import ResolveError
from agentguard.gateway import SERVER_NAME
from agentguard.launcher.claude_code import TOOL_PREFIX, mcp_config
from agentguard.models import Enforcement, RunMode
from agentguard.services import Services
from agentguard.store import EventRecord

SSE_KEEPALIVE_SECONDS = 15.0


class CreateRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task: str = Field(min_length=1, max_length=4000)
    mode: RunMode
    scenario: str | None = None
    dataset_id: str = "baseline"
    subject: str = Field(default="alice", pattern=r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
    enforcement: Enforcement = Enforcement.ENFORCE
    # The agent's tool allowlist. Omitted: the scenario's tools, or every tool.
    tools: list[str] | None = Field(default=None, max_length=200)


class ResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "deny"]
    args_hash: str = Field(min_length=10, max_length=100)
    note: str | None = Field(default=None, max_length=500)


def authenticate(request: Request, authorization: Annotated[str | None, Header()] = None) -> Principal:
    services: Services = request.app.state.services
    settings = services.settings
    token = bearer(authorization)
    if token is not None:
        if is_operator(token, settings.operator_token):
            return Principal(settings.operator_name, "admin", "operator-token")
        if token.startswith(USER_TOKEN_PREFIX):
            user = services.store.user_by_token_hash(hash_user_token(token))
            if user is not None:
                return Principal(user.name, user.role, "user-token")
        raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})
    if settings.auth_header:
        email = request.headers.get(settings.auth_header, "").strip()
        peer = request.client.host if request.client else None
        if email and trusted_proxy(peer, settings.trusted_proxies):
            user = services.store.user_by_email(email)
            if user is None:
                raise HTTPException(403, f"{email} is not an AgentGuard user; ask an admin to add you")
            return Principal(user.name, user.role, "sso")
    raise HTTPException(401, "sign in required", headers={"WWW-Authenticate": "Bearer"})


def role(required: str) -> Any:
    def check(who: Annotated[Principal, Depends(authenticate)]) -> Principal:
        if not who.can(required):
            raise HTTPException(403, f"needs the {required} role; you are {who.role}")
        return who

    return Depends(check)


Viewer = Annotated[Principal, role("viewer")]
Approver = Annotated[Principal, role("approver")]
Admin = Annotated[Principal, role("admin")]


def _sse(event: EventRecord) -> str:
    data = json.dumps(event.to_dict(), ensure_ascii=False)
    return f"id: {event.seq}\nevent: {event.type}\ndata: {data}\n\n"


def build_router(services: Services) -> APIRouter:
    router = APIRouter(prefix="/api")
    settings = services.settings

    def _run_or_404(run_id: str) -> Any:
        run = services.store.get_run(run_id)
        if run is None:
            raise HTTPException(404, "no such run")
        return run

    @router.get("/health")
    async def health() -> dict[str, Any]:
        return {"ok": True, "version": __version__}

    @router.get("/session")
    async def session(
        request: Request, authorization: Annotated[str | None, Header()] = None
    ) -> dict[str, Any]:
        """Who is signed in, without failing: lets the dashboard pick token sign-in or SSO."""
        try:
            who = authenticate(request, authorization)
        except HTTPException as exc:
            return {"user": None, "message": exc.detail if exc.status_code == 403 else ""}
        return {"user": {"name": who.name, "role": who.role, "via": who.via}, "message": ""}

    @router.get("/config")
    async def config(who: Viewer) -> dict[str, Any]:
        return {
            "version": __version__,
            "operator": who.name,
            "user": {"name": who.name, "role": who.role, "via": who.via},
            "tools_mode": settings.tools_mode,
            "upstreams": sorted(s for s in services.registry.sources() if s != "builtin"),
            "claude_available": settings.claude_available(),
            "claude_model": settings.claude_model,
            "reviewer": services.reviewer_name,
            "mcp_url": settings.public_mcp_url,
        }

    @router.get("/policies/current")
    async def current_policy(who: Viewer) -> dict[str, Any]:
        return services.policies.current().summary()

    @router.get("/scenarios")
    async def scenarios(who: Viewer) -> list[dict[str, Any]]:
        known = set(services.registry.names())
        out = []
        for s in services.scenarios.list():
            missing = sorted(set(s.tools or []) - known)
            out.append({**s.model_dump(), "available": not missing, "missing_tools": missing})
        return out

    @router.get("/datasets")
    async def datasets(who: Viewer) -> list[dict[str, Any]]:
        out = []
        for ds_id in services.datasets.ids():
            ds = services.datasets.get(ds_id)
            out.append(
                {"id": ds.id, "title": ds.title, "description": ds.description, "users": sorted(ds.users)}
            )
        return out

    @router.post("/runs", status_code=201)
    async def create_run(body: CreateRunRequest, who: Admin) -> dict[str, Any]:
        if body.dataset_id not in services.datasets.ids():
            raise HTTPException(400, "unknown dataset")
        if body.scenario is not None and body.scenario not in services.scenarios.scenarios:
            raise HTTPException(400, "unknown scenario")
        try:
            run, token = services.runs.create(
                owner=who.name,
                task=body.task,
                mode=body.mode,
                dataset_id=body.dataset_id,
                subject=body.subject,
                enforcement=body.enforcement,
                scenario=body.scenario,
                tools=body.tools,
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        response: dict[str, Any] = {"run": run.public()}
        if body.mode == RunMode.EXTERNAL:
            # Shown once. The operator hands it to the agent; AgentGuard keeps only a hash.
            response["token"] = token
            response["mcp_config"] = mcp_config(settings.public_mcp_url, token)
            response["claude_command"] = (
                f"claude mcp add --transport http {SERVER_NAME} {settings.public_mcp_url} "
                f'--header "Authorization: Bearer {token}"'
            )
            response["allowed_tools_pattern"] = f"{TOOL_PREFIX}*"
        return response

    @router.get("/runs")
    async def list_runs(who: Viewer, limit: int = 50) -> list[dict[str, Any]]:
        return [
            {**r.public(), "metrics": services.gate.metrics(r.id)}
            for r in services.store.list_runs(min(max(limit, 1), 200))
        ]

    @router.get("/runs/{run_id}")
    async def get_run(run_id: str, who: Viewer) -> dict[str, Any]:
        run = _run_or_404(run_id)
        return {
            "run": run.public(),
            "metrics": services.gate.metrics(run_id),
            "actions": [a.public() for a in services.store.list_actions(run_id)],
            "current_policy_version": services.policies.current().version,
        }

    @router.post("/runs/{run_id}/cancel")
    async def cancel_run(run_id: str, who: Admin) -> dict[str, Any]:
        _run_or_404(run_id)
        stopped = services.runs.cancel(run_id, who.name)
        run = _run_or_404(run_id)
        return {"stopped": stopped, "run": run.public()}

    @router.get("/runs/{run_id}/events")
    async def run_events(
        run_id: str,
        request: Request,
        who: Viewer,
        after: int = 0,
        last_event_id: Annotated[str | None, Header()] = None,
    ) -> StreamingResponse:
        _run_or_404(run_id)
        if last_event_id and last_event_id.isdigit():
            after = max(after, int(last_event_id))

        async def stream() -> AsyncIterator[str]:
            queue = services.bus.subscribe(run_id)
            last = after
            try:
                yield "retry: 2000\n\n"
                while True:
                    # The queue is only a wake-up signal; the database is the source of truth,
                    # so ordering holds and nothing is skipped after a reconnect.
                    for event in services.store.events_after(run_id, last):
                        yield _sse(event)
                        last = event.seq
                    if await request.is_disconnected():
                        return
                    try:
                        await asyncio.wait_for(queue.get(), SSE_KEEPALIVE_SECONDS)
                    except TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                services.bus.unsubscribe(queue, run_id)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    @router.post("/approvals/{action_id}/resolve")
    async def resolve(action_id: str, body: ResolveRequest, who: Approver) -> dict[str, Any]:
        try:
            action = services.gate.resolve_approval(
                action_id,
                approve=body.decision == "approve",
                approver=who.name,
                args_hash=body.args_hash,
                note=body.note,
            )
        except ResolveError as exc:
            raise HTTPException(exc.status, exc.message) from exc
        return {"action": action.public()}

    return router
