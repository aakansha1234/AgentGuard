"""Scripted stand-ins for the Claude Messages API and the OpenAI Responses API.

Turn 1 asks for two tool calls (one the policy allows, one it denies); turn 2
answers with text that quotes what the tools returned. Requests are recorded so
tests can check what the SDKs sent.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from tests.liveserver import free_port

CALLS = [("get_user_logins", {"user": "alice"}), ("get_user_logins", {"user": "bob"})]


class FakeModelApis:
    def __init__(self) -> None:
        self.anthropic_requests: list[dict[str, Any]] = []
        self.anthropic_headers: list[dict[str, str]] = []
        self.openai_requests: list[dict[str, Any]] = []
        app = Starlette(
            routes=[
                Route("/v1/messages", self._messages, methods=["POST"]),
                Route("/v1/responses", self._responses, methods=["POST"]),
            ]
        )
        self.port = free_port()
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> FakeModelApis:
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline:
                raise RuntimeError("fake model APIs did not start")
            time.sleep(0.02)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(10)

    # --- Claude Messages API ----------------------------------------------------------------

    async def _messages(self, request: Request) -> JSONResponse:
        body = await request.json()
        self.anthropic_requests.append(body)
        self.anthropic_headers.append(dict(request.headers))
        last = body["messages"][-1]
        results = [
            block
            for block in (last["content"] if isinstance(last["content"], list) else [])
            if isinstance(block, dict) and block.get("type") == "tool_result"
        ]
        base = {"id": f"msg_{len(self.anthropic_requests)}", "type": "message", "role": "assistant"}
        base |= {
            "model": body["model"],
            "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        if body.get("mcp_servers") or results:
            text = "Summary. " + " | ".join(json.dumps(r.get("content"))[:4000] for r in results)
            return JSONResponse(
                {**base, "content": [{"type": "text", "text": text}], "stop_reason": "end_turn"}
            )
        content = [
            {"type": "tool_use", "id": f"toolu_{i}", "name": name, "input": args}
            for i, (name, args) in enumerate(CALLS)
        ]
        return JSONResponse({**base, "content": content, "stop_reason": "tool_use"})

    # --- OpenAI Responses API ---------------------------------------------------------------

    async def _responses(self, request: Request) -> JSONResponse:
        body = await request.json()
        self.openai_requests.append(body)
        n = len(self.openai_requests)
        base = {
            "id": f"resp_{n}",
            "object": "response",
            "created_at": 0,
            "model": body["model"],
            "status": "completed",
            "parallel_tool_calls": True,
            "tool_choice": "auto",
            "tools": [],
        }
        outputs = [i for i in body["input"] if isinstance(i, dict)] if isinstance(body["input"], list) else []
        if any(t.get("type") == "mcp" for t in body.get("tools", [])) or outputs:
            text = "Summary. " + " | ".join(o.get("output", "")[:4000] for o in outputs)
            message = {
                "type": "message",
                "id": f"msg_{n}",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}],
            }
            return JSONResponse({**base, "output": [message]})
        calls = [
            {
                "type": "function_call",
                "id": f"fc_{i}",
                "call_id": f"call_{i}",
                "name": name,
                "arguments": json.dumps(args),
                "status": "completed",
            }
            for i, (name, args) in enumerate(CALLS)
        ]
        return JSONResponse({**base, "output": calls})
