"""Cloudflare Clef (Workers AI) as an escalate-only reviewer.

Clef answers typed questions with probabilities, like Jev. It gets the same
trusted-only state and the same yes/no ("noul") questions, so the two can be
compared with `agentguard eval-reviewer --reviewer clef`.

Needs CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN (a token with Workers AI
read access).
"""

from __future__ import annotations

import os
from typing import Any

import httpx2

from agentguard.reviewers.base import ReviewInput, ReviewResult
from agentguard.reviewers.jev import QUESTIONS, review_state, verdict

# The full Clef model. Clef-flash missed most cases in `agentguard eval-reviewer`, so it isn't offered.
MODEL = "clef"
API = f"https://api.cloudflare.com/client/v4/accounts/{{account}}/ai/run/@cf/cloudflare/{MODEL}"


class ClefError(RuntimeError):
    pass


class ClefReviewer:
    name = "clef"

    def __init__(
        self,
        *,
        account_id: str | None = None,
        api_token: str | None = None,
        client: httpx2.AsyncClient | None = None,
        timeout: float = 10.0,
    ) -> None:
        account_id = account_id or os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        api_token = api_token or os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
        if not account_id or not api_token:
            raise ClefError("Clef needs CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN")
        self._url = API.format(account=account_id)
        self._client = client or httpx2.AsyncClient(timeout=timeout)
        self._headers = {"Authorization": f"Bearer {api_token}"}

    async def review(self, inp: ReviewInput, threshold: float) -> ReviewResult:
        body = {
            "model": MODEL,
            "state": review_state(inp),
            "questions": {name: {"type": "noul", "instructions": text} for name, text in QUESTIONS.items()},
        }
        response = await self._client.post(self._url, json=body, headers=self._headers)
        if response.status_code != 200:
            raise ClefError(f"Clef returned HTTP {response.status_code}: {response.text[:300]}")
        data: Any = response.json()
        # The REST API wraps model output in Cloudflare's {"success", "result"} envelope.
        if isinstance(data, dict) and "result" in data:
            if data.get("success") is False:
                raise ClefError(f"Clef error: {data.get('errors')}")
            data = data["result"]
        try:
            scores = {name: float(data["answers"][name]["noul"]) for name in QUESTIONS}
        except (KeyError, TypeError, ValueError) as exc:
            raise ClefError(f"unexpected Clef response: {exc!r}") from exc
        return verdict(scores, threshold, self.name)

    async def aclose(self) -> None:
        await self._client.aclose()
