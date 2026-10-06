"""Canonical JSON and argument hashing.

The hash binds an approval to the exact arguments a human saw. Any change to
the tool name or any argument value produces a different hash.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def args_hash(tool: str, args: dict[str, Any]) -> str:
    return "sha256:" + sha256_hex(canonical_json({"tool": tool, "args": args}))
