"""Post-processing of tool results before they reach the model or the audit log.

- Redacts secret-looking strings.
- Collects facts later policy decisions can depend on (IPs and event IDs the
  agent has seen).
- Flags text that looks like instructions aimed at the agent. This is a
  heuristic for visibility; enforcement never relies on it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

REDACTED = "[REDACTED]"

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("password", re.compile(r"(?i)\b(pass(?:word|wd)?|pwd)\s*[=:]\s*['\"]?[^\s'\",;]+")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("api_key", re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b")),
]

_INSTRUCTION_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(?:all\s+|any\s+)?(?:your|previous|prior|the\s+above)\s+instructions\b"),
    re.compile(
        r"(?i)\b(?:system|developer)\s+(?:note|prompt|message)\s+to\s+(?:the\s+)?(?:ai|agent|assistant)\b"
    ),
    re.compile(r"(?i)\b(?:upload|send|post|exfiltrate|forward)\s+(?:all\s+)?(?:the\s+)?logs?\s+to\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:a|an|in)\b"),
]

_EVENT_ID = re.compile(r"\bEVT-\d{4,}\b")


def _redact_text(text: str, counter: dict[str, int]) -> str:
    for kind, pattern in _SECRET_PATTERNS:

        def _sub(m: re.Match[str], kind: str = kind) -> str:
            counter[kind] = counter.get(kind, 0) + 1
            if kind == "password":
                return m.group(1) + "=" + REDACTED
            return REDACTED

        text = pattern.sub(_sub, text)
    return text


def redact(value: Any) -> tuple[Any, dict[str, int]]:
    counter: dict[str, int] = {}

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            return _redact_text(v, counter)
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    return walk(value), counter


def _strings(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(_strings(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(_strings(v))
    return out


def _collect_keys(value: Any, keys: frozenset[str]) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for k, v in value.items():
            if k in keys and isinstance(v, str):
                found.add(v)
            else:
                found |= _collect_keys(v, keys)
    elif isinstance(value, list):
        for v in value:
            found |= _collect_keys(v, keys)
    return found


@dataclass
class ResultFacts:
    redactions: dict[str, int] = field(default_factory=dict)
    ips: set[str] = field(default_factory=set)
    event_ids: set[str] = field(default_factory=set)
    instruction_like: list[str] = field(default_factory=list)


def analyze_result(result: dict[str, Any]) -> tuple[dict[str, Any], ResultFacts]:
    """Return the redacted result and the facts extracted from it."""
    redacted, counts = redact(result)
    facts = ResultFacts(redactions=counts)
    facts.ips = {ip for v in _collect_keys(redacted, frozenset({"ip", "src_ip"})) if (ip := _canonical_ip(v))}
    facts.event_ids = {m for s in _strings(redacted) for m in _EVENT_ID.findall(s)} & _collect_keys(
        redacted, frozenset({"id"})
    )
    for s in _strings(redacted):
        if any(p.search(s) for p in _INSTRUCTION_PATTERNS):
            facts.instruction_like.append(s[:300])
    return redacted, facts


def _canonical_ip(value: str) -> str | None:
    """Log fields are untrusted: only values that parse as an IP address count."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def cited_event_ids(text: str) -> list[str]:
    return sorted(set(_EVENT_ID.findall(text)))
