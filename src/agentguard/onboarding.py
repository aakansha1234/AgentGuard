"""`agentguard init`: write a cautious starting policy for your MCP servers.

It connects to every server in the upstreams file, lists their tools, and writes
one rule per server and kind of tool:

- read-only tools: allowed
- tools that change something: need a human's approval
- tools that can send data out: need a human's approval (and the model reviewer, if on)

Anything else is denied by default. The result is a starting point: tighten the
rules with `when` conditions (which arguments, which targets) before relying on it.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import yaml

from agentguard.policy import Policy
from agentguard.tools import ToolRegistry
from agentguard.tools.base import ToolSpec
from agentguard.tools.upstream import UpstreamPool, build_specs, discover, load_upstreams

HEADER = """\
# Starting policy written by `agentguard init` for: {servers}.
#
# Read-only tools are allowed; tools that change something or can send data out
# need a human's approval; anything else is denied. Tighten these rules with
# `when` conditions before relying on them, e.g. only allow writes to one project:
#
#   when:
#     - {{ path: args.repo, op: in, list: our_repos }}
#
# Check it with `agentguard check-policy`, then try it in monitor-only mode
# (enforcement: shadow) and compare with `agentguard policy-diff`.

"""


def _kind(spec: ToolSpec) -> str:
    if "egress" in spec.labels:
        return "outbound"
    if "side_effect" in spec.labels:
        return "changes"
    if "read_only" in spec.labels:
        return "reads"
    return "unknown"


RULES = {
    "reads": ("allow", "Read-only tools on {server} are allowed."),
    "changes": ("require_approval", "Tools on {server} that change something need a human's approval."),
    "outbound": ("require_approval", "Tools on {server} that can send data out need a human's approval."),
}


def policy_for(specs: list[ToolSpec], name: str = "my-agents") -> str:
    by_server: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for spec in specs:
        by_server[spec.source][_kind(spec)].append(spec.name)
    rules = []
    for server in sorted(by_server):
        for kind in ("reads", "changes", "outbound"):
            tools = sorted(by_server[server].get(kind, []))
            if tools:
                effect, text = RULES[kind]
                rules.append(
                    {
                        "id": f"{server}-{kind}",
                        "description": text.format(server=server),
                        "effect": effect,
                        "match": {"tools": tools},
                    }
                )
    doc = {
        "schema_version": 1,
        "name": name,
        "description": "From agentguard init: reads allowed, changes and outbound need approval.",
        "default_effect": "deny",
        "approval_ttl_seconds": 300,
        "on_human_deny": "continue",
        "limits": {"max_tool_calls": 50, "max_run_seconds": 1800, "max_policy_denials": 3},
        "lists": {},
        "reviewer": {
            "enabled": True,
            "review_labels": ["egress"],
            "fail_closed_labels": ["egress", "side_effect"],
            "escalate_threshold": 0.7,
            "timeout_seconds": 3,
        },
        "rules": rules,
    }
    body = yaml.safe_dump(doc, sort_keys=False, width=100)
    return HEADER.format(servers=", ".join(sorted(by_server)) or "no servers") + body


def init_policy(upstreams_path: Path, output: Path, *, force: bool = False) -> tuple[Path, list[ToolSpec]]:
    if output.exists() and not force:
        raise FileExistsError(f"{output} exists; pass --force to overwrite it")
    upstreams = load_upstreams(upstreams_path)
    if not upstreams:
        raise ValueError(f"{upstreams_path} lists no servers")
    discovered = discover(upstreams)
    specs = build_specs(upstreams, discovered, UpstreamPool(upstreams, discovered))
    text = policy_for(specs)
    Policy.parse(text, ToolRegistry(specs))  # the generated policy must load
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text)
    return output, specs
