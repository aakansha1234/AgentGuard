"""The environment a launched agent process gets.

Only what the agent CLI needs to start and authenticate is passed through.
AgentGuard's own secrets (upstream credentials, reviewer keys, the operator
token) stay out, so the agent can't use them even if it found a way to read its
environment.
"""

from __future__ import annotations

import os

# Exact names passed through when set.
PASSTHROUGH = (
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "TERM",
    "TMPDIR",
    "TZ",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
)
# Prefixes passed through: locale and XDG directories (where agent CLIs keep their login).
PASSTHROUGH_PREFIXES = ("LC_", "XDG_")


def agent_env(*, allow_prefixes: tuple[str, ...] = (), extra: dict[str, str] | None = None) -> dict[str, str]:
    """`allow_prefixes` admits the agent's own settings, e.g. ("CLAUDE_", "ANTHROPIC_")."""
    prefixes = PASSTHROUGH_PREFIXES + allow_prefixes
    env = {k: v for k, v in os.environ.items() if k in PASSTHROUGH or k.startswith(prefixes)}
    env.update(extra or {})
    return env
