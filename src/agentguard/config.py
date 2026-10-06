"""Runtime settings, read from environment variables."""

from __future__ import annotations

import ipaddress
import os
import re
import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class ConfigError(ValueError):
    """A setting is missing or invalid. The CLI reports it and exits with status 2."""


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip()


_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_dotenv(path: Path) -> list[str]:
    """Load KEY=VALUE lines from `path` into os.environ without overriding variables
    that are already set. Returns the names it set; never logs values."""
    if not path.is_file():
        return []
    loaded: list[str] = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, sep, value = line.partition("=")
        name = name.strip()
        if not sep or not _ENV_NAME.match(name):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if os.environ.get(name, "").strip():
            continue
        os.environ[name] = value
        loaded.append(name)
    return loaded


def load_project_dotenv() -> list[str]:
    """Load the project's .env (path overridable with AGENTGUARD_DOTENV; empty disables)."""
    target = os.environ.get("AGENTGUARD_DOTENV")
    if target is None:
        target = str(PROJECT_ROOT / ".env")
    return load_dotenv(Path(target)) if target else []


@dataclass
class Settings:
    root: Path = PROJECT_ROOT
    data_dir: Path = field(default_factory=lambda: PROJECT_ROOT / ".agentguard")
    policy_path: Path = field(default_factory=lambda: PROJECT_ROOT / "policies" / "default.yaml")
    host: str = "127.0.0.1"  # bind address
    port: int = 8787
    # Where people and external agents reach this server, e.g. https://vm.exe.xyz:8787.
    # Used in connect instructions and accepted as a Host by the MCP endpoint.
    public_url: str | None = None
    operator_token: str = ""
    operator_name: str = "operator"
    claude_bin: str = "claude"
    claude_model: str = "claude-opus-5-5"
    claude_max_turns: int = 24
    # Claude Code aborts an HTTP MCP call after this long without a response or
    # progress update. It must exceed the approval TTL.
    claude_mcp_idle_timeout_ms: int = 600_000
    tools_mode: str = "mock"
    # Who reviews actions in the policy's review_labels: "jev", "clef" or "human".
    # Required, no default. A model mode without its API key is a startup error, never a fallback.
    reviewer: str = ""
    # MCP servers whose tools AgentGuard proxies (tools/upstream.py). None: built-in tools only.
    upstreams_path: Path | None = None
    # The four mock SOC tools behind the demo scenarios. Turn off for real deployments.
    demo_tools: bool = True
    # Single sign-on through a trusted reverse proxy (auth.py), e.g. X-ExeDev-Email on exe.dev.
    auth_header: str | None = None
    trusted_proxies: list[str] = field(default_factory=list)
    # Alerts when a human is needed (notify.py). The URL is a secret.
    notify_webhook: str | None = None
    notify_format: str = "slack"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "agentguard.db"

    @property
    def fixtures_dir(self) -> Path:
        return self.root / "fixtures"

    @property
    def web_dir(self) -> Path:
        return self.root / "web"

    @property
    def worker_prompt_path(self) -> Path:
        return self.root / "prompts" / "worker.md"

    @property
    def internal_host(self) -> str:
        """Address local clients (launcher, replay, CLI) use to reach this server."""
        return "127.0.0.1" if self.host in ("0.0.0.0", "::", "") else self.host  # noqa: S104

    @property
    def base_url(self) -> str:
        return f"http://{self.internal_host}:{self.port}"

    @property
    def public_base_url(self) -> str:
        return (self.public_url or self.base_url).rstrip("/")

    @property
    def public_mcp_url(self) -> str:
        return f"{self.public_base_url}/mcp"

    @property
    def mcp_url(self) -> str:
        return f"{self.base_url}/mcp"

    def claude_available(self) -> bool:
        return shutil.which(self.claude_bin) is not None

    @classmethod
    def from_env(cls) -> Settings:
        s = cls()
        data_dir = _env("AGENTGUARD_DATA_DIR")
        if data_dir:
            s.data_dir = Path(data_dir)
        policy = _env("AGENTGUARD_POLICY")
        if policy:
            s.policy_path = Path(policy)
        s.host = _env("AGENTGUARD_HOST", s.host) or s.host
        s.public_url = _env("AGENTGUARD_PUBLIC_URL")
        s.port = int(_env("AGENTGUARD_PORT", str(s.port)) or s.port)
        s.operator_name = _env("AGENTGUARD_OPERATOR_NAME", s.operator_name) or s.operator_name
        s.operator_token = _env("AGENTGUARD_OPERATOR_TOKEN", "") or ""
        s.claude_bin = _env("AGENTGUARD_CLAUDE_BIN", s.claude_bin) or s.claude_bin
        s.claude_model = _env("AGENTGUARD_CLAUDE_MODEL", s.claude_model) or s.claude_model
        s.tools_mode = _env("TOOLS_MODE", s.tools_mode) or s.tools_mode
        s.reviewer = (_env("AGENTGUARD_REVIEWER") or "").strip().lower()
        demo = (_env("AGENTGUARD_DEMO_TOOLS") or "on").strip().lower()
        if demo not in ("on", "off"):
            raise ConfigError("AGENTGUARD_DEMO_TOOLS must be on or off")
        s.demo_tools = demo == "on"
        s.auth_header = _env("AGENTGUARD_AUTH_HEADER") or None
        proxies = _env("AGENTGUARD_TRUSTED_PROXIES") or ""
        s.trusted_proxies = [p.strip() for p in proxies.split(",") if p.strip()]
        for net in s.trusted_proxies:
            try:
                ipaddress.ip_network(net, strict=False)
            except ValueError as exc:
                raise ConfigError(f"AGENTGUARD_TRUSTED_PROXIES: {net!r} is not a network") from exc
        s.notify_webhook = _env("AGENTGUARD_NOTIFY_WEBHOOK") or None
        s.notify_format = (_env("AGENTGUARD_NOTIFY_FORMAT") or "slack").strip().lower()
        if s.notify_format not in ("slack", "json"):
            raise ConfigError("AGENTGUARD_NOTIFY_FORMAT must be slack or json")
        upstreams = _env("AGENTGUARD_UPSTREAMS")
        if upstreams:
            s.upstreams_path = Path(upstreams)
        if s.tools_mode != "mock":
            raise ConfigError("Only TOOLS_MODE=mock is supported in this version.")
        return s

    def ensure_operator_token(self) -> str:
        """Use the configured token, or create one and keep it in the data dir (mode 0600)."""
        if self.operator_token:
            return self.operator_token
        self.data_dir.mkdir(parents=True, exist_ok=True)
        token_file = self.data_dir / "operator_token"
        if token_file.exists():
            self.operator_token = token_file.read_text().strip()
        else:
            self.operator_token = secrets.token_urlsafe(32)
            token_file.write_text(self.operator_token + "\n")
            token_file.chmod(0o600)
        return self.operator_token
