"""Who is calling, and what they may do.

Credentials never overlap:

- Run token (agr_...): one per run, only accepted on the MCP endpoint, stored
  hashed. It can't call the API, so an agent can't approve its own requests.
- Operator token: the bootstrap admin, from AGENTGUARD_OPERATOR_TOKEN or the
  data directory.
- Personal tokens (agu_...): one per user from `agentguard user add`, stored hashed.
- Single sign-on: a trusted reverse proxy (exe.dev, oauth2-proxy, Cloudflare
  Access...) puts the signed-in email in a header (AGENTGUARD_AUTH_HEADER). It is
  only believed from proxy addresses, never from local connections, and only for
  emails listed as users.

Roles, each including the ones below it:
    admin     start and stop runs
    approver  approve or deny held actions
    viewer    see runs, policy and audit log
"""

from __future__ import annotations

import hmac
import ipaddress
from dataclasses import dataclass

from agentguard.canonical import sha256_hex

RUN_TOKEN_PREFIX = "agr_"  # noqa: S105 - a prefix, not a secret
USER_TOKEN_PREFIX = "agu_"  # noqa: S105 - a prefix, not a secret
ROLES = ("viewer", "approver", "admin")


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    via: str  # "operator-token", "user-token" or "sso"

    def can(self, role: str) -> bool:
        return ROLES.index(self.role) >= ROLES.index(role)


def hash_token(token: str) -> str:
    return sha256_hex("agentguard-run-token:" + token)


def hash_user_token(token: str) -> str:
    return sha256_hex("agentguard-user-token:" + token)


def bearer(header_value: str | None) -> str | None:
    if not header_value:
        return None
    scheme, _, value = header_value.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def is_operator(token: str | None, operator_token: str) -> bool:
    if not token or not operator_token or token.startswith(RUN_TOKEN_PREFIX):
        return False
    return hmac.compare_digest(token.encode(), operator_token.encode())


def trusted_proxy(peer: str | None, trusted: list[str]) -> bool:
    """May a request from `peer` carry the SSO header?

    With AGENTGUARD_TRUSTED_PROXIES set, only those networks. Otherwise any
    non-loopback peer: the proxy connects from outside, while processes on this
    machine (agents included) connect over loopback and can't forge the header.
    """
    if not peer:
        return False
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if trusted:
        return any(ip in ipaddress.ip_network(net, strict=False) for net in trusted)
    return not ip.is_loopback
