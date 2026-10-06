"""Command line: `agentguard serve | start | stop | restart | status | check-policy | connect | ...`."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import httpx2

from agentguard.config import ConfigError, Settings, load_project_dotenv


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from agentguard.app import create_app
    from agentguard.services import ReviewerConfigError
    from agentguard.tools.upstream import UpstreamError

    settings = Settings.from_env()
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port
    from_env = bool(settings.operator_token)
    token = settings.ensure_operator_token()
    try:
        app = create_app(settings)
    except (ReviewerConfigError, UpstreamError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    source = "AGENTGUARD_OPERATOR_TOKEN" if from_env else str(settings.data_dir / "operator_token")
    print(f"AgentGuard dashboard: {settings.public_base_url}/")
    print(f"MCP gateway:          {settings.public_mcp_url}")
    print(f"Listening on:         {settings.host}:{settings.port}")
    print(f"Operator token:       {token[:6]}… (full value in {source})")
    print(f"Reviewer:             {settings.reviewer}")
    print(f"Claude Code CLI:      {'found' if settings.claude_available() else 'not found (live mode off)'}")
    sys.stdout.flush()
    # Dashboards hold live-update streams open; don't let them block a restart.
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="warning", timeout_graceful_shutdown=5)
    return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    from agentguard import daemon

    settings = Settings.from_env()
    if args.command == "restart":
        daemon.stop(settings)
        return daemon.start(settings)
    return int(getattr(daemon, args.command)(settings))


def cmd_check_policy(args: argparse.Namespace) -> int:
    from agentguard.policy import Policy, PolicyError
    from agentguard.services import build_registry
    from agentguard.tools.upstream import UpstreamError

    settings = Settings.from_env()
    path = Path(args.path) if args.path else settings.policy_path
    try:
        registry, _ = build_registry(settings)  # includes upstream tools, so their rules are checked too
        policy = Policy.load(path, registry)
    except (PolicyError, UpstreamError) as exc:
        print(f"invalid policy: {exc}", file=sys.stderr)
        return 1
    print(f"{path}: OK, version {policy.version}, {len(policy.doc.rules)} rules")
    if policy.inactive_rules:
        print(f"inactive (upstream not configured): {', '.join(sorted(policy.inactive_rules))}")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    from agentguard.onboarding import init_policy
    from agentguard.tools.upstream import UpstreamError

    settings = Settings.from_env()
    upstreams = Path(args.upstreams) if args.upstreams else settings.upstreams_path
    if upstreams is None:
        print("Set AGENTGUARD_UPSTREAMS or pass --upstreams (see upstreams.example.yaml).", file=sys.stderr)
        return 2
    try:
        path, specs = init_policy(upstreams, Path(args.output), force=args.force)
    except (UpstreamError, FileExistsError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {path} for {len(specs)} tools:")
    for spec in specs:
        print(f"  {spec.name:40} {', '.join(sorted(spec.labels))}")
    print(
        "\nNext:\n"
        f"  1. Read and tighten the rules in {path}.\n"
        f"  2. Put AGENTGUARD_POLICY={path} (and AGENTGUARD_DEMO_TOOLS=off) in .env.\n"
        "  3. uv run agentguard check-policy && uv run agentguard restart"
    )
    return 0


def cmd_policy_diff(args: argparse.Namespace) -> int:
    from agentguard.policy import Policy, PolicyError
    from agentguard.policy_diff import diff, print_report
    from agentguard.services import build_registry
    from agentguard.store import Store
    from agentguard.tools.upstream import UpstreamError

    settings = Settings.from_env()
    try:
        registry, _ = build_registry(settings)
        policy = Policy.load(Path(args.policy), registry)
    except (PolicyError, UpstreamError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    store = Store(settings.db_path)
    try:
        print_report(diff(store, policy, args.limit), f"{args.policy} ({policy.version})")
    finally:
        store.close()
    return 0


def cmd_notify_test(args: argparse.Namespace) -> int:
    """Send a sample approval alert to AGENTGUARD_NOTIFY_WEBHOOK."""
    from agentguard.notify import Notifier
    from agentguard.store import EventRecord

    settings = Settings.from_env()
    if not settings.notify_webhook:
        print("Set AGENTGUARD_NOTIFY_WEBHOOK first (e.g. a Slack incoming-webhook URL).", file=sys.stderr)
        return 2

    event = EventRecord(
        0,
        "run_test",
        0,
        "",
        "approval.requested",
        "act_test",
        {
            "tool": "cloudflare__block_ip",
            "args": {"ip": "203.0.113.42", "duration_minutes": 60},
            "rule_ids": ["R-32-cf-block-needs-human"],
            "explanation": "This is a test alert from `agentguard notify-test`.",
            "expires_at": "in 5 minutes",
        },
    )

    async def send() -> bool:
        notifier = Notifier(
            url=settings.notify_webhook or "",
            fmt=settings.notify_format,
            dashboard_url=settings.public_base_url,
            bus=None,
            recorder=None,
        )
        try:
            return await notifier.send(event)
        finally:
            await notifier.stop()

    ok = asyncio.run(send())
    print("sent" if ok else "failed: check the URL and the server's log")
    return 0 if ok else 1


def cmd_user(args: argparse.Namespace) -> int:
    import re
    import secrets
    import sqlite3

    from agentguard.auth import ROLES, USER_TOKEN_PREFIX, hash_user_token
    from agentguard.store import Store

    settings = Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(settings.db_path)
    try:
        if args.action == "list":
            users = store.list_users()
            if not users:
                print("No users yet. The operator token is the only way in.")
            for u in users:
                sign_in = ", ".join(x for x in ("token" if u.token_hash else "", u.email or "") if x)
                print(f"  {u.name:20} {u.role:9} {sign_in}{'  (disabled)' if u.disabled else ''}")
            return 0
        if args.action == "remove":
            if not store.remove_user(args.name):
                print(f"no user {args.name!r}", file=sys.stderr)
                return 1
            print(f"Removed {args.name}.")
            return 0
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9._@-]{0,63}", args.name):
            print("names start with a letter and use letters, digits, . _ @ -", file=sys.stderr)
            return 2
        if args.role not in ROLES:
            print(f"role must be one of {', '.join(ROLES)}", file=sys.stderr)
            return 2
        token = None if args.no_token else USER_TOKEN_PREFIX + secrets.token_urlsafe(32)
        if token is None and not args.email:
            print("a user needs a token, an --email for single sign-on, or both", file=sys.stderr)
            return 2
        try:
            store.add_user(
                name=args.name,
                role=args.role,
                email=args.email,
                token_hash=hash_user_token(token) if token else None,
            )
        except sqlite3.IntegrityError:
            print(f"{args.name!r} or that email is already a user", file=sys.stderr)
            return 1
        print(f"Added {args.name} ({args.role}).")
        if token:
            print(f"Token (shown once; paste it on the dashboard sign-in): {token}")
        if args.email:
            how = settings.auth_header or "AGENTGUARD_AUTH_HEADER (not set yet)"
            print(f"Single sign-on: {args.email} via {how}")
        return 0
    finally:
        store.close()


def cmd_backup(args: argparse.Namespace) -> int:
    from datetime import UTC, datetime

    from agentguard.store import Store

    settings = Settings.from_env()
    if not settings.db_path.exists():
        print(f"no database at {settings.db_path}", file=sys.stderr)
        return 1
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    dest = Path(args.output) if args.output else settings.data_dir / "backups" / f"agentguard-{stamp}.sqlite"
    dest.parent.mkdir(parents=True, exist_ok=True)
    store = Store(settings.db_path)
    try:
        store.backup(dest)
    finally:
        store.close()
    dest.chmod(0o600)
    print(f"Backed up to {dest}")
    return 0


def cmd_export_audit(args: argparse.Namespace) -> int:
    """Write the audit log as JSON lines (one event per line), e.g. for a SIEM."""
    from agentguard.store import Store

    settings = Settings.from_env()
    store = Store(settings.db_path)
    out = open(args.output, "a" if args.append else "w") if args.output else sys.stdout  # noqa: SIM115
    last = args.after
    count = 0
    try:
        while batch := store.all_events_after(last):
            for event in batch:
                out.write(json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
                last = event.seq
                count += 1
    finally:
        if out is not sys.stdout:
            out.close()
        store.close()
    print(f"exported {count} events; next time use --after {last}", file=sys.stderr)
    return 0


def cmd_connect(args: argparse.Namespace) -> int:
    """Create an external run and print how to point an MCP client (e.g. Claude Code) at it."""
    settings = Settings.from_env()
    token = settings.ensure_operator_token()
    from agentguard.connect import instructions

    body: dict[str, object] = {
        "task": args.task,
        "mode": "external",
        "dataset_id": args.dataset,
        "subject": args.subject,
        "enforcement": "shadow" if args.shadow else "enforce",
    }
    if args.tools:
        body["tools"] = [t.strip() for t in args.tools.split(",") if t.strip()]
    resp = httpx2.post(
        f"{settings.base_url}/api/runs", json=body, headers={"Authorization": f"Bearer {token}"}, timeout=10
    )
    if resp.status_code != 201:
        print(f"error {resp.status_code}: {resp.text}", file=sys.stderr)
        return 1
    data = resp.json()
    run = data["run"]
    url = data["mcp_config"]["mcpServers"]["agentguard"]["url"]
    print(f"Run {run['id']} created ({len(run['tools'])} tools: {', '.join(run['tools'])}).")
    print("The token below is shown once.\n")
    print(instructions(args.client, url, data["token"]))
    print(f"\nWatch and approve on the dashboard: {settings.public_base_url}/#run={run['id']}")
    print(
        "Only calls to AgentGuard's tools are guarded. An agent's own built-in tools "
        "(shell, file, web) bypass AgentGuard unless they're turned off."
    )
    return 0


def cmd_export_cases(args: argparse.Namespace) -> int:
    from agentguard.policy import Policy
    from agentguard.reviewer_eval import export_real_cases
    from agentguard.services import build_registry
    from agentguard.store import Store

    settings = Settings.from_env()
    registry, _ = build_registry(settings)
    labels = list(Policy.load(settings.policy_path, registry).doc.reviewer.review_labels)
    store = Store(settings.db_path)
    try:
        text = export_real_cases(store, labels, args.limit)
    finally:
        store.close()
    Path(args.output).write_text(text)
    count = text.count("\n- id: ")
    print(f"Wrote {count} cases to {args.output}. Label them, then run eval-reviewer --cases {args.output}.")
    return 0


def cmd_eval_reviewer(args: argparse.Namespace) -> int:
    from agentguard.reviewer_eval import main as eval_main

    return asyncio.run(eval_main(args))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run the dashboard, API and MCP gateway")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.set_defaults(fn=cmd_serve)

    for name, text in (
        ("start", "run the server in the background (log and pid in the data directory)"),
        ("stop", "stop the background server and the agents it launched"),
        ("restart", "stop, then start"),
        ("status", "show whether the background server is running"),
    ):
        sub.add_parser(name, help=text).set_defaults(fn=cmd_daemon)

    p = sub.add_parser("check-policy", help="validate a policy file")
    p.add_argument("path", nargs="?")
    p.set_defaults(fn=cmd_check_policy)

    p = sub.add_parser("init", help="write a starting policy for the MCP servers in your upstreams file")
    p.add_argument("--upstreams", help="upstreams file (default: AGENTGUARD_UPSTREAMS)")
    p.add_argument("--output", default="policies/my-policy.yaml")
    p.add_argument("--force", action="store_true", help="overwrite an existing file")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("policy-diff", help="replay recorded decisions against an edited policy")
    p.add_argument("policy", help="the policy file to try")
    p.add_argument("--limit", type=int, default=1000, help="how many recent actions to replay")
    p.set_defaults(fn=cmd_policy_diff)

    sub.add_parser("notify-test", help="send a sample alert to AGENTGUARD_NOTIFY_WEBHOOK").set_defaults(
        fn=cmd_notify_test
    )

    p = sub.add_parser("user", help="manage who can use the dashboard and API")
    user_sub = p.add_subparsers(dest="action", required=True)
    add = user_sub.add_parser("add", help="add a user (prints their token once)")
    add.add_argument("name")
    add.add_argument("--role", required=True, help="admin, approver or viewer")
    add.add_argument("--email", help="for single sign-on through AGENTGUARD_AUTH_HEADER")
    add.add_argument("--no-token", action="store_true", help="single sign-on only, no personal token")
    user_sub.add_parser("list", help="list users")
    rm = user_sub.add_parser("remove", help="remove a user")
    rm.add_argument("name")
    p.set_defaults(fn=cmd_user)

    p = sub.add_parser("backup", help="consistent copy of the database (safe while running)")
    p.add_argument("--output", help="file to write (default: <data dir>/backups/agentguard-<time>.sqlite)")
    p.set_defaults(fn=cmd_backup)

    p = sub.add_parser("export-audit", help="audit log as JSON lines, e.g. for a SIEM")
    p.add_argument("--output", help="file to write (default: stdout)")
    p.add_argument("--after", type=int, default=0, help="only events after this sequence number")
    p.add_argument("--append", action="store_true", help="append to --output instead of replacing it")
    p.set_defaults(fn=cmd_export_audit)

    p = sub.add_parser("connect", help="create a run for an external MCP agent")
    p.add_argument("--task", required=True)
    p.add_argument("--dataset", default="baseline")
    p.add_argument("--subject", default="alice")
    p.add_argument("--shadow", action="store_true", help="monitor only: record, do not block")
    p.add_argument("--client", choices=["claude", "codex", "api"], default="claude", help="which agent")
    p.add_argument("--tools", help="comma-separated tool allowlist (default: every tool)")
    p.set_defaults(fn=cmd_connect)

    p = sub.add_parser("export-cases", help="export real reviewed actions as eval cases to label")
    p.add_argument("--output", default="real_cases.yaml")
    p.add_argument("--limit", type=int, default=1000)
    p.set_defaults(fn=cmd_export_cases)

    p = sub.add_parser("eval-reviewer", help="measure whether a model reviewer (Jev or Clef) adds value")
    p.add_argument("--reviewer", choices=["jev", "clef"], default="jev")
    p.add_argument(
        "--cases", action="append", help="labelled cases YAML (repeatable; default: dev + held-out)"
    )
    p.add_argument("--review-labels", help="comma-separated tool labels to review (default: from the policy)")
    p.add_argument("--threshold", type=float)
    p.add_argument("--fake", action="store_true", help="keyword stand-in instead of a model (no API key)")
    p.set_defaults(fn=cmd_eval_reviewer)

    args = parser.parse_args(argv)
    load_project_dotenv()
    try:
        return int(args.fn(args))
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
