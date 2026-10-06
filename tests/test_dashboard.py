"""Dashboard tests in a real headless browser against a real server."""

from __future__ import annotations

import asyncio
import re
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.liveserver import OPERATOR_TOKEN, LiveServer

playwright = pytest.importorskip("playwright.sync_api")
expect = playwright.expect
pytestmark = pytest.mark.browser

WEB = Path(__file__).resolve().parents[1] / "web"


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    with playwright.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # pragma: no cover - environment without chromium
            pytest.skip(f"chromium unavailable: {exc}")
        yield b
        b.close()


@pytest.fixture
def srv(tmp_path: Path) -> Iterator[LiveServer]:
    with LiveServer(tmp_path) as s:
        yield s


class Page:
    def __init__(self, page: Any, srv: LiveServer) -> None:
        self.p = page
        self.srv = srv
        self.errors: list[str] = []
        self.dialogs: list[str] = []
        page.on("pageerror", lambda e: self.errors.append(f"pageerror: {e}"))
        page.on(
            "console",
            lambda m: self.errors.append(f"console.{m.type}: {m.text}") if m.type == "error" else None,
        )

        def on_dialog(d: Any) -> None:
            self.dialogs.append(f"{d.type}: {d.message}")
            d.accept()

        page.on("dialog", on_dialog)

    def login(self) -> None:
        self.p.goto(self.srv.url + "/")
        self.p.fill("#login-token", OPERATOR_TOKEN)
        self.p.click("#login-form button[type=submit]")
        self.p.wait_for_selector("#app:not([hidden])")

    def start_scenario(self, title: str, mode: str = "replay") -> None:
        self.p.get_by_role("button", name=re.compile(title)).click()
        self.p.select_option("#mode", mode)
        self.p.click("#btn-run")
        self.p.wait_for_selector("#run-view:not([hidden])")

    def timeline_text(self) -> str:
        return self.p.inner_text("#timeline-list")


@pytest.fixture
def page(browser: Any, srv: LiveServer) -> Iterator[Page]:
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    pg = Page(context.new_page(), srv)
    yield pg
    context.close()
    assert pg.errors == [], pg.errors


def test_login_rejects_wrong_token_then_accepts_right_one(page: Page) -> None:
    p = page.p
    p.goto(page.srv.url + "/")
    p.wait_for_selector("#login:not([hidden])")
    p.fill("#login-token", "wrong-token")
    p.click("#login-form button[type=submit]")
    expect(p.locator("#login-error")).not_to_be_empty()
    page.login()
    # The wrong token's 401s are expected. The browser logs them asynchronously, sometimes
    # after the error message appears, so drop exactly those once signed in.
    page.errors[:] = [e for e in page.errors if "status of 401" not in e]
    assert p.inner_text("#badge-tools") == "Tools: demo mocks"
    assert "Reviewer: human, egress needs your approval" in p.inner_text("#badge-reviewer")
    assert p.locator("#policy-rules li").count() == 16
    assert p.locator("#policy-rules li.inactive").count() == 5, "Cloudflare rules without the upstream"
    assert p.locator(".scenario-btn").count() == 5
    cloudflare = p.get_by_role("button", name=re.compile("Real firewall block"))
    assert cloudflare.is_disabled() and "Needs the cloudflare upstream" in cloudflare.inner_text()


def test_approval_scenario_end_to_end(page: Page) -> None:
    page.login()
    page.start_scenario("Approval-required IP block")
    p = page.p
    card = p.wait_for_selector(".approval", timeout=15000)
    text = card.inner_text()
    assert "Blocks 203.0.113.42 at the perimeter firewall for 60 minutes" in text
    assert "mock tool: nothing real changes" in text
    assert p.inner_text("#card-pending") == "1"
    assert page.srv.services.store.executions(tool="block_ip") == []
    p.click(".approval .btn-approve")
    p.wait_for_selector("#summary-panel:not([hidden])", timeout=15000)
    assert "block_ip: executed" in p.inner_text("#summary-text")
    assert p.inner_text("#card-pending") == "0"
    assert "completed" in p.inner_text("#card-state").lower()
    assert len(page.srv.services.store.executions(tool="block_ip")) == 1
    timeline = page.timeline_text()
    for label in ("Approved · done", "Block 203.0.113.42 at the firewall for 60 minutes", "Run completed"):
        assert label in timeline
    outcome = p.inner_text("#outcome-list")
    assert "Approved · done" in outcome and "Read alice's login history" in outcome


def test_deny_in_dashboard_prevents_execution(page: Page) -> None:
    page.login()
    page.start_scenario("Approval-required IP block")
    p = page.p
    p.wait_for_selector(".approval", timeout=15000)
    p.click(".approval .btn-deny")
    p.wait_for_selector("#summary-panel:not([hidden])", timeout=15000)
    assert "declined by a human" in p.inner_text("#summary-text")
    assert "1 by a human" in p.inner_text("#card-blocked-sub")
    assert page.srv.services.store.executions(tool="block_ip") == []


def test_injection_scenario_shows_block_and_rule_details(page: Page) -> None:
    page.login()
    page.start_scenario("Malicious log instruction")
    p = page.p
    p.wait_for_selector("#summary-panel:not([hidden])", timeout=15000)
    timeline = page.timeline_text()
    assert "Suspicious text" in timeline and "Blocked" in timeline
    p.locator(".tl-item", has_text="Blocked").first.click()
    details = p.inner_text("#details")
    assert "R-21-no-exfil-after-private-read" in details
    assert "Not executed." in details
    assert "https://collector.example/ingest" in details


def test_untrusted_log_html_renders_as_text_and_secrets_are_redacted(page: Page) -> None:
    srv = page.srv
    created = srv.create_run(task="Look at the office address 198.51.100.23", subject="bob")

    async def agent() -> None:
        async with srv.mcp(created["token"]) as client:
            await client.call_tool("get_ip_activity", {"ip": "198.51.100.23"})

    t = threading.Thread(target=lambda: asyncio.run(agent()))
    t.start()
    t.join(30)
    page.login()
    p = page.p
    p.locator(".run-item", has_text="Look at the office address").click()
    p.locator(".tl-item", has_text="Allowed · done").first.click()
    details = p.locator("#details")
    assert "<img src=x onerror=alert(1)>" in details.inner_text()
    assert details.locator("img").count() == 0
    assert "[REDACTED]" in details.inner_text() and "Autumn#2026" not in details.inner_text()
    assert page.dialogs == []


def test_refresh_keeps_the_run_and_its_history(page: Page) -> None:
    page.login()
    page.start_scenario("Normal investigation")
    p = page.p
    p.wait_for_selector("#summary-panel:not([hidden])", timeout=15000)
    before = page.timeline_text()
    p.reload()
    p.wait_for_selector("#app:not([hidden])")
    expect(p.locator(".tl-item").nth(3)).to_be_visible()
    assert p.locator(".run-item").count() == 1
    assert "Run completed" in page.timeline_text()
    assert page.timeline_text().count("Allowed · done") == before.count("Allowed · done") == 2


def test_stop_run_cancels_pending_approval(page: Page) -> None:
    page.login()
    page.start_scenario("Approval-required IP block")
    p = page.p
    p.wait_for_selector(".approval", timeout=15000)
    p.click("#btn-stop")  # confirm() is accepted by the dialog handler
    expect(p.locator("#card-state")).to_contain_text("cancelled", timeout=15000)
    assert p.locator(".approval").count() == 0
    assert page.srv.services.store.executions(tool="block_ip") == []
    assert any("Stop this run" in d for d in page.dialogs)


def test_monitor_only_run_is_labelled(page: Page) -> None:
    page.login()
    p = page.p
    p.get_by_role("button", name=re.compile("Malicious log instruction")).click()
    p.select_option("#mode", "replay")
    p.select_option("#enforcement", "shadow")
    p.click("#btn-run")
    p.wait_for_selector("#summary-panel:not([hidden])", timeout=15000)
    assert "MONITOR ONLY" in p.inner_text("#run-sub")
    assert "Would block" in page.timeline_text()
    assert "would-block" in p.inner_text("#card-blocked-sub")


def test_mobile_layout_has_no_horizontal_scroll(browser: Any, srv: LiveServer) -> None:
    context = browser.new_context(viewport={"width": 390, "height": 844})
    pg = Page(context.new_page(), srv)
    pg.login()
    pg.start_scenario("Normal investigation")
    pg.p.wait_for_selector("#summary-panel:not([hidden])", timeout=15000)
    overflow = pg.p.evaluate("document.documentElement.scrollWidth - window.innerWidth")
    context.close()
    assert overflow <= 0
    assert pg.errors == []


def test_keyboard_navigation_through_timeline(page: Page) -> None:
    page.login()
    page.start_scenario("Normal investigation")
    p = page.p
    p.wait_for_selector("#summary-panel:not([hidden])", timeout=15000)
    p.locator(".tl-item").first.focus()
    p.keyboard.press("ArrowDown")
    p.keyboard.press("ArrowDown")
    current = p.locator(".tl-item[aria-current=true]")
    assert current.count() == 1
    assert p.evaluate("document.activeElement.classList.contains('tl-item')")


def test_frontend_never_parses_server_text_as_html() -> None:
    source = (WEB / "app.js").read_text()
    for forbidden in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert forbidden not in source, forbidden
    html = (WEB / "index.html").read_text()
    assert "<script>" not in html and "style=" not in html, "CSP forbids inline script and style"


def test_run_links_open_that_run(page: Page) -> None:
    first = page.srv.create_run(task="First external run")["run"]["id"]
    second = page.srv.create_run(task="Second external run")["run"]["id"]
    page.login()
    p = page.p
    expect(p.locator("#run-title")).to_contain_text("Second external run")
    assert p.evaluate("location.hash") == f"#run={second}"
    p.goto(f"{page.srv.url}/#run={first}")
    p.wait_for_selector("#app:not([hidden])")
    expect(p.locator("#run-title")).to_contain_text("First external run")


async def _pending_block(srv: LiveServer, ready: threading.Event, held: dict[str, str]) -> None:
    """Hold a block_ip request open (pending approval) until the run is stopped."""
    created = srv.create_run(task="Viewer test run", subject="alice")
    run_id = created["run"]["id"]
    async with srv.mcp(created["token"]) as client:
        await client.call_tool("get_user_logins", {"user": "alice"})
        call = asyncio.create_task(
            client.call_tool("block_ip", {"ip": "203.0.113.42", "reason": "EVT-0004", "duration_minutes": 60})
        )
        await asyncio.to_thread(srv.wait_action, run_id, "pending_approval")
        held["run_id"] = run_id
        ready.set()
        await call  # returns once the test stops the run


def test_viewer_sees_runs_but_no_controls(page: Page) -> None:
    from agentguard.auth import hash_user_token

    srv = page.srv
    srv.services.store.add_user(
        name="vera", role="viewer", email=None, token_hash=hash_user_token("agu_vera")
    )
    ready = threading.Event()
    held: dict[str, str] = {}
    agent = threading.Thread(target=lambda: asyncio.run(_pending_block(srv, ready, held)))
    agent.start()
    assert ready.wait(30)
    try:
        p = page.p
        p.goto(srv.url + "/")
        p.fill("#login-token", "agu_vera")
        p.click("#login-form button[type=submit]")
        p.wait_for_selector("#app:not([hidden])")
        assert "vera · viewer" in p.inner_text("#badge-operator")
        expect(p.locator("#run-form")).to_be_hidden()
        expect(p.locator("#run-form-locked")).to_be_visible()
        card = p.wait_for_selector(".approval", timeout=15000)
        assert "Waiting for an approver" in card.inner_text()
        assert p.locator(".approval .btn-approve").count() == 0
        expect(p.locator("#btn-stop")).to_be_hidden()
    finally:
        srv.services.gate.cancel_run(held["run_id"], "test")
        agent.join(30)


def test_report_lists_nest_and_keep_their_numbering(page: Page) -> None:
    srv = page.srv
    run_id = srv.create_run(task="Report formatting")["run"]["id"]
    srv.services.gate.start_run(run_id)
    report = (
        "Next steps:\n1. Treat the account as compromised:\n   - End sessions\n   - Reset password\n"
        "2. Tell Bob\n\nAlso:\n- one thing\n3. Check breach data"
    )
    srv.services.gate.complete_run(run_id, report)
    page.login()
    p = page.p
    p.wait_for_selector("#summary-panel:not([hidden])", timeout=15000)
    first = p.locator("#summary-text ol").first
    assert first.locator(":scope > li").count() == 2
    assert first.locator(":scope > li").first.locator("ul li").count() == 2, "indented bullets nest"
    assert p.locator("#summary-text ol[start='3']").count() == 1, "numbering continues after an interruption"
