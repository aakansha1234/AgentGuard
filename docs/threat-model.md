# AgentGuard threat model

What AgentGuard defends against, how, and what it does not cover. Each defence names
the test that checks it.

## What is protected

- **Systems the agent can change** through upstream MCP servers (for example the
  Cloudflare firewall) and the credentials for them.
- **Data the agent reads** (logs, tickets) and where it could send them.
- **The decision record**: who approved what, and why something was blocked.

## Who is involved

| Actor | Trusted for | Not trusted for |
|---|---|---|
| Operator / approver (a person) | Writing policy, approving held actions | - |
| The agent (a model) | Proposing actions | Anything else: it can be wrong, overreach, or be steered |
| Content the agent reads | Nothing | Everything: logs and web pages can carry instructions |
| Upstream MCP servers | Doing what their tools say | Labelling their own tools honestly (AgentGuard defaults to the cautious reading) |
| Model reviewer (Jev / Clef) | A second opinion that can only add a human check | Allowing anything |

## Trust boundaries

1. **Agent → AgentGuard (MCP).** The agent holds only a run token, which works only on
   the MCP endpoint, for that run, and only for that run's tool allowlist.
2. **AgentGuard → upstream servers.** AgentGuard holds the credentials, resolved
   from its own environment; agents never receive them.
3. **People → AgentGuard (dashboard/API).** Operator token, personal tokens, or
   single sign-on through a trusted proxy; each person has a role.

## Threats and defences

| Threat | Defence | Checked by |
|---|---|---|
| Agent calls a tool it shouldn't | Per-run tool allowlist; unknown tools denied; default deny | `test_run_allowlist_hides_and_refuses_other_tools`, `test_policy.py` |
| Agent slips extra arguments past rules | Arguments validated against the tool's schema; undeclared fields refused | `test_discovery_builds_strict_namespaced_tools` |
| Agent bypasses AgentGuard by using credentials directly | Credentials live only in AgentGuard's environment; launched agents get an allowlisted environment | `test_live_run_happy_path` (no secrets in agent env), `test_proxied_calls_are_checked_then_forwarded` |
| Agent bypasses AgentGuard with built-in tools | Claude Code launched with no built-in tools and checked at start-up (fails closed) | `test_live_run_with_extra_tools_is_killed_before_any_call_runs` |
| Prompt injection in logs steers the agent | Rules don't read tool output; exfiltration after a private read is denied; suspicious text flagged | `test_injection_scenario_shows_block_and_rule_details` |
| Agent approves its own request | Run tokens are refused by the API; approvals need the approver role | `test_bad_tokens_and_run_tokens_are_refused`, `test_viewer_can_look_but_not_act` |
| Approved action swapped for a different one | Approval bound to the exact argument hash and policy version, single use, expires | `test_gate.py` (argument change, policy change, expiry, double approve) |
| Same approval executed twice (races, retries) | Execution ledger keyed by action id; conditional state transitions | `test_conditional_transition_has_exactly_one_winner_across_threads` |
| AgentGuard restarts mid-approval | Pending approvals fail closed on restart; nothing executes later by surprise | `test_gate.py` restart recovery |
| Upstream server changes its tools after review | Tool schemas fingerprinted at discovery; a change stops startup | `test_pool_refuses_to_open_if_tools_changed_since_discovery` |
| IP encoding tricks (`::ffff:10.0.0.1`) | IPv4-mapped addresses folded before CIDR checks | `test_cidr_rules_fold_ipv4_mapped_addresses`, `test_refuses_nonsense` |
| Forged single sign-on header | Header believed only from proxy addresses (never loopback) and only for listed users | `test_sso_header_from_a_local_process_is_ignored` |
| Secrets leak into the audit log or the UI | Tool output redacted before storage and display; webhook URL never logged | `test_untrusted_log_html_renders_as_text_and_secrets_are_redacted`, `test_approval_request_sends_a_slack_message` |
| Log text injects script into the dashboard | Strict CSP, no `innerHTML`, everything rendered as text | `test_frontend_never_parses_server_text_as_html` |
| Audit record altered afterwards | Events table append-only (database triggers); export for off-box retention | `test_events_are_append_only`, `test_export_audit_writes_json_lines_incrementally` |
| Model reviewer fooled or down | It can only escalate; on failure, outbound and side-effect actions wait for a human | `test_gate_fails_closed_when_jev_is_down` |
| Approvals expire unseen | Webhook alerts and desktop notifications; deny on expiry | `test_notify.py` |
| Runaway agent | Limits on calls, time and denials (3 strikes stops the run) | `test_gate.py` limits |

## Not covered (residual risks)

- **Tools AgentGuard doesn't see.** Only calls through AgentGuard are checked. Codex in
  particular keeps a code-execution mode that can't be turned off; run it where it
  can't reach anything sensitive ([connect-agents.md](connect-agents.md)).
- **A wrong policy.** AgentGuard enforces the rules it's given. `agentguard init` is
  cautious by default, and `policy-diff` and monitor-only mode help test changes.
  Writing good rules is still the operator's job.
- **A careless approver.** A human approving the wrong thing is not prevented; the
  approval card shows exactly what will run, and the record names who approved it.
- **Upstream server behaviour.** AgentGuard checks the request, not what the server
  then does. A malicious or buggy upstream server is out of scope.
- **The host.** Anyone with shell access to AgentGuard's machine can read its `.env`
  and database. Single process, SQLite: no high availability.
- **The reviewer's quality on real traffic.** It was measured on 50 synthetic cases;
  `agentguard export-cases` turns real traffic into cases to label and re-measure.
