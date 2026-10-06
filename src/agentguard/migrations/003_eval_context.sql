-- What the policy saw when it decided an action (JSON: tool, labels, args, facts, run,
-- session, and the policy's own effect and rules before any reviewer escalation).
-- Lets `agentguard policy-diff` replay recorded decisions against an edited policy.
ALTER TABLE actions ADD COLUMN eval_context TEXT;
