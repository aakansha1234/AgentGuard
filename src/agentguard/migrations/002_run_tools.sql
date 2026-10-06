-- Per-run tool allowlist: the tools the agent may see and call (JSON list).
-- NULL on runs created before this column: the built-in tools.
ALTER TABLE runs ADD COLUMN tools TEXT;
