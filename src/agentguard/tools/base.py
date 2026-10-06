"""Tool contracts: strict argument checks, labels and handlers.

A tool is either built in (arguments checked by a pydantic model, handler in
this package) or proxied from an upstream MCP server (arguments checked by the
server's JSON schema, handler forwards the call). The gate treats both alike.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import jsonschema
from pydantic import BaseModel, ConfigDict, ValidationError

from agentguard.tools.dataset import Dataset


class ToolArgs(BaseModel):
    """Base for tool arguments: unknown fields are rejected, values are canonicalized."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


@dataclass(frozen=True)
class ToolContext:
    run_id: str
    action_id: str
    dataset: Dataset
    now: datetime


# Built-in handlers take the validated pydantic model; upstream handlers take the
# canonical argument dict. Either may be async.
ToolHandler = Callable[[ToolContext, Any], dict[str, Any] | Awaitable[dict[str, Any]]]
FactsFn = Callable[[Any], dict[str, Any]]


def _no_facts(_args: Any) -> dict[str, Any]:
    return {}


class ToolArgsError(ValueError):
    """The proposed arguments don't match the tool's contract."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    labels: frozenset[str]
    handler: ToolHandler
    args_model: type[ToolArgs] | None = None  # built-in tools
    schema: dict[str, Any] | None = None  # upstream tools: the server's JSON schema
    facts: FactsFn = field(default=_no_facts)
    source: str = "builtin"  # or the upstream server's name

    def __post_init__(self) -> None:
        if (self.args_model is None) == (self.schema is None):
            raise ValueError(f"tool {self.name}: give exactly one of args_model or schema")

    def input_schema(self) -> dict[str, Any]:
        if self.schema is not None:
            return self.schema
        assert self.args_model is not None
        schema = self.args_model.model_json_schema()
        schema.pop("title", None)
        schema["additionalProperties"] = False
        for prop in schema.get("properties", {}).values():
            prop.pop("title", None)
        return schema

    def canonicalize(self, raw_args: dict[str, Any]) -> dict[str, Any]:
        """Validate raw arguments and return their canonical JSON form.

        Raises ToolArgsError on any problem.
        """
        if self.args_model is not None:
            try:
                return self.args_model.model_validate(raw_args).model_dump(mode="json")
            except ValidationError as exc:
                raise ToolArgsError(
                    "; ".join(
                        f"{'.'.join(str(p) for p in e['loc']) or '(arguments)'}: {e['msg']}"
                        for e in exc.errors()
                    )
                ) from exc
        assert self.schema is not None
        errors = sorted(
            jsonschema.Draft202012Validator(self.schema).iter_errors(raw_args), key=lambda e: list(e.path)
        )
        if errors:
            raise ToolArgsError(
                "; ".join(f"{'.'.join(str(p) for p in e.path) or '(arguments)'}: {e.message}" for e in errors)
            )
        return dict(raw_args)

    def parse(self, canonical: dict[str, Any]) -> Any:
        """What the handler and facts function receive: the model (built in) or the dict (upstream)."""
        return self.args_model.model_validate(canonical) if self.args_model is not None else canonical


class ToolRegistry:
    def __init__(self, tools: list[ToolSpec]) -> None:
        self._tools = {t.name: t for t in tools}
        if len(self._tools) != len(tools):
            raise ValueError("duplicate tool names")

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def all(self) -> list[ToolSpec]:
        return [self._tools[n] for n in self.names()]

    def labels(self) -> frozenset[str]:
        return frozenset(label for t in self._tools.values() for label in t.labels)

    def sources(self) -> frozenset[str]:
        """Where tools come from: "builtin" and the names of connected upstream servers."""
        return frozenset(t.source for t in self._tools.values())
