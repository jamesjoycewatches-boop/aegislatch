"""Trusted host wrapper. The agent must not receive direct access to the wrapped tool."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any
from .approvals import ApprovalAuthority
from .audit import AuditLedger
from .core import Decision, Policy, ToolCall


class ToolDenied(PermissionError):
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"Tool call blocked: {decision.status}: {decision.reason}")


class Gateway:
    def __init__(self, policy: Policy, *, approvals: ApprovalAuthority | None = None,
                 audit: AuditLedger | None = None):
        self.policy = policy
        self.approvals = approvals
        self.audit = audit

    def execute(self, call: ToolCall, handler: Callable[..., Any], *,
                trusted_schema: dict[str, Any] | None = None,
                approval_ticket: str | None = None) -> Any:
        decision = self.policy.evaluate(call, trusted_schema=trusted_schema)
        if decision.status == "review":
            verified = bool(approval_ticket and self.approvals and self.approvals.consume(approval_ticket, call, decision))
            if not verified:
                if self.audit:
                    self.audit.append(call, decision)
                raise ToolDenied(decision)
            decision = Decision("allow", "one-time human approval consumed", decision.rule_id)
        if self.audit:
            self.audit.append(call, decision)
        if not decision.allowed:
            raise ToolDenied(decision)
        # This package authorizes entry, not the handler's internal behavior.
        # Execute only carefully reviewed handlers with sandboxed OS privileges.
        return handler(**call.arguments)
