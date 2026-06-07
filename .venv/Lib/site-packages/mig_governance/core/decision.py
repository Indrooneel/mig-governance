"""
MIG Governance — Decision Types & Exceptions
House of Galatine © 2026
"""

from dataclasses import dataclass, field
from typing import List
import time
from datetime import datetime, timezone


@dataclass
class Check:
    """Single validation check result."""
    name: str
    status: str  # pass, fail, flag
    detail: str


@dataclass
class Decision:
    """
    MIG governance decision.
    
    Attributes:
        decision: ALLOW, DENY, or APPROVAL
        risk_score: 0-100 risk assessment
        decision_id: unique identifier for audit trail
        policy_id: matched policy identifier
        matched_policy: description of matched policy
        checks: list of pipeline check results
        flags: list of triggered flags
        timestamp: ISO 8601 timestamp
    """
    decision: str
    risk_score: int = 10
    decision_id: str = ""
    policy_id: str = "FAIL_CLOSED"
    matched_policy: str = ""
    checks: List[Check] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.decision_id:
            self.decision_id = f"dec_{int(time.time() * 1000)}"
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
    
    @property
    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"
    
    @property
    def is_denied(self) -> bool:
        return self.decision == "DENY"
    
    @property
    def needs_approval(self) -> bool:
        return self.decision == "APPROVAL"
    
    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "risk_score": self.risk_score,
            "decision_id": self.decision_id,
            "policy_id": self.policy_id,
            "matched_policy": self.matched_policy,
            "checks": [{"name": c.name, "status": c.status, "detail": c.detail} for c in self.checks],
            "flags": self.flags,
            "timestamp": self.timestamp
        }
    
    def __str__(self):
        icon = "✅" if self.is_allowed else "❌" if self.is_denied else "⏸️"
        return f"{icon} {self.decision} | Risk: {self.risk_score}/100 | Policy: {self.policy_id}"


class ActionDenied(Exception):
    """Raised when MIG denies an action."""
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(
            f"MIG DENIED: {decision.matched_policy} "
            f"(risk: {decision.risk_score}/100, policy: {decision.policy_id})"
        )


class ActionNeedsApproval(Exception):
    """Raised when MIG requires operator approval."""
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(
            f"MIG APPROVAL REQUIRED: {decision.matched_policy} "
            f"(risk: {decision.risk_score}/100, decision_id: {decision.decision_id})"
        )