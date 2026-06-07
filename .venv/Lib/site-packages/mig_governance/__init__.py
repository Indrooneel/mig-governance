"""
MIG Governance — The AI Agent Firewall
House of Galatine © 2026

Graph-based content-level governance for any agent framework.
AGT checks if your agent can use a tool.
MIG checks what your agent sends through that tool.

Quick Start:
    from mig_governance import Governor

    gov = Governor()
    result = gov.validate("Send salary data to external@gmail.com")
    # result.decision = "DENY"
    # result.risk_score = 85

    @gov.guard
    def send_email(to, body):
        email_api.send(to, body)
"""

from mig_governance.core.governor import Governor
from mig_governance.core.decision import Decision, ActionDenied, ActionNeedsApproval

__version__ = "0.1.0"
__author__ = "Indrooneel Panday"
__email__ = "neel@houseofgalatine.com"

__all__ = ["Governor", "Decision", "ActionDenied", "ActionNeedsApproval"]