"""
MIG Governance — LangGraph Integration
House of Galatine © 2026

Govern LangGraph agent tool calls through MIG.

Usage:
    from mig_governance import Governor
    from mig_governance.integrations.langgraph import mig_tool, mig_node
    
    gov = Governor(policies="./finance.json")
    
    @mig_tool(gov)
    def send_email(to: str, body: str):
        email_api.send(to, body)
    
    @mig_node(gov)
    def process_payment(state):
        return {"status": "paid"}
"""

from typing import Callable
from mig_governance.core.governor import Governor
from mig_governance.core.decision import ActionDenied, ActionNeedsApproval


def mig_tool(governor: Governor):
    """
    Decorator for LangGraph tools.
    Validates the tool call through MIG before execution.
    
    @mig_tool(gov)
    def my_tool(param1, param2):
        ...
    """
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            action_desc = governor._build_action_description(func, args, kwargs)
            result = governor.validate(action_desc)
            
            if result.is_allowed:
                return func(*args, **kwargs)
            elif result.needs_approval:
                return {
                    "_mig_status": "APPROVAL_REQUIRED",
                    "_mig_decision_id": result.decision_id,
                    "_mig_risk": result.risk_score,
                    "_mig_policy": result.policy_id,
                    "error": f"MIG requires approval: {result.matched_policy}"
                }
            else:
                return {
                    "_mig_status": "DENIED",
                    "_mig_risk": result.risk_score,
                    "_mig_policy": result.policy_id,
                    "error": f"MIG blocked: {result.matched_policy}"
                }
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        wrapper._mig_governed = True
        return wrapper
    return decorator


def mig_node(governor: Governor):
    """
    Decorator for LangGraph graph nodes.
    Validates state transitions through MIG before execution.
    
    @mig_node(gov)
    def my_node(state):
        return {"result": "done"}
    """
    def decorator(func: Callable):
        def wrapper(state):
            # Build description from function name + state
            parts = [func.__name__]
            if isinstance(state, dict):
                for key, val in state.items():
                    if not key.startswith("_"):
                        parts.append(f"{key}={val}")
            
            action_desc = " ".join(str(p) for p in parts)
            result = governor.validate(action_desc, context=state if isinstance(state, dict) else None)
            
            if result.is_allowed:
                output = func(state)
                if isinstance(output, dict):
                    output["_mig_decision"] = "ALLOW"
                    output["_mig_risk"] = result.risk_score
                return output
            
            elif result.needs_approval:
                return {
                    "_mig_decision": "APPROVAL",
                    "_mig_risk": result.risk_score,
                    "_mig_decision_id": result.decision_id,
                    "status": "pending_approval"
                }
            
            else:
                return {
                    "_mig_decision": "DENY",
                    "_mig_risk": result.risk_score,
                    "_mig_policy": result.policy_id,
                    "status": "blocked"
                }
        
        wrapper.__name__ = func.__name__
        wrapper._mig_governed = True
        return wrapper
    return decorator