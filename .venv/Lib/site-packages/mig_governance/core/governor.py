"""
MIG Governance — Governor Class
House of Galatine © 2026

The main entry point. This is what users interact with.

    gov = Governor()
    result = gov.validate("Send salary data externally")
    
    @gov.guard
    def send_email(to, body):
        ...
"""

import inspect
import json
from pathlib import Path
from typing import Optional, Callable

from mig_governance.core.decision import Decision, Check, ActionDenied, ActionNeedsApproval
from mig_governance.engine.validator import ValidationPipeline
from mig_governance.graph.nx_engine import NetworkXPolicyGraph
from mig_governance.embeddings.chroma_store import ChromaEmbeddings
from mig_governance.audit.sqlite_logger import SQLiteAudit


class Governor:
    """
    The MIG governance layer. Validates actions before execution.
    
    Free mode (default):
        gov = Governor(policies="./policies.json")
        # Uses NetworkX + ChromaDB locally. Zero servers.
    
    Pro mode:
        gov = Governor(api_key="gal_xxxxx")
        # Connects to hosted MIG with Neo4j + semantic embeddings.
    
    No policies specified:
        gov = Governor()
        # Loads built-in default policies.
    """
    
    def __init__(self, policies=None, api_key: str = None, 
                 endpoint: str = None, audit_path: str = None,
                 verbose: bool = False):
        
        self.verbose = verbose
        
        if api_key:
            # ── PRO MODE: Connect to hosted MIG ──
            self.mode = "pro"
            self.api_key = api_key
            self.endpoint = endpoint or "https://api.houseofgalatine.com"
            self._log("PRO mode — connecting to hosted MIG engine")
        else:
            # ── FREE MODE: Local NetworkX + ChromaDB ──
            self.mode = "local"
            
            # Build policy graph
            self.graph = NetworkXPolicyGraph()
            
            # Load policies
            if policies is None:
                policies = self._default_policies_path()
            
            if isinstance(policies, str):
                policy_path = Path(policies)
                if policy_path.is_file():
                    self.graph.load_from_file(policy_path)
                elif policy_path.is_dir():
                    self.graph.load_from_directory(policy_path)
                else:
                    self._log(f"Policy path not found: {policies}. Loading defaults.")
                    self.graph.load_from_file(self._default_policies_path())
            elif isinstance(policies, dict):
                self.graph.load_from_dict(policies)
            elif isinstance(policies, list):
                for p in policies:
                    if isinstance(p, str):
                        self.graph.load_from_file(Path(p))
                    elif isinstance(p, dict):
                        self.graph.load_from_dict(p)
            
            # Initialize ChromaDB for semantic matching
            self.embeddings = ChromaEmbeddings()
            all_policies = self.graph.get_all_policies()
            if all_policies:
                self.embeddings.index_policies(all_policies)
            
            # Validation pipeline
            self.pipeline = ValidationPipeline()
            
            # Audit trail
            audit_db = audit_path or "./mig_audit.db"
            self.audit = SQLiteAudit(audit_db)
            
            policy_count = len(all_policies)
            self._log(f"LOCAL mode — {policy_count} policies loaded, "
                     f"NetworkX graph built, ChromaDB indexed")
    
    
    def validate(self, action: str, context: dict = None) -> Decision:
        """
        Validate an action before execution.
        
        Args:
            action: Text description of the action to validate
            context: Optional context dict with additional info
        
        Returns:
            Decision with .decision (ALLOW/DENY/APPROVAL), .risk_score, 
            .checks, .flags, .policy_id
        
        Example:
            result = gov.validate("Send financial report to external@gmail.com")
            if result.is_allowed:
                do_the_thing()
        """
        if self.mode == "pro":
            return self._validate_pro(action, context)
        
        return self._validate_local(action, context)
    
    
    def guard(self, func: Callable = None, *, action_type: str = None):
        """
        Decorator that validates before function execution.
        
        Usage:
            @gov.guard
            def send_email(to, body):
                ...
            
            @gov.guard(action_type="payment")
            def process_payment(amount, recipient):
                ...
        
        Raises:
            ActionDenied: if MIG denies the action
            ActionNeedsApproval: if MIG requires operator approval
        """
        def decorator(f):
            def wrapper(*args, **kwargs):
                # Build action description from function call
                action_desc = self._build_action_description(f, args, kwargs)
                
                # Add action_type override if specified
                ctx = {"action_type_hint": action_type} if action_type else None
                
                # Validate through MIG
                result = self.validate(action_desc, context=ctx)
                
                if result.is_allowed:
                    return f(*args, **kwargs)
                elif result.needs_approval:
                    raise ActionNeedsApproval(result)
                else:
                    raise ActionDenied(result)
            
            wrapper.__name__ = f.__name__
            wrapper.__doc__ = f.__doc__
            wrapper._mig_governed = True
            wrapper._mig_governor = self
            return wrapper
        
        # Support both @gov.guard and @gov.guard(action_type="x")
        if func is not None:
            return decorator(func)
        return decorator
    
    
    def get_audit(self, limit: int = 50) -> list:
        """Get recent audit trail entries."""
        if self.mode == "pro":
            return self._pro_request("GET", "/audit", params={"limit": limit})
        return self.audit.get_recent(limit)
    
    
    def get_policies(self) -> list:
        """Get all loaded policies."""
        if self.mode == "pro":
            return self._pro_request("GET", "/policies")
        return self.graph.get_all_policies()
    
    
    def get_stats(self) -> dict:
        """Get governance statistics."""
        if self.mode == "pro":
            return self._pro_request("GET", "/stats")
        return self.audit.get_stats()
    
    
    # ═══════════════════════════════════════════════════════
    # INTERNAL: Local validation
    # ═══════════════════════════════════════════════════════
    
    def _validate_local(self, action: str, context: dict = None) -> Decision:
        """Run the full local validation pipeline."""
        checks = []
        flags = []
        risk_score = 10
        
        # ── Step 1: PII Detection ──
        pii_result = self.pipeline.detect_pii(action)
        if pii_result["found"]:
            flags.append("PII_DETECTED")
            risk_score = max(risk_score, 40)
            checks.append(Check(
                name="PII Detection",
                status="flag",
                detail=f"Detected: {', '.join(pii_result['types'])}"
            ))
        else:
            checks.append(Check(
                name="PII Detection",
                status="pass",
                detail="No sensitive data patterns detected"
            ))
        
        # ── Step 2: Action Classification ──
        action_type = self.pipeline.classify_action(action)
        if context and context.get("action_type_hint"):
            action_type = context["action_type_hint"]
        checks.append(Check(
            name="Action Classification",
            status="pass",
            detail=f"Classified as: {action_type}"
        ))
        
        # ── Step 3: Payload Analysis ──
        payload = self.pipeline.analyze_payload(action)
        if payload["sensitivity"] == "critical":
            risk_score = max(risk_score, 70)
            flags.append("PAYLOAD_CRITICAL")
        elif payload["sensitivity"] == "high":
            risk_score = max(risk_score, 40)
            flags.append("PAYLOAD_HIGH")
        
        if payload["destination"] == "external":
            risk_score = max(risk_score, 50)
            flags.append("EXTERNAL_DESTINATION")
        
        checks.append(Check(
            name="Payload Analysis",
            status="fail" if risk_score >= 70 else "flag" if risk_score >= 40 else "pass",
            detail=f"Sensitivity: {payload['sensitivity']} | Destination: {payload['destination']} | Risk: {risk_score}"
        ))
        
        # ── Step 4: Semantic Matching (ChromaDB) ──
        semantic_matches = self.embeddings.find_similar(action, top_k=3)
        
        # ── Step 5: Graph Policy Matching (NetworkX) ──
        matched_policy = self.graph.find_policy(
            action_type=action_type,
            destination=payload["destination"],
            sensitivity=payload["sensitivity"],
            semantic_candidates=semantic_matches
        )
        
        if matched_policy:
            decision = matched_policy.get("direction", "DENY")
            policy_id = matched_policy.get("id", "UNKNOWN")
            policy_desc = matched_policy.get("description", "")
            checks.append(Check(
                name="Graph Policy Match",
                status="pass" if decision == "ALLOW" else "fail" if decision == "DENY" else "flag",
                detail=f"{policy_id}: {policy_desc[:80]}"
            ))
        else:
            decision = "DENY"
            policy_id = "FAIL_CLOSED"
            policy_desc = "No matching policy — fail-closed"
            flags.append("NO_POLICY_MATCH")
            checks.append(Check(
                name="Graph Policy Match",
                status="fail",
                detail="No matching policy found — fail-closed → DENY"
            ))
        
        # ── Step 6: Risk Override ──
        if pii_result["found"] and payload["destination"] == "external":
            decision = "DENY"
            risk_score = max(risk_score, 90)
            flags.append("PII_EXTERNAL_OVERRIDE")
            checks.append(Check(
                name="Override",
                status="fail",
                detail="PII + external destination → DENY override"
            ))
        elif risk_score >= 80 and decision == "ALLOW":
            decision = "APPROVAL"
            flags.append("RISK_ESCALATION")
            checks.append(Check(
                name="Override",
                status="flag",
                detail=f"High risk ({risk_score}) → escalated to APPROVAL"
            ))
        elif risk_score >= 90 and decision == "APPROVAL":
            decision = "DENY"
            flags.append("RISK_OVERRIDE")
            checks.append(Check(
                name="Override",
                status="fail",
                detail=f"Critical risk ({risk_score}) → overridden to DENY"
            ))
        else:
            checks.append(Check(
                name="Override",
                status="pass",
                detail="No override needed"
            ))
        
        # ── Step 7: Final Decision ──
        if decision == "DENY":
            risk_score = max(risk_score, 70)
        
        checks.append(Check(
            name="Decision",
            status="pass" if decision == "ALLOW" else "fail" if decision == "DENY" else "flag",
            detail=f"Final: {decision} | Risk: {risk_score}/100"
        ))
        
        # ── Step 8: Audit ──
        result = Decision(
            decision=decision,
            risk_score=risk_score,
            policy_id=policy_id,
            matched_policy=policy_desc,
            checks=checks,
            flags=flags
        )
        
        self.audit.log(action, result)
        
        self._log(f"{result}")
        
        return result
    
    
    # ═══════════════════════════════════════════════════════
    # INTERNAL: Pro validation (API call)
    # ═══════════════════════════════════════════════════════
    
    def _validate_pro(self, action: str, context: dict = None) -> Decision:
        """Validate through hosted MIG engine."""
        try:
            import requests
        except ImportError:
            raise ImportError(
                "Pro mode requires 'requests' package. "
                "Install with: pip install mig-governance[pro]"
            )
        
        try:
            response = requests.post(
                f"{self.endpoint}/validate",
                json={
                    "text": action,
                    "context": json.dumps(context) if context else "",
                    "source": "mig_sdk"
                },
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return Decision(
                    decision=data.get("decision", "DENY"),
                    risk_score=data.get("risk_score", 100),
                    decision_id=data.get("decision_id", ""),
                    policy_id=data.get("policy_id", "UNKNOWN"),
                    matched_policy=data.get("matched_policy", ""),
                    checks=[Check(**c) for c in data.get("checks", [])],
                    flags=data.get("flags", [])
                )
            else:
                # API error — fail-closed
                return Decision(
                    decision="DENY",
                    risk_score=100,
                    policy_id="FAIL_CLOSED",
                    matched_policy=f"MIG Pro API error: {response.status_code}",
                    flags=["PRO_API_ERROR"]
                )
                
        except Exception as e:
            # Connection error — fail-closed
            return Decision(
                decision="DENY",
                risk_score=100,
                policy_id="FAIL_CLOSED",
                matched_policy=f"MIG Pro unreachable: {str(e)}",
                flags=["PRO_UNREACHABLE"]
            )
    
    
    def _pro_request(self, method: str, path: str, **kwargs):
        """Make a request to hosted MIG Pro."""
        import requests
        url = f"{self.endpoint}{path}"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        resp = requests.request(method, url, headers=headers, timeout=10, **kwargs)
        return resp.json()
    
    
    # ═══════════════════════════════════════════════════════
    # INTERNAL: Helpers
    # ═══════════════════════════════════════════════════════
    
    def _build_action_description(self, func, args, kwargs) -> str:
        """Convert a function call into a text description for validation."""
        parts = [func.__name__]
        
        try:
            sig = inspect.signature(func)
            param_names = list(sig.parameters.keys())
            
            for i, arg in enumerate(args):
                if i < len(param_names):
                    parts.append(f"{param_names[i]}={arg}")
                else:
                    parts.append(str(arg))
            
            for key, val in kwargs.items():
                parts.append(f"{key}={val}")
        except (ValueError, TypeError):
            parts.extend(str(a) for a in args)
            parts.extend(f"{k}={v}" for k, v in kwargs.items())
        
        return " ".join(str(p) for p in parts)
    
    
    def _default_policies_path(self) -> str:
        """Get path to built-in default policies."""
        return str(Path(__file__).parent.parent / "policies" / "default.json")
    
    
    def _log(self, msg: str):
        """Print log message if verbose mode is on."""
        if self.verbose:
            print(f"[MIG] {msg}")