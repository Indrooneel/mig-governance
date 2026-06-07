"""
MIG Governance — Server Mode
House of Galatine © 2026

Run MIG as a local API server for automation platform integration.

Usage:
    pip install mig-governance
    mig-governance serve
    
    OR
    
    python -m mig_governance.server

Then add http://localhost:8000/validate as an HTTP step
in Zapier, Make.com, Relevance AI, n8n, or Power Automate.

Your automation is now governed. Every action validated.
"""

import json
import argparse
from pathlib import Path

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    from typing import Optional
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from mig_governance.core.governor import Governor


def create_app(policies: str = None, verbose: bool = False) -> "FastAPI":
    """Create the FastAPI app with MIG governance."""
    
    if not FASTAPI_AVAILABLE:
        raise ImportError(
            "Server mode requires FastAPI and uvicorn.\n"
            "Install with: pip install mig-governance[server]\n"
            "Or: pip install fastapi uvicorn"
        )
    
    # Initialize Governor
    gov = Governor(policies=policies, verbose=verbose)
    
    app = FastAPI(
        title="MIG Governance API",
        description="The AI agent firewall. Validate any action before execution.",
        version="0.1.0"
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"]
    )
    
    # ── Request/Response Models ──
    
    class ValidateRequest(BaseModel):
        text: str
        action_type: Optional[str] = None
        context: Optional[str] = ""
        source: Optional[str] = "automation"
    
    class ApproveRequest(BaseModel):
        decision_id: str
        approved_by: str
    
    # ── Routes ──
    
    @app.get("/")
    def root():
        return {
            "service": "MIG Governance",
            "version": "0.1.0",
            "mode": gov.mode,
            "docs": "/docs",
            "validate": "POST /validate",
            "message": "Nothing executes without MIG approval."
        }
    
    @app.get("/health")
    def health():
        stats = gov.get_stats()
        policies = gov.get_policies()
        return {
            "status": "healthy",
            "mode": gov.mode,
            "policy_count": len(policies),
            "total_decisions": stats.get("total", 0),
            "graph_stats": gov.graph.get_graph_stats() if hasattr(gov, 'graph') else {}
        }
    
    @app.post("/validate")
    def validate(req: ValidateRequest):
        """
        Validate an action before execution.
        
        Send any action description. MIG returns ALLOW, DENY, or APPROVAL.
        
        Use this endpoint in your automation workflow:
        - Zapier: Webhooks by Zapier → POST
        - Make.com: HTTP Request module → POST
        - Relevance AI: Custom tool → HTTP POST
        - n8n: HTTP Request node → POST
        - Power Automate: HTTP action → POST
        """
        context = None
        if req.context:
            try:
                context = json.loads(req.context)
            except (json.JSONDecodeError, TypeError):
                context = {"raw_context": req.context}
        
        if req.action_type:
            if context is None:
                context = {}
            context["action_type_hint"] = req.action_type
        
        result = gov.validate(req.text, context=context)
        
        return result.to_dict()
    
    @app.get("/policies")
    def list_policies():
        policies = gov.get_policies()
        return {"policies": policies, "count": len(policies)}
    
    @app.get("/audit")
    def get_audit(limit: int = 50):
        decisions = gov.get_audit(limit)
        return {"count": len(decisions), "decisions": decisions}
    
    @app.get("/stats")
    def get_stats():
        return gov.get_stats()
    
    @app.get("/graph")
    def get_graph():
        """View the policy graph structure."""
        if hasattr(gov, 'graph'):
            return {
                "stats": gov.graph.get_graph_stats(),
                "visualization": gov.graph.visualize_text()
            }
        return {"error": "Graph not available in pro mode"}
    
    return app


def main():
    """CLI entry point: mig-governance serve"""
    parser = argparse.ArgumentParser(
        description="MIG Governance Server — validate any action before execution"
    )
    parser.add_argument(
        "command", 
        choices=["serve"],
        help="Command to run"
    )
    parser.add_argument(
        "--policies", "-p",
        default=None,
        help="Path to policy JSON file or directory"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to run on (default: 8000)"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.command == "serve":
        try:
            import uvicorn
        except ImportError:
            print("Server mode requires uvicorn.")
            print("Install with: pip install uvicorn")
            return
        
        app = create_app(policies=args.policies, verbose=args.verbose)
        
        print(f"""
╔══════════════════════════════════════════════════════╗
║  MIG Governance Server v0.1.0                        ║
║  House of Galatine                                   ║
║                                                      ║
║  Validate endpoint: http://{args.host}:{args.port}/validate    ║
║  API docs:          http://{args.host}:{args.port}/docs        ║
║  Health check:      http://{args.host}:{args.port}/health      ║
║                                                      ║
║  Add this URL as an HTTP step in your automation:    ║
║  Zapier · Make.com · Relevance AI · n8n · Power Auto ║
║                                                      ║
║  "Nothing executes without MIG approval."            ║
╚══════════════════════════════════════════════════════╝
        """)
        
        uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()