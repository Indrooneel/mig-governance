"""
MIG Governance — SQLite Audit Trail
House of Galatine © 2026

Every decision logged. Full traceability from action to outcome.
"""

import json
import sqlite3
import os
from typing import List
from mig_governance.core.decision import Decision


class SQLiteAudit:
    """Local SQLite audit trail. Every MIG decision is logged."""
    
    def __init__(self, db_path: str = "./mig_audit.db"):
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_table()
    
    def _create_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS mig_decisions (
                id TEXT PRIMARY KEY,
                action_text TEXT,
                decision TEXT,
                risk_score INTEGER,
                policy_id TEXT,
                matched_policy TEXT,
                flags TEXT,
                checks TEXT,
                timestamp TEXT
            )
        """)
        self.conn.commit()
    
    def log(self, action_text: str, decision: Decision):
        """Log a governance decision."""
        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO mig_decisions
                (id, action_text, decision, risk_score, policy_id, 
                 matched_policy, flags, checks, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                decision.decision_id,
                action_text,
                decision.decision,
                decision.risk_score,
                decision.policy_id,
                decision.matched_policy,
                json.dumps(decision.flags),
                json.dumps([{"name": c.name, "status": c.status, "detail": c.detail} 
                           for c in decision.checks]),
                decision.timestamp
            ))
            self.conn.commit()
        except Exception as e:
            print(f"[MIG Audit] Error logging decision: {e}")
    
    def get_recent(self, limit: int = 50) -> list:
        """Get recent decisions."""
        cur = self.conn.execute(
            "SELECT * FROM mig_decisions ORDER BY timestamp DESC LIMIT ?", 
            (limit,)
        )
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        results = []
        for row in rows:
            d = dict(zip(cols, row))
            d["flags"] = json.loads(d["flags"]) if d["flags"] else []
            d["checks"] = json.loads(d["checks"]) if d["checks"] else []
            results.append(d)
        return results
    
    def get_stats(self) -> dict:
        """Get governance statistics."""
        cur = self.conn.execute("SELECT COUNT(*) FROM mig_decisions")
        total = cur.fetchone()[0]
        cur = self.conn.execute(
            "SELECT decision, COUNT(*) FROM mig_decisions GROUP BY decision"
        )
        by_decision = dict(cur.fetchall())
        return {
            "total": total,
            "allowed": by_decision.get("ALLOW", 0),
            "denied": by_decision.get("DENY", 0),
            "approval": by_decision.get("APPROVAL", 0)
        }