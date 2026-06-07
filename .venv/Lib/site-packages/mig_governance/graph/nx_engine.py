"""
MIG Governance — NetworkX Policy Graph Engine
House of Galatine © 2026

Graph-based policy matching using NetworkX.
This is what makes MIG different from rule-based systems.

Graph Structure:
    (:PolicyPack) --[:CONTAINS]--> (:Policy)
    (:Policy) --[:APPLIES_TO]--> (:ActionType)
    (:Policy) --[:TARGETS]--> (:Destination)
    (:Policy) --[:PROTECTS]--> (:DataType)
    (:Zone) --[:ENFORCES]--> (:Policy)
    (:Zone) --[:CONNECTS_TO]--> (:Zone)
"""

import json
import networkx as nx
from pathlib import Path
from typing import Optional, List, Dict, Tuple


class NetworkXPolicyGraph:
    """
    In-memory policy graph using NetworkX.
    
    Policies are nodes. Actions, destinations, data types, and zones
    connect through edges. Decisions come from TRAVERSAL, not rule matching.
    
    That's the difference:
    - Rules say: "if action == X and destination == Y then DENY"
    - Graphs say: "traverse from action through relationships to find 
                   the most contextually relevant policy"
    """
    
    def __init__(self):
        self.G = nx.DiGraph()
        self._policy_count = 0
    
    
    def load_from_file(self, path: Path):
        """Load policies from a JSON file."""
        path = Path(path)
        if not path.exists():
            print(f"[MIG Graph] Policy file not found: {path}")
            return
        
        try:
            data = json.loads(path.read_text())
            self.load_from_dict(data)
        except Exception as e:
            print(f"[MIG Graph] Error loading {path}: {e}")
    
    
    def load_from_directory(self, dir_path: Path):
        """Load all JSON policy files from a directory."""
        dir_path = Path(dir_path)
        if not dir_path.exists():
            return
        
        for f in dir_path.glob("*.json"):
            self.load_from_file(f)
    
    
    def load_from_dict(self, data: dict):
        """Build graph from a policy dictionary."""
        pack_name = data.get("name", f"pack_{self._policy_count}")
        pack_node = f"pack:{pack_name}"
        
        # Create policy pack node
        self.G.add_node(pack_node, type="PolicyPack", name=pack_name)
        
        # Create policy nodes
        for policy in data.get("policies", []):
            self._add_policy(policy, pack_node)
        
        # Create zone nodes
        for zone in data.get("zones", []):
            self._add_zone(zone)
    
    
    def _add_policy(self, policy: dict, pack_node: str):
        """Add a single policy to the graph with all relationships."""
        pol_id = policy["id"]
        self._policy_count += 1
        
        # ── Policy node ──
        self.G.add_node(pol_id,
            type="Policy",
            direction=policy.get("direction", "DENY"),
            description=policy.get("description", ""),
            keywords=policy.get("keywords", []),
            enforcement=policy.get("enforcement", "standard"),
            conditions=policy.get("conditions", {}),
            raw=policy
        )
        
        # ── Pack → Policy ──
        self.G.add_edge(pack_node, pol_id, rel="CONTAINS")
        
        # ── Policy → ActionType ──
        if "action_type" in policy:
            action_node = f"action:{policy['action_type']}"
            if not self.G.has_node(action_node):
                self.G.add_node(action_node, type="ActionType", name=policy["action_type"])
            self.G.add_edge(pol_id, action_node, rel="APPLIES_TO")
        
        # ── Policy → Destination ──
        conditions = policy.get("conditions", {})
        if "destination" in conditions:
            dest = conditions["destination"]
            dest_node = f"dest:{dest}"
            if not self.G.has_node(dest_node):
                self.G.add_node(dest_node, type="Destination", name=dest)
            self.G.add_edge(pol_id, dest_node, rel="TARGETS")
        
        # ── Policy → DataType (from keywords) ──
        for kw in policy.get("keywords", []):
            data_node = f"data:{kw}"
            if not self.G.has_node(data_node):
                self.G.add_node(data_node, type="DataType", name=kw)
            self.G.add_edge(pol_id, data_node, rel="PROTECTS")
        
        # ── Policy → Sensitivity level ──
        if "sensitivity" in conditions:
            sens_node = f"sens:{conditions['sensitivity']}"
            if not self.G.has_node(sens_node):
                self.G.add_node(sens_node, type="Sensitivity", level=conditions["sensitivity"])
            self.G.add_edge(pol_id, sens_node, rel="REQUIRES_SENSITIVITY")
    
    
    def _add_zone(self, zone: dict):
        """Add a zone to the graph."""
        zone_id = zone["id"]
        
        self.G.add_node(zone_id,
            type="Zone",
            name=zone.get("name", ""),
            purdue_level=zone.get("purdue_level", ""),
            description=zone.get("description", ""),
            blocked_actions=zone.get("blocked_actions", []),
            allowed_sources=zone.get("allowed_sources", [])
        )
        
        # Connect zone to relevant policies
        for blocked_action in zone.get("blocked_actions", []):
            for pol_id, pol_data in self._get_policies_by_keyword(blocked_action):
                self.G.add_edge(zone_id, pol_id, rel="ENFORCES")
    
    
    def find_policy(self, action_type: str = None, destination: str = None,
                    sensitivity: str = None, semantic_candidates: list = None) -> Optional[dict]:
        """
        Traverse the graph to find the most relevant policy.
        
        Search strategy:
        1. Exact action type match via graph edges
        2. Semantic candidates from ChromaDB
        3. Keyword matching on DataType nodes
        4. Destination-based matching
        
        CRITICAL: Policies with conditions are only matched if
        conditions are satisfied. A DENY policy requiring 
        destination=external does NOT match when destination=internal.
        
        Priority for SAME action: ALLOW with matching conditions wins.
        Priority for DIFFERENT actions: DENY > APPROVAL > ALLOW.
        """
        raw_candidates = []
        
        # ── Strategy 1: Action type edges ──
        if action_type:
            action_node = f"action:{action_type}"
            if self.G.has_node(action_node):
                for pred in self.G.predecessors(action_node):
                    node_data = self.G.nodes[pred]
                    if node_data.get("type") == "Policy":
                        raw_candidates.append({
                            "id": pred,
                            "match_type": "action_type",
                            "score": 1.0,
                            **node_data
                        })
        
        # ── Strategy 2: Semantic candidates from ChromaDB ──
        if semantic_candidates:
            for candidate_id, score in semantic_candidates:
                if self.G.has_node(candidate_id):
                    node_data = self.G.nodes[candidate_id]
                    if node_data.get("type") == "Policy":
                        existing = [c for c in raw_candidates if c["id"] == candidate_id]
                        if not existing:
                            raw_candidates.append({
                                "id": candidate_id,
                                "match_type": "semantic",
                                "score": score,
                                **node_data
                            })
        
        # ── Strategy 3: Destination matching ──
        if destination:
            dest_node = f"dest:{destination}"
            if self.G.has_node(dest_node):
                for pred in self.G.predecessors(dest_node):
                    node_data = self.G.nodes[pred]
                    if node_data.get("type") == "Policy":
                        existing = [c for c in raw_candidates if c["id"] == pred]
                        if not existing:
                            raw_candidates.append({
                                "id": pred,
                                "match_type": "destination",
                                "score": 0.8,
                                **node_data
                            })
        
        # ── Strategy 4: Keyword matching via DataType nodes ──
        if not raw_candidates and action_type:
            for word in action_type.replace("_", " ").split():
                data_node = f"data:{word}"
                if self.G.has_node(data_node):
                    for pred in self.G.predecessors(data_node):
                        node_data = self.G.nodes[pred]
                        if node_data.get("type") == "Policy":
                            existing = [c for c in raw_candidates if c["id"] == pred]
                            if not existing:
                                raw_candidates.append({
                                    "id": pred,
                                    "match_type": "keyword",
                                    "score": 0.5,
                                    **node_data
                                })
        
        if not raw_candidates:
            return None  # No match → fail-closed → DENY
        
        # ═══════════════════════════════════════════════════
        # CRITICAL: Filter by conditions
        # A policy with conditions:{destination:"external"}
        # does NOT match when actual destination is "internal"
        # ═══════════════════════════════════════════════════
        
        context = {
            "destination": destination or "internal",
            "sensitivity": sensitivity or "low",
            "action_type": action_type or "unknown"
        }
        
        candidates = []
        for c in raw_candidates:
            conditions = c.get("conditions", {})
            if not conditions:
                # No conditions — always matches
                candidates.append(c)
            elif self._conditions_match(conditions, context):
                # Has conditions AND they match
                candidates.append(c)
            # else: has conditions that DON'T match — skip this policy
        
        if not candidates:
            # All candidates had unmatched conditions
            # Check if there's an unconditional ALLOW for this action
            unconditional_allow = [c for c in raw_candidates 
                                   if c.get("direction") == "ALLOW" 
                                   and not c.get("conditions", {})]
            if unconditional_allow:
                return max(unconditional_allow, key=lambda c: c.get("score", 0))
            return None  # fail-closed
        
        # ═══════════════════════════════════════════════════
        # Priority: exact action match ALLOW > conditional DENY > APPROVAL
        # ═══════════════════════════════════════════════════
        
        # First: exact action_type ALLOW matches (most specific)
        action_allows = [c for c in candidates 
                        if c.get("direction") == "ALLOW" 
                        and c.get("match_type") == "action_type"]
        if action_allows:
            return max(action_allows, key=lambda c: c.get("score", 0))
        
        # Second: conditional DENY matches (policy conditions met)
        deny_candidates = [c for c in candidates if c.get("direction") == "DENY"]
        if deny_candidates:
            return max(deny_candidates, key=lambda c: c.get("score", 0))
        
        # Third: APPROVAL
        approval_candidates = [c for c in candidates if c.get("direction") == "APPROVAL"]
        if approval_candidates:
            return max(approval_candidates, key=lambda c: c.get("score", 0))
        
        # Fourth: any ALLOW
        allow_candidates = [c for c in candidates if c.get("direction") == "ALLOW"]
        if allow_candidates:
            return max(allow_candidates, key=lambda c: c.get("score", 0))
        
        return candidates[0]
    
    
    def _conditions_match(self, conditions: dict, context: dict) -> bool:
        """
        Check if a policy's conditions match the current context.
        
        A policy with conditions:{destination:"external"} only matches
        when the actual destination IS external.
        """
        for key, required_value in conditions.items():
            actual_value = context.get(key)
            if actual_value is None:
                continue  # No context for this condition — skip
            if actual_value != required_value:
                return False  # Condition not met — policy doesn't apply
        return True
    
    
    def check_zone(self, zone_id: str, action_type: str) -> Optional[dict]:
        """Check if an action is blocked in a specific zone."""
        if not self.G.has_node(zone_id):
            return None
        
        zone_data = self.G.nodes[zone_id]
        blocked = zone_data.get("blocked_actions", [])
        
        if action_type in blocked or any(b in action_type for b in blocked):
            return {
                "blocked": True,
                "zone": zone_data.get("name", zone_id),
                "reason": f"Action '{action_type}' is blocked in zone '{zone_data.get('name', zone_id)}'"
            }
        
        return {"blocked": False, "zone": zone_data.get("name", zone_id)}
    
    
    def get_all_policies(self) -> List[dict]:
        """Return all policy nodes for ChromaDB indexing."""
        policies = []
        for node_id, data in self.G.nodes(data=True):
            if data.get("type") == "Policy":
                policies.append({
                    "id": node_id,
                    "direction": data.get("direction", "DENY"),
                    "description": data.get("description", ""),
                    "keywords": data.get("keywords", []),
                    "enforcement": data.get("enforcement", "standard")
                })
        return policies
    
    
    def get_graph_stats(self) -> dict:
        """Return graph statistics."""
        type_counts = {}
        for _, data in self.G.nodes(data=True):
            node_type = data.get("type", "unknown")
            type_counts[node_type] = type_counts.get(node_type, 0) + 1
        
        return {
            "total_nodes": self.G.number_of_nodes(),
            "total_edges": self.G.number_of_edges(),
            "node_types": type_counts,
            "policy_count": type_counts.get("Policy", 0)
        }
    
    
    def visualize_text(self) -> str:
        """Return text visualization of the graph."""
        lines = []
        lines.append(f"MIG Policy Graph: {self.G.number_of_nodes()} nodes, "
                     f"{self.G.number_of_edges()} edges")
        lines.append("")
        
        for node_id, data in sorted(self.G.nodes(data=True), 
                                      key=lambda x: x[1].get("type", "")):
            node_type = data.get("type", "?")
            direction = f" [{data['direction']}]" if "direction" in data else ""
            lines.append(f"  ({node_type}) {node_id}{direction}")
            
            for _, target, edge_data in self.G.edges(node_id, data=True):
                rel = edge_data.get("rel", "?")
                lines.append(f"    --[{rel}]--> {target}")
        
        return "\n".join(lines)
    
    
    def _get_policies_by_keyword(self, keyword: str) -> List[Tuple[str, dict]]:
        """Find policies containing a specific keyword."""
        matches = []
        for node_id, data in self.G.nodes(data=True):
            if data.get("type") == "Policy":
                if keyword in data.get("keywords", []):
                    matches.append((node_id, data))
        return matches