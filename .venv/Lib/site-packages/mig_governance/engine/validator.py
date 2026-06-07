"""
MIG Governance — Validation Pipeline
House of Galatine © 2026

8-step validation: PII → Action → Payload → Graph → Risk → Override → Decision → Audit
PII detection, action classification, payload analysis ported from mig_core.py
"""

import re
from typing import Dict, List, Optional


class ValidationPipeline:
    """
    The validation engine. Runs content-level checks on every action.
    This is what AGT doesn't do — actual content inspection.
    """
    
    # ═══════════════════════════════════════════════════════
    # PII DETECTION
    # ═══════════════════════════════════════════════════════
    
    PII_PATTERNS = [
        (r'[\w.+-]+@[\w-]+\.[\w.]+', 'email_address'),
        (r'\b\d{3}-\d{2}-\d{4}\b', 'ssn'),
        (r'\b\d{4}\s?\d{4}\s?\d{4}\b', 'card_number'),
        (r'\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b', 'card_number_16'),
        (r'\b\d{12}\b', 'aadhaar'),
        (r'\b\d{3}-\d{3}-\d{4}\b', 'phone_number'),
        (r'\b\d{10}\b', 'phone_or_id'),
        (r'\b[A-Z]{2}\d{6,8}\b', 'passport_number'),
    ]
    
    PII_KEYWORDS = [
        "personal data", "salary", "ssn", "social security", 
        "passport", "bank account", "credit card", "debit card",
        "medical", "health record", "compensation", "date of birth",
        "home address", "phone number", "driver license",
        "aadhaar", "pan card", "tax id", "national insurance",
        "patient", "diagnosis", "prescription"
    ]
    
    def detect_pii(self, text: str) -> Dict:
        """
        Scan text for PII patterns and keywords.
        Returns dict with 'found' (bool) and 'types' (list).
        """
        lower = text.lower()
        found_types = []
        
        # Pattern matching
        for pattern, pii_type in self.PII_PATTERNS:
            if re.search(pattern, text):
                found_types.append(pii_type)
        
        # Keyword matching
        for keyword in self.PII_KEYWORDS:
            if keyword in lower:
                found_types.append(f"keyword:{keyword}")
        
        return {
            "found": len(found_types) > 0,
            "types": list(set(found_types)),
            "count": len(set(found_types))
        }
    
    
    # ═══════════════════════════════════════════════════════
    # ACTION CLASSIFICATION
    # ═══════════════════════════════════════════════════════
    
    ACTION_PATTERNS = {
        "read_data": [
            r'read', r'get', r'fetch', r'retrieve', r'query', r'view',
            r'check', r'monitor', r'status', r'list', r'show', r'display'
        ],
        "send_email": [
            r'send\s+email', r'email\s+to', r'send\s+mail', r'compose\s+email',
            r'send\s+message', r'notify\s+via\s+email'
        ],
        "send_message": [
            r'send\s+message', r'post\s+to\s+slack', r'send\s+notification',
            r'chat', r'message\s+to'
        ],
        "export_data": [
            r'export', r'download', r'extract\s+to', r'dump',
            r'backup\s+to', r'transfer\s+to', r'send\s+out'
        ],
        "process_payment": [
            r'pay', r'payment', r'transfer\s+fund', r'wire', r'invoice',
            r'process\s+payment', r'send\s+money', r'disburse'
        ],
        "modify_record": [
            r'update', r'modify', r'change', r'edit', r'alter',
            r'delete', r'remove', r'drop'
        ],
        "share_document": [
            r'share', r'attach', r'upload', r'publish', r'distribute',
            r'forward', r'send\s+file', r'send\s+document', r'send\s+report'
        ],
        "access_database": [
            r'database', r'sql', r'query\s+db', r'select\s+from',
            r'insert\s+into', r'drop\s+table', r'truncate'
        ],
        "execute_command": [
            r'execute', r'run', r'launch', r'start', r'invoke',
            r'deploy', r'install'
        ],
        # OT-specific
        "write_setpoint": [
            r'set\s+.*(?:speed|pressure|temperature|flow|level|rpm|kpa)',
            r'write\s+.*register', r'change\s+.*setpoint', r'adjust'
        ],
        "read_sensor": [
            r'read\s+.*sensor', r'sensor\s+value', r'current\s+.*speed',
            r'measure', r'monitor\s+.*(?:pump|valve|pressure|temperature)'
        ],
        "write_safety": [
            r'safety', r'sis', r'emergency', r'shutdown', r'interlock', r'trip'
        ],
        "firmware_update": [
            r'firmware', r'flash', r'upload\s+program', r'deploy\s+code'
        ],
    }
    
    def classify_action(self, text: str) -> str:
        """
        Classify the action type from text.
        Returns action type string.
        """
        lower = text.lower()
        
        # Check patterns in priority order (most specific first)
        priority_order = [
            "write_safety", "firmware_update", "write_setpoint", "read_sensor",
            "send_email", "process_payment", "export_data", "share_document",
            "access_database", "execute_command", "modify_record",
            "send_message", "read_data"
        ]
        
        for action_type in priority_order:
            patterns = self.ACTION_PATTERNS.get(action_type, [])
            for pattern in patterns:
                if re.search(pattern, lower):
                    return action_type
        
        return "unknown"
    
    
    # ═══════════════════════════════════════════════════════
    # PAYLOAD ANALYSIS
    # ═══════════════════════════════════════════════════════
    
    SENSITIVITY_KEYWORDS = {
        "critical": [
            "password", "secret", "api_key", "private_key", "credentials",
            "access_token", "auth", "safety", "sis", "emergency",
            "classified", "top_secret", "confidential"
        ],
        "high": [
            "financial", "revenue", "salary", "payment", "invoice",
            "contract", "legal", "medical", "health", "patient",
            "ssn", "credit_card", "bank", "tax"
        ],
        "medium": [
            "internal", "employee", "customer", "project", "strategy",
            "roadmap", "performance", "review", "budget"
        ],
        "low": [
            "public", "blog", "marketing", "general", "info",
            "newsletter", "announcement"
        ]
    }
    
    DESTINATION_KEYWORDS = {
        "external": [
            "external", "outside", "send externally",
            "@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com",
            "third party", "external vendor", "external contractor",
            "offsite", "send outside", "share externally",
            "forward externally", "export outside"
        ],
        "internal": [
            "internal", "team", "company", "org", "department",
            "colleague", "manager", "supervisor", "report",
            "read", "view", "check", "review", "summary",
            "current", "status", "monitor"
        ],
        "safety": [
            "safety", "sis", "emergency", "shutdown", "interlock"
        ],
        "control": [
            "plc", "controller", "register", "actuator", "scada"
        ]
    }
    
    def analyze_payload(self, text: str) -> Dict:
        """
        Analyze payload content for sensitivity and destination.
        Returns dict with 'sensitivity' and 'destination'.
        """
        lower = text.lower()
        
        # Determine sensitivity
        sensitivity = "low"
        for level in ["critical", "high", "medium"]:
            keywords = self.SENSITIVITY_KEYWORDS[level]
            if any(kw in lower for kw in keywords):
                sensitivity = level
                break
        
        # Determine destination — default is INTERNAL
        # Only flag as external if EXPLICIT external indicators present
        destination = "internal"
        
        # Check for explicit external signals first
        external_keywords = self.DESTINATION_KEYWORDS["external"]
        if any(kw in lower for kw in external_keywords):
            destination = "external"
        
        # Check for safety/control destinations (OT)
        elif any(kw in lower for kw in self.DESTINATION_KEYWORDS.get("safety", [])):
            destination = "safety"
        elif any(kw in lower for kw in self.DESTINATION_KEYWORDS.get("control", [])):
            destination = "control"
        
        return {
            "sensitivity": sensitivity,
            "destination": destination
        }