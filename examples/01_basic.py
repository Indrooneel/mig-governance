"""
MIG Governance — Basic Usage Example
pip install mig-governance

This example shows:
1. Simple validation
2. Decorator-based governance
3. Multiple scenarios
"""

from mig_governance import Governor, ActionDenied, ActionNeedsApproval

# Initialize — loads default policies automatically
gov = Governor(verbose=True)

print("=" * 60)
print("MIG Governance SDK — Basic Demo")
print("=" * 60)

# ── Example 1: Simple validation ──
print("\n--- Example 1: Direct validation ---\n")

# Safe action
result = gov.validate("Read the current sales report")
print(f"Action: Read sales report")
print(f"Result: {result}\n")

# Dangerous action
result = gov.validate("Send salary data to external@gmail.com")
print(f"Action: Send salary data externally")
print(f"Result: {result}\n")

# Needs approval
result = gov.validate("Process payment of $50,000 to vendor")
print(f"Action: Process payment")
print(f"Result: {result}\n")


# ── Example 2: Decorator-based governance ──
print("\n--- Example 2: Decorator governance ---\n")

@gov.guard
def send_email(to: str, subject: str, body: str):
    """Send an email — MIG validates before execution."""
    print(f"  ✅ Email sent to {to}: {subject}")
    return {"status": "sent", "to": to}

@gov.guard
def read_database(query: str):
    """Read from database — MIG validates the query."""
    print(f"  ✅ Query executed: {query}")
    return {"status": "success", "rows": 42}

# Safe: internal email
try:
    result = send_email("team@company.com", "Meeting", "Team sync at 3pm")
    print(f"  Result: {result}")
except ActionDenied as e:
    print(f"  ❌ Blocked: {e}")
except ActionNeedsApproval as e:
    print(f"  ⏸️  Needs approval: {e}")

print()

# Dangerous: external email with PII
try:
    result = send_email("hacker@external.com", "Data", "SSN: 123-45-6789 salary: $150,000")
    print(f"  Result: {result}")
except ActionDenied as e:
    print(f"  ❌ Blocked: {e}")
except ActionNeedsApproval as e:
    print(f"  ⏸️  Needs approval: {e}")

print()

# Safe: database read
try:
    result = read_database("SELECT name FROM employees")
    print(f"  Result: {result}")
except ActionDenied as e:
    print(f"  ❌ Blocked: {e}")

print()

# Dangerous: database delete
try:
    result = read_database("DROP TABLE employees")
    print(f"  Result: {result}")
except ActionDenied as e:
    print(f"  ❌ Blocked: {e}")


# ── Example 3: Audit trail ──
print("\n--- Example 3: Audit trail ---\n")

stats = gov.get_stats()
print(f"Total decisions: {stats['total']}")
print(f"Allowed: {stats['allowed']}")
print(f"Denied: {stats['denied']}")
print(f"Approval required: {stats['approval']}")

print("\n" + "=" * 60)
print("MIG Governance — Nothing executes without approval.")
print("House of Galatine | houseofgalatine.com")
print("=" * 60)