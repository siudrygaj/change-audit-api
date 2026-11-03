# rules.py being the audit part of the project.
# It will be testing each change ticket against ITGC for change management, this being the same type of checks that an IT auditor would do, that being one of my inspirations for this project.
from datetime import date



# The lookup table of every rule: input code -> gives the severity, plain-text english. 
RULES = {
    "SOD_VIOLATION": ("High", "The same person has developed and deployed the change."),
    "SELF_APPROVAL": ("High", "The developer has approved their own change."),
    "UNAUTHORIZED": ("High", "The change was deployed before it was approved."),
    "UNTESTED": ("Medium", "There is no current evidence that the change was tested."),
}


def audit_change(ticket):
    """Run every rule on one ticket. Returns (control_result, risk_rating, exceptions)."""
    found = []  # codes of the rules that this ticket fails
    developer = ticket["developedBy"].lower()  # lower() so "JAKOB" == "jakob"

    # Rule 1: Having Segregation of duties, the developer should not deploy their own change
    if developer == ticket["deployedBy"].lower():
        found.append("SOD_VIOLATION")

    # Rule 2: Self-approving tickets, the developer should not be able to approve their own change
    if developer == ticket["approvedBy"].lower():
        found.append("SELF_APPROVAL")

    # Rule 3: Having correct Authorization, the change in the ticket must be approved BEFORE it is deployed out
        # fromisoformat will turns "2026-11-2" for example into a date format that Python can compare
    if date.fromisoformat(ticket["deployDate"]) < date.fromisoformat(ticket["approvalDate"]):
        found.append("UNAUTHORIZED")

    # Rule 4: There must be evidence that the change was tested before deployment
    if not ticket["tested"]:
        found.append("UNTESTED")

    # Turns each code into a full answer with a severity and reason
    exceptions = [{"code": code, "severity": RULES[code][0], "reason": RULES[code][1]}
                  for code in found]

    # Overall Risk being the worst the severity found (if no exception then would return Low)
    severities = [e["severity"] for e in exceptions]
    if "High" in severities:
        risk_rating = "High"
    elif "Medium" in severities:
        risk_rating = "Medium"
    else:
        risk_rating = "Low"

    # Having any exception at all will mean that the ticket failed the control test
    control_result = "Exception" if exceptions else "Compliant"
    return control_result, risk_rating, exceptions