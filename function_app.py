# function_app.py is the Change Auditor API (Azure Functions, Python v2 programming model).
# It stores IT change tickets in memory, and audits each one with rules.py, and it will only accept requests that are given with a valid API key in the X-API-KEY header.

import hmac          # constant-time comparison for the API key
import json          # turn Python dicts into JSON text
import os            # read settings (API_KEY) from the environment
import uuid          # generating unique ids for new tickets
from datetime import date, datetime, timezone

import azure.functions as func

from rules import RULES, audit_change

# like from class the ANONYMOUS feature will turn off Azure's built-in function keys. This is because we check our own API key below.
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# The in-memory repository: a dictionary of { id: ticket }.
# It will live in the apps memory, so it will wipe whenever the app restarts. But that's ok because it was expected during the midterm (Note: for final, this is where I should expand on a DB).

changes = {}

# Every field a client must send when creating or updating a ticket
REQUIRED_FIELDS = ["ticketId", "system", "description", "approvedBy",
                   "developedBy", "deployedBy", "approvalDate", "deployDate", "tested"]


# HELPERS

def json_response(body, status=200):
    """Send back a JSON response with the given HTTP status code."""
    return func.HttpResponse(json.dumps(body, indent=2), status_code=status,
                             mimetype="application/json")


def error(status, message, details=None):
    """Send back an error in one consistent format: {"error": ..., "details": [...]}."""
    body = {"error": message}
    if details:
        body["details"] = details
    return json_response(body, status)


def is_authorized(req):
    """API key check: True only if the X-API-Key header matches the API_KEY setting."""
    expected = os.environ.get("API_KEY", "")      # from local.settings.json and/or Azure App Settings
    provided = req.headers.get("X-API-Key", "")   # from the request header
    # compare_digest takes the same time no matter where the keys differ, so an attacker can just guess the key by timing a response.
    return bool(expected) and hmac.compare_digest(provided.encode(), expected.encode())


def is_valid_date(value):
    """True if value is a date in YYYY-MM-DD format."""
    try:
        date.fromisoformat(value)
        return True
    except (TypeError, ValueError):
        return False


def validate(data):
    """Check the ticket and return a list of problems (empty list = valid)."""
    # Step 1: Every required field needs to be present
    problems = [f"{field} is required" for field in REQUIRED_FIELDS if field not in data]
    if problems:
        return problems
    # Step 2: text fields must be real, non-empty text
    for field in ["ticketId", "system", "description", "approvedBy", "developedBy", "deployedBy"]:
        if not isinstance(data[field], str) or not data[field].strip():
            problems.append(f"{field} must be a non-empty text value")
    # Step 3: ticket ids following the CHG- formatting
    if not str(data["ticketId"]).startswith("CHG-"):
        problems.append("ticketId must start with CHG- (example: CHG-10001)")
    # Step 4: the dates must be real dates
    for field in ["approvalDate", "deployDate"]:
        if not is_valid_date(data[field]):
            problems.append(f"{field} must be a date in YYYY-MM-DD format")
    # Step 5: The tested must be either true or false
    if not isinstance(data["tested"], bool):
        problems.append("tested must be true or false")
    return problems


def read_ticket(req):
    """Read the JSON body, validate it, and audit it. Returns (ticket, error_response)."""
    try:
        data = req.get_json()
    except ValueError:
        return None, error(400, "Request body must be valid JSON")
    if not isinstance(data, dict):
        return None, error(400, "Request body must be a JSON object")

    problems = validate(data)
    if problems:
        return None, error(400, "Validation failed", problems)

    # Will copy ONLY the expected fields, so a client for example can't sneak in "controlResult": "Compliant"
    ticket = {field: data[field] for field in REQUIRED_FIELDS}
    # Running the audit rules to store the results from the ticket
    ticket["controlResult"], ticket["riskRating"], ticket["exceptions"] = audit_change(ticket)
    return ticket, None


def find_by_ticket_id(ticket_id):
    """Return the stored ticket with this ticketId (e.g. CHG-10001), or None. Used for 409."""
    for t in changes.values():
        if t["ticketId"].lower() == ticket_id.lower():
            return t
    return None


def now():
    """Current time in UTC, e.g. 2026-11-03T21:45:00+00:00."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# CRUD ENDPOINTS
# Every endpoint follows the same 4 steps:
# Step 1: Check the API key - 401
# Step 2: Reading / Validating - 400
# Step 3: Using the repo - 404 / 409
# Step 4: Returning JSON - 200 / 201 


# CREATE: POST /api/changes
@app.route(route="changes", methods=["POST"])
def create_change(req: func.HttpRequest) -> func.HttpResponse:
    if not is_authorized(req):
        return error(401, "Missing or invalid API key")

    ticket, problem = read_ticket(req)
    if problem:
        return problem

    if find_by_ticket_id(ticket["ticketId"]):
        return error(409, f"Ticket {ticket['ticketId']} already exists")

    # The SERVER creates the unique id (uuid4), the client never sends one
    ticket = {"id": str(uuid.uuid4()), **ticket, "createdAt": now(), "updatedAt": now()}
    changes[ticket["id"]] = ticket          # add it to the in-memory repository
    return json_response(ticket, 201)       # 201 Created


# READ ALL: GET /api/changes   (optional filter for the tickets - ?result=Exception)
@app.route(route="changes", methods=["GET"])
def get_changes(req: func.HttpRequest) -> func.HttpResponse:
    if not is_authorized(req):
        return error(401, "Missing or invalid API key")

    results = list(changes.values())
    result_filter = req.params.get("result")
    if result_filter:
        results = [t for t in results if t["controlResult"].lower() == result_filter.lower()]
    return json_response(results)


# READ ONE: GET /api/changes/{id}
@app.route(route="changes/{id}", methods=["GET"])
def get_change(req: func.HttpRequest) -> func.HttpResponse:
    if not is_authorized(req):
        return error(401, "Missing or invalid API key")

    ticket = changes.get(req.route_params.get("id"))   # {id} coming from the URL
    if not ticket:
        return error(404, "Change ticket not found")
    return json_response(ticket)


# UPDATE: PUT /api/changes/{id}   (replacing the ticket and RE-RUNS the audit)
@app.route(route="changes/{id}", methods=["PUT"])
def update_change(req: func.HttpRequest) -> func.HttpResponse:
    if not is_authorized(req):
        return error(401, "Missing or invalid API key")

    change_id = req.route_params.get("id")
    existing = changes.get(change_id)
    if not existing:
        return error(404, "Change ticket not found")

    ticket, problem = read_ticket(req)   # validating and re-auditing the new version
    if problem:
        return problem

    duplicate = find_by_ticket_id(ticket["ticketId"])
    if duplicate and duplicate["id"] != change_id:
        return error(409, f"Ticket {ticket['ticketId']} already exists")

    # keeping the same id and createdAt, refreshing updatedAt
    ticket = {"id": change_id, **ticket, "createdAt": existing["createdAt"], "updatedAt": now()}
    changes[change_id] = ticket
    return json_response(ticket)


# DELETE: DELETE /api/changes/{id}
@app.route(route="changes/{id}", methods=["DELETE"])
def delete_change(req: func.HttpRequest) -> func.HttpResponse:
    if not is_authorized(req):
        return error(401, "Missing or invalid API key")

    ticket = changes.pop(req.route_params.get("id"), None)   # remove it from the repository
    if not ticket:
        return error(404, "Change ticket not found")
    return json_response({"message": "Change ticket deleted", "deleted": ticket})


# OPTIONAL EXTRA ENDPOINTS

# PURGE: DELETE /api/changes   (removing every ticket - Bruno will run this first for a clean start)
@app.route(route="changes", methods=["DELETE"])
def purge_changes(req: func.HttpRequest) -> func.HttpResponse:
    if not is_authorized(req):
        return error(401, "Missing or invalid API key")

    count = len(changes)
    changes.clear()
    return json_response({"message": "All change tickets deleted", "deletedCount": count})


# COUNTS: GET /api/counts   (summary for auditors)
# Not /changes/counts, because "counts" would clash with /changes/{id}
@app.route(route="counts", methods=["GET"])
def get_counts(req: func.HttpRequest) -> func.HttpResponse:
    if not is_authorized(req):
        return error(401, "Missing or invalid API key")

    tickets = list(changes.values())
    by_exception = {code: 0 for code in RULES}       # starting every rule at 0
    by_risk = {"High": 0, "Medium": 0, "Low": 0}
    for t in tickets:
        by_risk[t["riskRating"]] += 1
        for e in t["exceptions"]:
            by_exception[e["code"]] += 1

    return json_response({
        "total": len(tickets),
        "compliant": sum(1 for t in tickets if t["controlResult"] == "Compliant"),
        "exception": sum(1 for t in tickets if t["controlResult"] == "Exception"),
        "byRisk": by_risk,
        "byException": by_exception,
    })