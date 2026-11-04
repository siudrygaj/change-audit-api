# Change Auditor API

Azure Functions REST API (Python) that stores IT change tickets and audits each one
against ITGC change-management controls. Built for my CS-432 Cloud Computing midterm.

## What it does
- CRUD on change tickets (in-memory)
- API key auth with the `X-API-Key` header
- Audits every ticket with 4 rules: SOD_VIOLATION, SELF_APPROVAL, UNAUTHORIZED, UNTESTED
- Returns Compliant/Exception, a risk rating, and a reason for each problem

## Endpoints (all under /api)
| Method | Route | What it does |
|---|---|---|
| POST | /changes | Create + audit a ticket |
| GET | /changes | Get all (optional `?result=Exception`) |
| GET | /changes/{id} | Get one |
| PUT | /changes/{id} | Update + re-audit |
| DELETE | /changes/{id} | Delete one |
| DELETE | /changes | Delete all (purge) |
| GET | /counts | Summary counts |

## Run it locally
1. `python3.12 -m venv .venv && source .venv/bin/activate`
2. `pip install -r requirements.txt`
3. Copy `local.settings.example.json` to `local.settings.json` and set your own `API_KEY`
4. `func start`

## Tests
Open the `bruno/` folder in Bruno, pick the `local` or `azure` environment, set `apiKey`, and run the collection (18 tests).
