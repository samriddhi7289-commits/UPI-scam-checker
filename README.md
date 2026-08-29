# UPI Scam Pattern Checker

A rule-based tool that scores the scam risk of a message, UPI ID, or link — built from real, current (2026) UPI fraud patterns reported by RBI, NPCI, and I4C.

## Why this exists

UPI fraud in India crossed ₹1,750 crore in FY 2025-26, a 31% rise over the previous year. Most existing "UPI scam checker" projects/tutorials online are built around the old fake collect-request scam — but NPCI discontinued P2P collect requests in October 2025, so that vector is now mostly irrelevant. This tool is built around what's actually happening now: screen-sharing app scams, fake KYC/verification links, QR tampering, micro-transaction fraud, and lookalike bank domains.

## Why rule-based, not AI/ML

Every flag this tool raises comes from an explicit, readable rule in `rule_engine.py` — not a model's black-box output. That means:
- Every result is explainable ("flagged because X")
- It's auditable and extendable — add a new scam pattern, add a new rule
- It doesn't need training data or an API key to run

This was a deliberate choice, not a limitation — for a fraud-awareness tool, transparency matters more than raw accuracy from a model no one can inspect.

## How scoring works

Each input type (message text, UPI ID, or URL) is checked against a category-specific checklist. Matches add weighted points (5–40 depending on severity), the total is capped at 100, and mapped to a risk band:

- 0 → SAFE
- 1–19 → LOW
- 20–49 → MEDIUM
- 50+ → HIGH

Weights are currently based on how severe/definitive each signal is (e.g. "asks for OTP" = 35, since no legitimate reason ever requires this). These are a starting point — worth refining against real reported cases if you extend this project.

## What's included

**Backend (`backend/`)**
- `rule_engine.py` — stateless scoring logic, including English + Hinglish scam phrase lists
- `db.py` — SQLite persistence layer, tracks VPA check history for pattern correlation (kept separate from rule_engine on purpose — rules stay pure/stateless, state lives here)
- `app.py` — Flask API with 5 endpoints:
  - `POST /api/check` — single message/UPI ID/link check (VPA checks also accept an optional `amount` field)
  - `POST /api/check-batch` — check up to 50 lines at once (`{ input_type, values: [...] }`)
  - `POST /api/check-qr` — upload a QR code image, auto-decodes the UPI VPA (and amount, if present) and runs it through the same rule checks
  - `POST /api/feedback` — logs whether a result was accurate to `feedback_log.jsonl`
  - `GET /api/stats` — reads the feedback log and returns overall + per-risk-level accuracy
  - `GET /api/health` — health check
- `test_rule_engine.py` — pytest suite (30 tests) covering every rule category, batch handling, QR parsing, and risk-level boundaries. Run with `pytest test_rule_engine.py -v`.
- `Dockerfile` / `Procfile` — deployment configs (see `DEPLOY.md` in the project root)

**Frontend (`frontend/`)**
- `index.html` — the current full-featured version: 4 input tabs (Message/UPI ID/Link/QR Code), batch mode, example chips, animated risk gauge, copy-report, feedback buttons, session scan history, amount field for pattern detection
- `versions/` — earlier design iterations kept for reference

## Repeated micro-transaction pattern detection

A known real fraud tactic ("salami slicing") sends several small payments to the same account to stay under bank fraud-alert thresholds. This tool now tracks VPA check history (locally, in `scan_history.db`) and flags it: if the same UPI ID shows up 3+ times with amounts under ₹10 within a 30-day window, an extra finding is added and the risk score bumped accordingly — on top of whatever the base rule checks already found.

This only works if you supply an amount when checking a VPA (there's an optional amount field in the UI), or when scanning a QR code that embeds one (`am=` in the UPI URI).

## Setup

```bash
# Backend
cd backend
pip install -r requirements.txt
python app.py
# runs on http://localhost:5000

# Frontend
# Open frontend/index.html in a browser (backend must be running first)
```

**Note on QR decoding:** `pyzbar` wraps a native `zbar` library. On Windows the pip wheel bundles the required DLL, so `pip install -r requirements.txt` should be enough. On Linux, if you hit an import error, install the system library first: `sudo apt install libzbar0`. The included `Dockerfile` handles this automatically for deployment.

## Deploying a live version

See `DEPLOY.md` for a full walkthrough of getting this onto a real URL (Render for the backend, Netlify for the frontend) — worth doing before putting this on your resume, since a clickable live link is more convincing than "clone and run locally."


## What's next / known limitations

- Deepfake voice phishing is a growing 2026 threat with no text-based signal to catch
- VPA suspicion rules are heuristic-only; a real version would ideally cross-check against a reported-scammer database
- Domain lookalike detection uses basic Levenshtein distance — could be extended with a larger reference list of Indian bank/fintech domains
- Feedback is logged locally but not yet used to auto-tune rule weights — that would be a natural v2 direction
- **Deliberately not built (scope decision, not oversight):** a browser extension wrapper and a crowdsourced scam-report database were considered but left out — both are substantial standalone builds that would have diluted focus on getting the core tool solid within the timeline. Worth a dedicated follow-up project.
- The micro-transaction correlation currently only tracks amount + VPA, not sender identity — a more complete version would need users to be authenticated, which is a meaningfully bigger scope (auth, accounts) than this project set out to cover.

## Sources referenced for scam patterns

- RBI Master Direction on Fraud Risk Management (Jan 2024) and Digital Payment Fraud circular (Mar 2025)
- NPCI advisories (2025-2026) on QR tampering, screen-sharing scams, P2P collect request discontinuation
- I4C Q2 2026 advisory on fake customer care pages
- National Cyber Crime Helpline (1930) / cybercrime.gov.in reporting guidance
