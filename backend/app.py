import io
import json
import os
import time

from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
from pyzbar.pyzbar import decode as decode_qr

from rule_engine import analyze_input, analyze_batch, extract_upi_id_from_qr_string, get_risk_level
import db

db.init_db()

app = Flask(__name__)
# In production, set FRONTEND_ORIGIN to your deployed frontend URL instead of "*"
CORS(app, origins=os.environ.get("FRONTEND_ORIGIN", "*"))

FEEDBACK_LOG = os.path.join(os.path.dirname(__file__), "feedback_log.jsonl")


def _extract_amount_from_text(text: str):
    """Best-effort amount extraction from free text, e.g. 'Rs 5' or '₹200'."""
    import re
    match = re.search(r"(?:rs\.?|₹|inr)\s?(\d+(?:\.\d+)?)", text.lower())
    return float(match.group(1)) if match else None


def _apply_vpa_correlation(result: dict, vpa: str, amount):
    """
    Logs this VPA check, then checks whether it fits a repeated
    micro-transaction pattern. If so, layers an extra finding onto the
    existing rule-based result and bumps the score accordingly.
    """
    db.log_vpa_check(vpa, amount, result["risk_level"], result["score"])

    count, total = db.get_micro_transaction_pattern(vpa)
    if count > 0:
        bonus = 20
        new_score = min(result["score"] + bonus, 100)
        result["findings"].append({
            "reason": f"This UPI ID has received {count} separate small payments (under ₹10, totaling ₹{total:.0f}) recently — a known 'salami slicing' pattern used to stay under fraud-alert thresholds",
            "weight": bonus,
            "category": "repeated_micro_pattern"
        })
        result["score"] = new_score
        result["risk_level"] = get_risk_level(new_score)
        result["correlation_flag"] = True
    else:
        result["correlation_flag"] = False

    return result


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(force=True)
    input_type = data.get("input_type")  # 'text' | 'vpa' | 'url'
    value = data.get("value", "").strip()
    amount = data.get("amount")  # optional, only meaningful for 'vpa'

    if not value:
        return jsonify({"error": "value is required"}), 400
    if input_type not in ("text", "vpa", "url"):
        return jsonify({"error": "input_type must be 'text', 'vpa', or 'url'"}), 400

    result = analyze_input(input_type, value)

    if input_type == "vpa":
        if amount is None:
            amount = _extract_amount_from_text(value) or None
        result = _apply_vpa_correlation(result, value, amount)

    return jsonify(result)


@app.route("/api/check-batch", methods=["POST"])
def check_batch():
    """Body: { input_type: 'text'|'vpa'|'url', values: ['line1', 'line2', ...] }"""
    data = request.get_json(force=True)
    input_type = data.get("input_type")
    values = data.get("values", [])

    if input_type not in ("text", "vpa", "url"):
        return jsonify({"error": "input_type must be 'text', 'vpa', or 'url'"}), 400
    if not isinstance(values, list) or not values:
        return jsonify({"error": "values must be a non-empty list"}), 400
    if len(values) > 50:
        return jsonify({"error": "max 50 items per batch"}), 400

    results = analyze_batch(input_type, values)
    return jsonify({"count": len(results), "results": results})


@app.route("/api/check-qr", methods=["POST"])
def check_qr():
    """Accepts a multipart form upload under field name 'image'.
    Decodes any UPI QR code found, extracts the VPA, and runs it
    through the same VPA rule checks."""
    if "image" not in request.files:
        return jsonify({"error": "no image uploaded (field name must be 'image')"}), 400

    file = request.files["image"]
    try:
        img = Image.open(io.BytesIO(file.read()))
    except Exception:
        return jsonify({"error": "could not read image file"}), 400

    decoded = decode_qr(img)
    if not decoded:
        return jsonify({"error": "no QR code detected in this image"}), 422

    qr_text = decoded[0].data.decode("utf-8", errors="ignore")
    vpa = extract_upi_id_from_qr_string(qr_text)

    if not vpa:
        return jsonify({
            "error": "QR code decoded but does not look like a UPI payment code",
            "raw_decoded_text": qr_text
        }), 422

    import re
    amount_match = re.search(r"[?&]am=([\d.]+)", qr_text)
    amount = float(amount_match.group(1)) if amount_match else None

    result = analyze_input("vpa", vpa)
    result = _apply_vpa_correlation(result, vpa, amount)
    result["decoded_from_qr"] = True
    result["raw_qr_text"] = qr_text
    return jsonify(result)


@app.route("/api/feedback", methods=["POST"])
def feedback():
    """Body: { input_type, value, risk_level, score, was_correct: bool, note?: str }
    Appends to a local JSONL log — not acted on live, just recorded for later review."""
    data = request.get_json(force=True)
    required = ("input_type", "value", "risk_level", "score", "was_correct")
    if not all(k in data for k in required):
        return jsonify({"error": f"body must include {required}"}), 400

    entry = {k: data[k] for k in required}
    entry["note"] = data.get("note", "")
    entry["timestamp"] = time.time()

    with open(FEEDBACK_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

    return jsonify({"status": "logged"})


@app.route("/api/stats", methods=["GET"])
def stats():
    """Reads feedback_log.jsonl and returns basic accuracy stats.
    Nothing fancy — just makes the logged feedback visible instead of
    sitting unused in a file."""
    if not os.path.exists(FEEDBACK_LOG):
        return jsonify({
            "total_feedback": 0,
            "accuracy_pct": None,
            "by_risk_level": {},
            "message": "No feedback logged yet."
        })

    entries = []
    with open(FEEDBACK_LOG, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    total = len(entries)
    if total == 0:
        return jsonify({
            "total_feedback": 0,
            "accuracy_pct": None,
            "by_risk_level": {},
            "message": "No feedback logged yet."
        })

    correct = sum(1 for e in entries if e.get("was_correct"))
    accuracy_pct = round((correct / total) * 100, 1)

    by_level = {}
    for e in entries:
        level = e.get("risk_level", "UNKNOWN")
        by_level.setdefault(level, {"total": 0, "correct": 0})
        by_level[level]["total"] += 1
        if e.get("was_correct"):
            by_level[level]["correct"] += 1

    for level, counts in by_level.items():
        counts["accuracy_pct"] = round((counts["correct"] / counts["total"]) * 100, 1)

    return jsonify({
        "total_feedback": total,
        "accuracy_pct": accuracy_pct,
        "by_risk_level": by_level
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
