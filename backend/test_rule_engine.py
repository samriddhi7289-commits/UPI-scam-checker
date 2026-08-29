"""
Test suite for rule_engine.py

Run with: pytest test_rule_engine.py -v
"""

import pytest
from rule_engine import (
    analyze_text, analyze_vpa, analyze_url, analyze_input, analyze_batch,
    get_risk_level, extract_upi_id_from_qr_string
)


class TestTextAnalysis:
    def test_screen_share_scam_flags_high(self):
        score, findings = analyze_text(
            "Your account will be blocked. Install AnyDesk and share your OTP to verify KYC immediately."
        )
        assert score >= 50
        categories = [f["category"] for f in findings]
        assert "urgency" in categories
        assert "remote_access" in categories
        assert "sensitive_info" in categories

    def test_normal_message_is_clean(self):
        score, findings = analyze_text("Hey are we still meeting for lunch tomorrow?")
        assert score == 0
        assert findings == []

    def test_hinglish_urgency_detected(self):
        score, findings = analyze_text("Aapka khata turant band ho jayega, abhi OTP bhejo")
        assert score > 0
        categories = [f["category"] for f in findings]
        assert "urgency" in categories

    def test_fake_refund_pattern(self):
        score, findings = analyze_text(
            "You are eligible for a refund of Rs 2000. Pay Rs 1 processing fee to claim your refund now."
        )
        categories = [f["category"] for f in findings]
        assert "fake_refund" in categories

    def test_micro_transaction_mention(self):
        score, findings = analyze_text("Pay Rs 2 to verify your account")
        categories = [f["category"] for f in findings]
        assert "micro_transaction" in categories

    def test_case_insensitivity(self):
        score_lower, _ = analyze_text("install anydesk now")
        score_upper, _ = analyze_text("INSTALL ANYDESK NOW")
        assert score_lower == score_upper

    def test_empty_string_is_safe(self):
        score, findings = analyze_text("")
        assert score == 0
        assert findings == []


class TestVpaAnalysis:
    def test_suspicious_refund_handle_flagged(self):
        score, findings = analyze_vpa("refund8823910@paytm")
        assert score > 0
        assert any(f["category"] == "suspicious_vpa" for f in findings)

    def test_normal_handle_is_clean(self):
        score, findings = analyze_vpa("rahul.sharma@okhdfcbank")
        assert score == 0

    def test_invalid_format_flagged(self):
        score, findings = analyze_vpa("not-a-valid-vpa")
        assert findings[0]["category"] == "invalid_format"

    def test_long_alphanumeric_handle_flagged(self):
        score, findings = analyze_vpa("xk29283746@ybl")
        assert score > 0


class TestUrlAnalysis:
    def test_lookalike_domain_flagged(self):
        score, findings = analyze_url("http://hdfcbank-kyc-verify.com/login")
        assert score > 0
        assert any(f["category"] == "lookalike_domain" for f in findings)

    def test_url_shortener_flagged(self):
        score, findings = analyze_url("http://bit.ly/3xKq9pL")
        assert score > 0
        assert any(f["category"] == "shortened_url" for f in findings)

    def test_legitimate_bank_domain_not_flagged_as_lookalike(self):
        score, findings = analyze_url("https://www.hdfcbank.com/personal/pay")
        lookalike_hits = [f for f in findings if f["category"] == "lookalike_domain"]
        assert lookalike_hits == []


class TestRiskLevels:
    @pytest.mark.parametrize("score,expected", [
        (0, "SAFE"),
        (1, "LOW"),
        (19, "LOW"),
        (20, "MEDIUM"),
        (49, "MEDIUM"),
        (50, "HIGH"),
        (100, "HIGH"),
    ])
    def test_risk_level_boundaries(self, score, expected):
        assert get_risk_level(score) == expected


class TestAnalyzeInput:
    def test_routes_to_correct_analyzer(self):
        text_result = analyze_input("text", "install anydesk now")
        vpa_result = analyze_input("vpa", "refund123@paytm")
        url_result = analyze_input("url", "http://bit.ly/xyz")
        assert text_result["input_type"] == "text"
        assert vpa_result["input_type"] == "vpa"
        assert url_result["input_type"] == "url"

    def test_score_capped_at_100(self):
        # stack every trigger possible into one message
        result = analyze_input(
            "text",
            "URGENT account blocked immediately verify kyc. Install AnyDesk teamviewer now. "
            "Share otp pin cvv. Pay Rs 1 refund payment processing fee. "
            "Calling from your bank rbi officer. Pay Rs 2 now."
        )
        assert result["score"] <= 100

    def test_invalid_input_type_raises(self):
        with pytest.raises(ValueError):
            analyze_input("not_a_real_type", "value")


class TestBatch:
    def test_batch_returns_one_result_per_line(self):
        results = analyze_batch("text", ["install anydesk", "lets meet tomorrow", "send otp now"])
        assert len(results) == 3

    def test_batch_skips_blank_lines(self):
        results = analyze_batch("text", ["hello", "", "   ", "world"])
        assert len(results) == 2


class TestQrParsing:
    def test_extracts_vpa_from_upi_uri(self):
        vpa = extract_upi_id_from_qr_string("upi://pay?pa=merchant123@paytm&pn=Shop&am=500")
        assert vpa == "merchant123@paytm"

    def test_extracts_raw_vpa_without_wrapper(self):
        vpa = extract_upi_id_from_qr_string("someone@okhdfcbank")
        assert vpa == "someone@okhdfcbank"

    def test_non_upi_qr_returns_none(self):
        vpa = extract_upi_id_from_qr_string("https://example.com")
        assert vpa is None

    def test_empty_string_returns_none(self):
        assert extract_upi_id_from_qr_string("") is None
