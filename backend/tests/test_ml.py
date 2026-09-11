"""Tests for ML email threat classifier.

Verifies:
- Training on synthetic data
- Classification of phishing, spam, legitimate, suspicious emails
- Explainable signals
- API endpoint integration
- Edge cases (empty body, missing fields)
"""
from __future__ import annotations

import io

from app.ml.classifier import EmailClassifier, _compute_signals, get_classifier
from tests.conftest import SAMPLE_EML, SAMPLE_EML_HEADERS_ONLY


class TestSignalComputation:
    """Test explainable signal extraction."""

    def test_urgency_signals(self):
        signals, details = _compute_signals(
            subject="URGENT: Verify your account immediately",
            sender=None,
            sender_name=None,
            body_text="Your account will be suspended. Act now!",
            body_html=None,
        )
        assert signals["urgency_language"] > 0
        assert "urgency_language" in details

    def test_credential_signals(self):
        signals, details = _compute_signals(
            subject="Security Alert",
            sender=None,
            sender_name=None,
            body_text="Please confirm your password and credit card number",
            body_html=None,
        )
        assert signals["credential_request"] > 0

    def test_payment_signals(self):
        signals, details = _compute_signals(
            subject="Urgent Invoice",
            sender=None,
            sender_name=None,
            body_text="Wire transfer required immediately to bank account",
            body_html=None,
        )
        assert signals["payment_request"] > 0

    def test_ip_url_signals(self):
        signals, details = _compute_signals(
            subject="Click here",
            sender=None,
            sender_name=None,
            body_text="Visit http://192.168.1.1/steal for more info",
            body_html=None,
        )
        assert signals["suspicious_url"] > 0

    def test_impersonation_signal(self):
        signals, details = _compute_signals(
            subject="From PayPal",
            sender="attacker@evil.com",
            sender_name="PayPal Security Team",
            body_text=None,
            body_html=None,
        )
        assert signals["impersonation"] > 0

    def test_clean_email_no_signals(self):
        signals, details = _compute_signals(
            subject="Meeting tomorrow",
            sender="colleague@company.com",
            sender_name="John Doe",
            body_text="Hi, let's meet at 3pm in the conference room.",
            body_html=None,
        )
        assert signals["urgency_language"] == 0
        assert signals["credential_request"] == 0
        assert signals["payment_request"] == 0
        assert signals["suspicious_url"] == 0


class TestClassifier:
    """Test the ML classifier."""

    def test_classifier_trains(self):
        clf = EmailClassifier()
        clf.train()
        assert clf._trained is True

    def test_classify_phishing(self):
        clf = get_classifier()
        result = clf.classify(
            subject="URGENT: Verify your password or account will be deleted",
            sender="security@paypa1.com",
            sender_name="PayPal Security",
            body_text="We detected unusual activity. Confirm your credentials immediately or your account will be suspended.",
        )
        assert result.label in ("phishing", "suspicious")
        assert result.confidence > 0
        assert result.risk_score > 0
        assert "urgency_language" in result.signals
        assert "credential_request" in result.signals

    def test_classify_legitimate(self):
        clf = get_classifier()
        result = clf.classify(
            subject="Meeting tomorrow at 3pm",
            sender="colleague@company.com",
            sender_name="Jane Smith",
            body_text="Hi team, let's meet tomorrow at 3pm in the conference room to discuss the project.",
        )
        assert result.label in ("legitimate", "suspicious")
        assert result.confidence > 0

    def test_classify_spam(self):
        clf = get_classifier()
        result = clf.classify(
            subject="You have won $1,000,000!",
            sender="prize@lottery.com",
            sender_name="Lottery Commission",
            body_text="Congratulations! You have been selected to receive a cash prize. Click here to claim now!",
        )
        assert result.label in ("spam", "suspicious", "phishing")

    def test_classify_empty(self):
        clf = get_classifier()
        result = clf.classify(
            subject=None,
            sender=None,
            sender_name=None,
            body_text=None,
            body_html=None,
        )
        assert result.label in ("legitimate", "suspicious", "phishing", "spam")
        assert 0.0 <= result.confidence <= 1.0

    def test_probabilities_sum_to_one(self):
        clf = get_classifier()
        result = clf.classify(
            subject="Test",
            sender="test@example.com",
            body_text="Hello world",
        )
        total = sum(result.probabilities.values())
        assert abs(total - 1.0) < 0.01

    def test_risk_score_range(self):
        clf = get_classifier()
        result = clf.classify(
            subject="URGENT: Verify password now",
            sender="attacker@evil.com",
            body_text="Send your credit card number immediately",
        )
        assert 0.0 <= result.risk_score <= 1.0


class TestMLEndpoint:
    """Integration tests for POST /api/emails/{id}/classify."""

    def _upload_email(self, client, eml=SAMPLE_EML) -> int:
        resp = client.post(
            "/api/emails/analyze",
            files={"file": ("test.eml", io.BytesIO(eml), "message/rfc822")},
        )
        assert resp.status_code == 201
        return resp.json()["id"]

    def test_classify_endpoint_works(self, client):
        eid = self._upload_email(client, SAMPLE_EML_HEADERS_ONLY)
        resp = client.post(f"/api/emails/{eid}/classify")
        assert resp.status_code == 200
        data = resp.json()
        assert "label" in data
        assert "confidence" in data
        assert "signals" in data
        assert "risk_score" in data
        assert data["label"] in ("legitimate", "suspicious", "phishing", "spammer")

    def test_get_classification(self, client):
        eid = self._upload_email(client)
        resp = client.get(f"/api/emails/{eid}/classify")
        assert resp.status_code == 200
        data = resp.json()
        assert "label" in data

    def test_classify_nonexistent(self, client):
        resp = client.post("/api/emails/99999/classify")
        assert resp.status_code == 404
