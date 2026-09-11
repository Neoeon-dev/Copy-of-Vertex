"""Email threat classifier using TF-IDF + Logistic Regression.

Classifies emails as: legitimate | suspicious | phishing | spam

The model produces EXPLAINABLE signals:
- urgency_language: presence of urgent/pressure words
- credential_request: requests for passwords, login info
- payment_request: wire transfer, payment demands
- suspicious_domain: domain risk indicators
- impersonation: display-name vs address mismatch
- suspicious_url: URLs detected in body
- authentication_anomalies: SPF/DKIM failures

Model is trained on synthetic data for the prototype.
Real training data should replace this before production.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

logger = logging.getLogger(__name__)

# ── Explainable signal patterns ──────────────────────────────────────

URGENCY_WORDS = re.compile(
    r"\b(urgent|immediately|expire|suspended|verify|confirm|act now|"
    r"limited time|deadline|warning|alert|attention|required|"
    r"final notice|account locked|security breach|unusual activity)\b",
    re.IGNORECASE,
)

CREDENTIAL_WORDS = re.compile(
    r"\b(password|passwd|credentials|login|signin|sign in|log in|"
    r"username|user name|account number|ssn|social security|"
    r"credit card|debit card|pin number|security code|cvv)\b",
    re.IGNORECASE,
)

PAYMENT_WORDS = re.compile(
    r"\b(wire transfer|bank transfer|western union|money gram|bitcoin|"
    r"crypto|payment due|invoice attached|urgent payment|"
    r"bank details|account details|routing number|iban|swift)\b",
    re.IGNORECASE,
)

URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
    re.IGNORECASE,
)

IP_URL_PATTERN = re.compile(
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
)


@dataclass
class ClassificationResult:
    """Result of email classification with explainable signals."""

    label: str  # legitimate | suspicious | phishing | spam
    confidence: float  # 0.0 – 1.0
    probabilities: dict[str, float] = field(default_factory=dict)
    signals: dict[str, float] = field(default_factory=dict)  # signal_name → 0.0–1.0
    signal_details: dict[str, str] = field(default_factory=dict)
    risk_score: float = 0.0  # 0.0 – 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "confidence": round(self.confidence, 3),
            "probabilities": {k: round(v, 3) for k, v in self.probabilities.items()},
            "signals": {k: round(v, 3) for k, v in self.signals.items()},
            "signal_details": self.signal_details,
            "risk_score": round(self.risk_score, 3),
        }


# ── Feature extraction ───────────────────────────────────────────────


def _compute_signals(
    subject: str | None,
    sender: str | None,
    sender_name: str | None,
    body_text: str | None,
    body_html: str | None,
    spf_result: str | None = None,
    dkim_result: str | None = None,
) -> tuple[dict[str, float], dict[str, str]]:
    """Compute explainable signal scores from email content.

    Returns (signals, signal_details) where each signal is 0.0–1.0.
    """
    signals: dict[str, float] = {}
    details: dict[str, str] = {}

    text = " ".join(filter(None, [subject, body_text]))

    # Urgency language
    urgency_matches = URGENCY_WORDS.findall(text)
    signals["urgency_language"] = min(1.0, len(urgency_matches) * 0.25)
    if urgency_matches:
        details["urgency_language"] = f"Found: {', '.join(set(urgency_matches))}"

    # Credential requests
    credential_matches = CREDENTIAL_WORDS.findall(text)
    signals["credential_request"] = min(1.0, len(credential_matches) * 0.3)
    if credential_matches:
        details["credential_request"] = f"Found: {', '.join(set(credential_matches))}"

    # Payment requests
    payment_matches = PAYMENT_WORDS.findall(text)
    signals["payment_request"] = min(1.0, len(payment_matches) * 0.3)
    if payment_matches:
        details["payment_request"] = f"Found: {', '.join(set(payment_matches))}"

    # Suspicious URLs
    urls = URL_PATTERN.findall(text)
    ip_urls = IP_URL_PATTERN.findall(text)
    signals["suspicious_url"] = min(1.0, len(ip_urls) * 0.5 + (0.3 if len(urls) > 3 else 0))
    if ip_urls:
        details["suspicious_url"] = f"IP-based URLs found: {len(ip_urls)}"
    elif len(urls) > 3:
        details["suspicious_url"] = f"Many URLs detected: {len(urls)}"

    # Impersonation (display name doesn't match email domain)
    if sender and sender_name:
        sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
        name_lower = sender_name.lower()
        if sender_domain and sender_domain.split(".")[0] not in name_lower:
            signals["impersonation"] = 0.5
            details["impersonation"] = (
                f"Display name '{sender_name}' does not clearly match domain '{sender_domain}'"
            )
        else:
            signals["impersonation"] = 0.0
    else:
        signals["impersonation"] = 0.0

    # Authentication anomalies
    auth_score = 0.0
    if spf_result and spf_result in ("FAIL", "SOFTFAIL"):
        auth_score += 0.4
    if dkim_result and dkim_result == "FAIL":
        auth_score += 0.3
    if spf_result and spf_result == "NONE":
        auth_score += 0.1
    signals["authentication_anomalies"] = min(1.0, auth_score)
    if auth_score > 0:
        parts = []
        if spf_result:
            parts.append(f"SPF={spf_result}")
        if dkim_result:
            parts.append(f"DKIM={dkim_result}")
        details["authentication_anomalies"] = "; ".join(parts)

    return signals, details


def _build_feature_text(
    subject: str | None,
    sender: str | None,
    body_text: str | None,
    body_html: str | None,
) -> str:
    """Combine email fields into a single text for TF-IDF."""
    parts = []
    if subject:
        parts.append(f"SUBJECT: {subject}")
    if sender:
        parts.append(f"FROM: {sender}")
    if body_text:
        parts.append(f"BODY: {body_text[:2000]}")
    # Extract text from HTML if present
    if body_html and not body_text:
        # Simple HTML tag stripping
        clean = re.sub(r"<[^>]+>", " ", body_html)
        parts.append(f"BODY: {clean[:2000]}")
    return " ".join(parts)


# ── Synthetic training data ──────────────────────────────────────────

_SYNTHETIC_TRAINING_DATA: list[tuple[str, str]] = [
    # Phishing examples
    ("URGENT: Your account has been suspended. Verify your identity immediately.", "phishing"),
    ("Verify your password now or your account will be deleted", "phishing"),
    "Wire transfer required urgently to the following bank account".split(" ", 1)[0] and
    ("Dear customer, we detected unusual activity. Click here to verify your account.", "phishing"),
    ("Security Alert: Unauthorized access detected. Confirm your credentials.", "phishing"),
    ("Your PayPal account is limited. Log in to restore access.", "phishing"),
    ("Final warning: Your subscription expires today. Update payment info.", "phishing"),
    ("ATTN: Wire transfer of $45,000 required immediately for urgent invoice", "phishing"),
    ("Your account will be locked. Verify your password and SSN immediately.", "phishing"),
    ("Microsoft Security: Unusual sign-in activity. Verify your login.", "phishing"),
    ("Action Required: Suspicious activity detected on your bank account. Confirm details.", "phishing"),

    # Spam examples
    ("Buy cheap medications online! Best prices guaranteed!", "spam"),
    ("You have won $1,000,000! Claim your prize now!", "spam"),
    ("Lose weight fast with this miracle supplement!", "spam"),
    ("Nigerian prince needs your help transferring $10 million", "spam"),
    ("Limited time offer: 90% discount on luxury watches!", "spam"),
    ("Make money from home! $5000/day guaranteed!", "spam"),
    ("Free iPhone giveaway! Click here to claim!", "spam"),
    ("Hot singles in your area want to meet you!", "spam"),
    ("Discount pharmacy: Buy Viagra Cialis online cheap", "spam"),
    ("Congratulations! You've been selected for a cash prize!", "spam"),

    # Legitimate examples
    ("Meeting tomorrow at 3pm in conference room B", "legitimate"),
    ("Project update: Q4 results are ready for review", "legitimate"),
    "Please find attached the quarterly report for your review".split(" ", 1)[0] and
    ("Hi team, the deployment is scheduled for Friday.", "legitimate"),
    ("Your order has been shipped. Tracking number: 1Z999AA10123", "legitimate"),
    ("Reminder: Team lunch this Wednesday at noon", "legitimate"),
    ("Re: Question about the API integration", "legitimate"),
    ("Thank you for your purchase. Receipt attached.", "legitimate"),
    ("The quarterly budget review meeting has been rescheduled.", "legitimate"),
    ("Can you review the pull request when you get a chance?", "legitimate"),
    ("Newsletter: This week in technology updates", "legitimate"),

    # Suspicious examples
    ("Please review the attached document and reply with your feedback", "suspicious"),
    ("Your account needs attention. Please check your settings.", "suspicious"),
    ("Important update regarding your service subscription", "suspicious"),
    ("We need to verify some information. Please respond promptly.", "suspicious"),
    ("Action needed: Please update your billing information", "suspicious"),
]


class EmailClassifier:
    """ML-based email threat classifier with explainable signals."""

    def __init__(self) -> None:
        self._pipeline: Pipeline | None = None
        self._labels: list[str] = ["legitimate", "suspicious", "phishing", "spammer"]
        self._trained = False

    def train(self) -> None:
        """Train the classifier on synthetic data.

        In production, replace with real labeled email datasets.
        """
        texts = [text for text, _ in _SYNTHETIC_TRAINING_DATA]
        labels = [label for _, label in _SYNTHETIC_TRAINING_DATA]

        self._pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 2),
                stop_words="english",
                sublinear_tf=True,
            )),
            ("clf", LogisticRegression(
                max_iter=1000,
                C=1.0,
                class_weight="balanced",
                random_state=42,
            )),
        ])

        self._pipeline.fit(texts, labels)
        self._labels = self._pipeline.classes_.tolist()
        self._trained = True
        logger.info("Email classifier trained on %d samples, classes: %s", len(texts), self._labels)

    def classify(
        self,
        subject: str | None = None,
        sender: str | None = None,
        sender_name: str | None = None,
        body_text: str | None = None,
        body_html: str | None = None,
        spf_result: str | None = None,
        dkim_result: str | None = None,
    ) -> ClassificationResult:
        """Classify an email and return explanation with signals."""
        if not self._trained:
            self.train()

        # Build feature text for TF-IDF
        feature_text = _build_feature_text(subject, sender, body_text, body_html)

        # ML prediction
        proba = self._pipeline.predict_proba([feature_text])[0]
        label_idx = int(np.argmax(proba))
        label = self._labels[label_idx]
        confidence = float(proba[label_idx])

        probabilities = {self._labels[i]: float(proba[i]) for i in range(len(self._labels))}

        # Compute explainable signals
        signals, signal_details = _compute_signals(
            subject=subject,
            sender=sender,
            sender_name=sender_name,
            body_text=body_text,
            body_html=body_html,
            spf_result=spf_result,
            dkim_result=dkim_result,
        )

        # Compute overall risk score from ML + signals
        ml_risk = {"legitimate": 0.0, "suspicious": 0.4, "phishing": 0.8, "spammer": 0.5}
        risk = ml_risk.get(label, 0.3) * confidence

        # Add signal contributions
        signal_weights = {
            "urgency_language": 0.15,
            "credential_request": 0.2,
            "payment_request": 0.15,
            "suspicious_url": 0.15,
            "impersonation": 0.1,
            "authentication_anomalies": 0.15,
        }
        for sig_name, sig_val in signals.items():
            weight = signal_weights.get(sig_name, 0.1)
            risk += sig_val * weight

        risk = min(1.0, risk)

        return ClassificationResult(
            label=label,
            confidence=confidence,
            probabilities=probabilities,
            signals=signals,
            signal_details=signal_details,
            risk_score=risk,
        )


# Singleton classifier instance
_classifier: EmailClassifier | None = None


def get_classifier() -> EmailClassifier:
    global _classifier
    if _classifier is None:
        _classifier = EmailClassifier()
    return _classifier
