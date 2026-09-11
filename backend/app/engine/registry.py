"""
Centralized Risk Factor Registry for VERTEX (Phase D5).
Stores stable risk factor definitions, category caps, default weights, and explanation templates.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional
from app.engine.schemas import RiskFactorCategory, RiskFactor


@dataclass(frozen=True)
class FactorDefinition:
    """Immutable definition of a registered forensic risk factor."""
    factor_id: str
    category: str
    name: str
    description: str
    default_contribution: float
    max_contribution: float
    direction: str = "INCREASE_RISK"
    evidence_requirement: str = "Any observed anomaly in corresponding analyzer"
    explanation_template: str = "{name}: {detail}"


# Category point contribution caps (controls runaway scores & prevents double-counting)
CATEGORY_CAPS: Dict[str, float] = {
    RiskFactorCategory.MODEL.value: 35.0,
    RiskFactorCategory.AUTHENTICATION.value: 20.0,
    RiskFactorCategory.IDENTITY.value: 15.0,
    RiskFactorCategory.DOMAIN.value: 15.0,
    RiskFactorCategory.URL.value: 15.0,
    RiskFactorCategory.ATTACHMENT.value: 15.0,
    RiskFactorCategory.INFRASTRUCTURE_RELAY.value: 10.0,
    RiskFactorCategory.CONTENT_BEC.value: 15.0,
    RiskFactorCategory.EVIDENCE.value: 10.0,
}


class RiskFactorRegistry:
    """Central repository of all valid forensic risk factors."""

    _FACTORS: Dict[str, FactorDefinition] = {}

    @classmethod
    def register(cls, definition: FactorDefinition) -> None:
        cls._FACTORS[definition.factor_id] = definition

    @classmethod
    def get(cls, factor_id: str) -> Optional[FactorDefinition]:
        return cls._FACTORS.get(factor_id)

    @classmethod
    def list_all(cls) -> List[FactorDefinition]:
        return list(cls._FACTORS.values())

    @classmethod
    def list_by_category(cls, category: str) -> List[FactorDefinition]:
        return [f for f in cls._FACTORS.values() if f.category == category]

    @classmethod
    def get_category_cap(cls, category: str) -> float:
        return CATEGORY_CAPS.get(category, 15.0)


# ─── Register Standard Forensic Risk Factors ─────────────────────────────

# 1. Model Factors
RiskFactorRegistry.register(FactorDefinition(
    factor_id="MODEL_PHISHING_CONFIRMED",
    category=RiskFactorCategory.MODEL.value,
    name="Model Phishing Prediction",
    description="Multimodal D4 classifier detected high phishing intent probability",
    default_contribution=25.0,
    max_contribution=25.0,
    direction="INCREASE_RISK",
    explanation_template="Multimodal threat classifier identified high phishing intent (P={prob:.1%}).",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="MODEL_PHISHING_SUSPECTED",
    category=RiskFactorCategory.MODEL.value,
    name="Model Phishing Suspected",
    description="Multimodal D4 classifier detected moderate phishing intent probability",
    default_contribution=15.0,
    max_contribution=15.0,
    direction="INCREASE_RISK",
    explanation_template="Multimodal threat classifier detected moderate phishing probability (P={prob:.1%}).",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="MODEL_SPAM_DETECTED",
    category=RiskFactorCategory.MODEL.value,
    name="Model Spam Intent",
    description="Multimodal D4 classifier identified unsolicited bulk or promotional intent",
    default_contribution=10.0,
    max_contribution=10.0,
    direction="INCREASE_RISK",
    explanation_template="Classifier detected unsolicited spam/promotional characteristics (P={prob:.1%}).",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="MODEL_LEGITIMATE_MITIGATION",
    category=RiskFactorCategory.MODEL.value,
    name="Model Legitimate Confidence",
    description="High legitimate confidence acts as mitigating factor",
    default_contribution=-10.0,
    max_contribution=10.0,
    direction="REDUCE_RISK",
    explanation_template="High legitimate probability (P={prob:.1%}) mitigates overall risk.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="MODEL_DISAGREEMENT_ELEVATION",
    category=RiskFactorCategory.MODEL.value,
    name="Model Modality Disagreement",
    description="Forensic tabular and semantic text models produced conflicting predictions",
    default_contribution=5.0,
    max_contribution=5.0,
    direction="INCREASE_RISK",
    explanation_template="Modality disagreement between forensic ({d2_label}) and semantic ({d3_label}) models increases uncertainty.",
))

# 2. Authentication Factors
RiskFactorRegistry.register(FactorDefinition(
    factor_id="AUTH_DMARC_FAIL",
    category=RiskFactorCategory.AUTHENTICATION.value,
    name="DMARC Policy Failure",
    description="DMARC validation failed; sending server violates domain publishing policy",
    default_contribution=12.0,
    max_contribution=12.0,
    direction="INCREASE_RISK",
    explanation_template="DMARC authentication check failed: sending host violates sender domain policy.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="AUTH_SPF_FAIL",
    category=RiskFactorCategory.AUTHENTICATION.value,
    name="SPF Verification Failure",
    description="Sender Policy Framework check failed (FAIL or SOFTFAIL)",
    default_contribution=8.0,
    max_contribution=8.0,
    direction="INCREASE_RISK",
    explanation_template="SPF verification failed ({spf_result}): transmitting IP is not authorized by domain SPF record.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="AUTH_DKIM_FAIL",
    category=RiskFactorCategory.AUTHENTICATION.value,
    name="DKIM Cryptographic Signature Failure",
    description="DKIM cryptographic body/header signature verification failed",
    default_contribution=8.0,
    max_contribution=8.0,
    direction="INCREASE_RISK",
    explanation_template="DKIM cryptographic signature verification failed: message integrity compromised or forged.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="AUTH_ALL_PASS",
    category=RiskFactorCategory.AUTHENTICATION.value,
    name="Full Authentication Alignment",
    description="SPF, DKIM, and DMARC all passed verification",
    default_contribution=-5.0,
    max_contribution=5.0,
    direction="REDUCE_RISK",
    explanation_template="Complete cryptographic alignment: SPF, DKIM, and DMARC all passed verified checks.",
))

# 3. Identity Factors
RiskFactorRegistry.register(FactorDefinition(
    factor_id="IDENTITY_DISPLAY_NAME_MISMATCH",
    category=RiskFactorCategory.IDENTITY.value,
    name="Display Name Impersonation",
    description="Display name claims an entity that does not match sender domain",
    default_contribution=8.0,
    max_contribution=8.0,
    direction="INCREASE_RISK",
    explanation_template="Display name '{name}' does not match originating domain '{domain}'.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="IDENTITY_REPLY_TO_MISMATCH",
    category=RiskFactorCategory.IDENTITY.value,
    name="Reply-To Domain Mismatch",
    description="Reply-To header routes responses to a different domain than From header",
    default_contribution=6.0,
    max_contribution=6.0,
    direction="INCREASE_RISK",
    explanation_template="Reply-To address ({reply_to}) diverts responses away from From domain ({sender}).",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="IDENTITY_ENVELOPE_MISMATCH",
    category=RiskFactorCategory.IDENTITY.value,
    name="Envelope Sender Mismatch",
    description="RFC5321 envelope sender does not align with RFC5322 From address",
    default_contribution=4.0,
    max_contribution=4.0,
    direction="INCREASE_RISK",
    explanation_template="Envelope sender does not align with visible From address.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="IDENTITY_PARSING_FAILURE",
    category=RiskFactorCategory.IDENTITY.value,
    name="Malformed Sender Address",
    description="Sender address failed RFC822 syntax parsing",
    default_contribution=4.0,
    max_contribution=4.0,
    direction="INCREASE_RISK",
    explanation_template="Sender address syntax is malformed or invalid.",
))

# 4. Domain Factors
RiskFactorRegistry.register(FactorDefinition(
    factor_id="DOMAIN_LOOKALIKE",
    category=RiskFactorCategory.DOMAIN.value,
    name="Lookalike / Typosquat Domain",
    description="Sender domain resembles a known legitimate brand (Levenshtein distance <= 2)",
    default_contribution=8.0,
    max_contribution=8.0,
    direction="INCREASE_RISK",
    explanation_template="Sender domain '{domain}' is a lookalike of target brand '{brand}'.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="DOMAIN_HOMOGLYPH",
    category=RiskFactorCategory.DOMAIN.value,
    name="Homoglyph / Punycode Deception",
    description="Domain contains Cyrillic/Greek homoglyphs or Punycode spoofing",
    default_contribution=8.0,
    max_contribution=8.0,
    direction="INCREASE_RISK",
    explanation_template="Domain '{domain}' contains deceptive homoglyphs or punycode characters.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="DOMAIN_SUSPICIOUS_TLD",
    category=RiskFactorCategory.DOMAIN.value,
    name="High-Abuse Top Level Domain",
    description="Sender domain uses a top-level domain frequently associated with abuse",
    default_contribution=5.0,
    max_contribution=5.0,
    direction="INCREASE_RISK",
    explanation_template="Sender domain uses a high-abuse top level domain ({tld}).",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="DOMAIN_HIGH_ENTROPY",
    category=RiskFactorCategory.DOMAIN.value,
    name="High-Entropy Domain Name",
    description="Domain string exhibits high Shannon entropy consistent with algorithmic generation",
    default_contribution=4.0,
    max_contribution=4.0,
    direction="INCREASE_RISK",
    explanation_template="Sender domain exhibits high Shannon entropy ({entropy:.2f}), indicative of algorithmic generation.",
))

# 5. URL Factors
RiskFactorRegistry.register(FactorDefinition(
    factor_id="URL_IP_BASED",
    category=RiskFactorCategory.URL.value,
    name="IP-Based URL Destination",
    description="Message contains hyperlinked raw IPv4/IPv6 destination address",
    default_contribution=8.0,
    max_contribution=8.0,
    direction="INCREASE_RISK",
    explanation_template="Email contains direct IP-based URL destination ({url}).",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="URL_SHORTENER",
    category=RiskFactorCategory.URL.value,
    name="URL Shortener Detected",
    description="Link utilizes a URL shortening service that conceals destination",
    default_contribution=4.0,
    max_contribution=4.0,
    direction="INCREASE_RISK",
    explanation_template="Email contains shortened URL concealing destination ({url}).",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="URL_SUSPICIOUS_PATH",
    category=RiskFactorCategory.URL.value,
    name="Suspicious URL Path Tokens",
    description="URL path contains credential harvesting cues (login, account, verify)",
    default_contribution=5.0,
    max_contribution=5.0,
    direction="INCREASE_RISK",
    explanation_template="URL path contains credential solicitation cues ({url}).",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="URL_PUNYCODE",
    category=RiskFactorCategory.URL.value,
    name="Punycode Encoded URL",
    description="URL destination uses Internationalized Domain Name (IDN) punycode encoding",
    default_contribution=5.0,
    max_contribution=5.0,
    direction="INCREASE_RISK",
    explanation_template="URL uses punycode encoding to disguise destination domain ({url}).",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="URL_HIGH_COUNT",
    category=RiskFactorCategory.URL.value,
    name="Excessive URL Density",
    description="Email contains unusually high quantity of external hyperlinks (> 5)",
    default_contribution=3.0,
    max_contribution=3.0,
    direction="INCREASE_RISK",
    explanation_template="Email contains an abnormally high density of external hyperlinks ({count} links).",
))

# 6. Attachment Factors
RiskFactorRegistry.register(FactorDefinition(
    factor_id="ATT_DOUBLE_EXTENSION",
    category=RiskFactorCategory.ATTACHMENT.value,
    name="Double Extension Deception",
    description="Attachment filename uses double extension to disguise executable payload (e.g. .pdf.exe)",
    default_contribution=10.0,
    max_contribution=10.0,
    direction="INCREASE_RISK",
    explanation_template="Attachment '{filename}' utilizes double extension to disguise executable payload.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="ATT_DANGEROUS_EXTENSION",
    category=RiskFactorCategory.ATTACHMENT.value,
    name="Dangerous File Type Attached",
    description="Attachment is a binary executable, script, or macro-enabled document",
    default_contribution=8.0,
    max_contribution=8.0,
    direction="INCREASE_RISK",
    explanation_template="Attachment '{filename}' is an executable or script format.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="ATT_MIME_MISMATCH",
    category=RiskFactorCategory.ATTACHMENT.value,
    name="Attachment MIME Type Mismatch",
    description="Declared MIME content type contradicts actual file extension",
    default_contribution=5.0,
    max_contribution=5.0,
    direction="INCREASE_RISK",
    explanation_template="Attachment '{filename}' MIME header ({mime}) does not match file extension.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="ATT_ARCHIVE_PRESENT",
    category=RiskFactorCategory.ATTACHMENT.value,
    name="Archive Container Attached",
    description="Email contains compressed container file (.zip, .rar, .7z) requiring inspection",
    default_contribution=4.0,
    max_contribution=4.0,
    direction="INCREASE_RISK",
    explanation_template="Email carries compressed archive attachment '{filename}'.",
))

# 7. Infrastructure & Relay Factors
RiskFactorRegistry.register(FactorDefinition(
    factor_id="RELAY_NON_MONOTONIC_TIME",
    category=RiskFactorCategory.INFRASTRUCTURE_RELAY.value,
    name="Non-Monotonic Relay Timestamps",
    description="Received hop timestamps appear out of chronological order (forged headers)",
    default_contribution=5.0,
    max_contribution=5.0,
    direction="INCREASE_RISK",
    explanation_template="Received header relay timestamps are non-monotonic, indicating header manipulation.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="RELAY_ANOMALOUS_HOP_COUNT",
    category=RiskFactorCategory.INFRASTRUCTURE_RELAY.value,
    name="Anomalous Relay Hop Count",
    description="Email traversed an abnormal number of relay hops (> 8 or 0)",
    default_contribution=4.0,
    max_contribution=4.0,
    direction="INCREASE_RISK",
    explanation_template="Relay hop trace is anomalous ({hops} hops).",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="INFRA_PRIVATE_ORIGINATING_IP",
    category=RiskFactorCategory.INFRASTRUCTURE_RELAY.value,
    name="RFC1918 Private Originating IP",
    description="Public transit email claims origin from non-routable private IP space",
    default_contribution=3.0,
    max_contribution=3.0,
    direction="INCREASE_RISK",
    explanation_template="Originating network IP ({ip}) is in non-routable private address space.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="INFRA_BOGON_IP",
    category=RiskFactorCategory.INFRASTRUCTURE_RELAY.value,
    name="Bogon / Unallocated IP Address",
    description="Relay IP is unallocated by IANA/RIR or reserved bogon",
    default_contribution=5.0,
    max_contribution=5.0,
    direction="INCREASE_RISK",
    explanation_template="Relay chain includes unallocated or bogon IP address ({ip}).",
))

# 8. Content / BEC Factors
RiskFactorRegistry.register(FactorDefinition(
    factor_id="BEC_CREDENTIAL_REQUEST",
    category=RiskFactorCategory.CONTENT_BEC.value,
    name="Credential Harvesting Intent",
    description="Body text solicits credentials, passwords, PINs, or security verification",
    default_contribution=7.0,
    max_contribution=7.0,
    direction="INCREASE_RISK",
    explanation_template="Content solicits account credentials, login passwords, or security authentication.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="BEC_PAYMENT_DEMAND",
    category=RiskFactorCategory.CONTENT_BEC.value,
    name="Financial / Payment Demands",
    description="Body text requests wire transfers, gift cards, invoice redirection, or cryptocurrency",
    default_contribution=7.0,
    max_contribution=7.0,
    direction="INCREASE_RISK",
    explanation_template="Content solicits urgent wire transfers, invoice redirection, or financial transactions.",
))

RiskFactorRegistry.register(FactorDefinition(
    factor_id="BEC_URGENCY_PRESSURE",
    category=RiskFactorCategory.CONTENT_BEC.value,
    name="Psychological Urgency Cues",
    description="Language applies coercive deadlines, impending suspension, or legal threats",
    default_contribution=4.0,
    max_contribution=4.0,
    direction="INCREASE_RISK",
    explanation_template="Content applies psychological pressure and artificial urgency cues.",
))


def get_default_registry() -> type[RiskFactorRegistry]:
    """Returns the canonical global RiskFactorRegistry."""
    return RiskFactorRegistry
