"""
Feature Group 11: BEC & Phishing Semantic Cues Telemetry.
Deterministic, keyword- and regex-based forensic semantic cues identifying
urgency, wire transfer demands, credential harvesting, secrecy, and executive authority.
"""
from typing import Dict, Any, Tuple, Optional, List
import re

URGENCY_TERMS = [
    r"\burgent\b", r"\bimmediately\b", r"\baction required\b", r"\bwithin 24 hours\b",
    r"\bsuspended\b", r"\bdeadline\b", r"\bexpire[ds]?\b", r"\bcritical\b",
    r"\bact now\b", r"\bfinal notice\b", r"\bimmediate response\b",
]

CREDENTIAL_HARVEST_TERMS = [
    r"\bverify your account\b", r"\bconfirm password\b", r"\bupdate payment\b",
    r"\bsecurity alert\b", r"\bunauthorized access\b", r"\blog in to verify\b",
    r"\breset password\b", r"\bsecurity notice\b", r"\bunusual activity\b",
]

PAYMENT_REQUEST_TERMS = [
    r"\bwire transfer\b", r"\bbank account\b", r"\binvoice attached\b",
    r"\bremittance\b", r"\bpayment details\b", r"\bgift card\b",
    r"\brouting number\b", r"\bdirect deposit\b", r"\bnew account details\b",
]

ACCOUNT_VERIFICATION_TERMS = [
    r"\bverify\b", r"\bverification\b", r"\bconfirm your identity\b",
    r"\bvalidate\b", r"\breactivate\b", r"\baccount suspended\b",
    r"\bsecurity update\b", r"\bconfirm details\b",
]

SECRECY_TERMS = [
    r"\bconfidential\b", r"\bkeep this between us\b", r"\bdo not contact\b",
    r"\bprivate matter\b", r"\bdiscreet\b", r"\bstrictly confidential\b",
    r"\burgent and confidential\b",
]

BANK_CHANGE_TERMS = [
    r"\bupdated bank\b", r"\bnew banking details\b", r"\bchange of account\b",
    r"\bbeneficiary change\b", r"\bnew bank\b", r"\bupdated account number\b",
    r"\bwire instructions\b",
]

GIFT_CARD_TERMS = [
    r"\bitunes\b", r"\bgoogle play\b", r"\bsteam card\b", r"\bgift card\b",
    r"\bapple card\b", r"\bamazon gift\b", r"\bebay card\b",
]

WIRE_TRANSFER_TERMS = [
    r"\bwire\b", r"\bswift\b", r"\biban\b", r"\bwire transfer\b",
    r"\brouting number\b", r"\bach transfer\b",
]

INVOICE_TERMS = [
    r"\binvoice\b", r"\breceipt\b", r"\bpurchase order\b", r"\boverdue\b",
    r"\bstatement\b", r"\bbilling statement\b", r"\bunpaid\b",
]

EXECUTIVE_TERMS = [
    r"\bceo\b", r"\bcfo\b", r"\bcto\b", r"\bcio\b", r"\bpresident\b",
    r"\bdirector\b", r"\bexecutive\b", r"\bboard\b", r"\bpartner\b",
]

LOGIN_TERMS = [
    r"\blogin\b", r"\bsign in\b", r"\blog in\b", r"\bportal\b",
    r"\bcredentials\b", r"\bsign-in\b", r"\blog-in\b",
]

PASSWORD_TERMS = [
    r"\bpassword\b", r"\bpasscode\b", r"\bpin\b", r"\bmfa\b",
    r"\b2fa\b", r"\botp\b", r"\bsecurity token\b",
]


def _count_matches(patterns: List[str], text: str) -> float:
    count = 0
    for pat in patterns:
        count += len(re.findall(pat, text, re.IGNORECASE))
    return float(count)


def extract_bec_phish_signals(
    subject: Optional[str] = None,
    body_text: Optional[str] = None,
    sender_name: Optional[str] = None,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """
    Extracts deterministic BEC, fraud, urgency, and credential-harvesting signals.
    """
    feats: Dict[str, float] = {}
    exps: Dict[str, str] = {}

    combined = f"{sender_name or ''} {subject or ''} {body_text or ''}"

    feats["bec_urgency_score"] = _count_matches(URGENCY_TERMS, combined)
    feats["bec_credential_harvest_cues"] = _count_matches(CREDENTIAL_HARVEST_TERMS, combined)
    feats["bec_payment_request_cues"] = _count_matches(PAYMENT_REQUEST_TERMS, combined)
    feats["bec_account_verification_cues"] = _count_matches(ACCOUNT_VERIFICATION_TERMS, combined)
    feats["bec_secrecy_cues"] = _count_matches(SECRECY_TERMS, combined)
    feats["bec_bank_change_cues"] = _count_matches(BANK_CHANGE_TERMS, combined)
    feats["bec_gift_card_cues"] = _count_matches(GIFT_CARD_TERMS, combined)
    feats["bec_wire_transfer_cues"] = _count_matches(WIRE_TRANSFER_TERMS, combined)
    feats["bec_invoice_cues"] = _count_matches(INVOICE_TERMS, combined)
    feats["bec_executive_terms_count"] = _count_matches(EXECUTIVE_TERMS, combined)
    feats["bec_login_terms_count"] = _count_matches(LOGIN_TERMS, combined)
    feats["bec_password_terms_count"] = _count_matches(PASSWORD_TERMS, combined)

    return feats, exps
