"""
Feature Group 4: Identity Consistency & Impersonation Telemetry.
Compares envelope headers (From, Reply-To, Return-Path), evaluates organizational
domain alignment via Public Suffix List, and detects executive/role spoofing.
"""
from typing import Dict, Any, Tuple, Optional
import email.utils
import re
from app.forensics.dmarc_analyzer import extract_domain_from_address, get_organizational_domain

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com",
    "proton.me", "aol.com", "icloud.com", "mail.com", "zoho.com", "yandex.com",
}

DISPOSABLE_DOMAINS = {
    "10minutemail.com", "tempmail.com", "guerrillamail.com", "mailinator.com",
    "trashmail.com", "throwawaymail.com", "sharklasers.com",
}

ROLE_KEYWORDS = {
    "ceo", "cfo", "cto", "cio", "president", "director", "executive",
    "payroll", "hr", "human resources", "admin", "administrator", "it support",
    "helpdesk", "security team", "billing", "accounts payable",
}


def extract_identity_consistency(
    from_raw: Optional[str] = None,
    reply_to_raw: Optional[str] = None,
    return_path_raw: Optional[str] = None,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """
    Evaluates identity consistency across sender headers and display names.
    """
    feats: Dict[str, float] = {}
    exps: Dict[str, str] = {}

    display_name, from_addr = email.utils.parseaddr(from_raw or "")
    from_domain = extract_domain_from_address(from_addr or from_raw or "")
    reply_to_domain = extract_domain_from_address(reply_to_raw or "")
    return_path_domain = extract_domain_from_address(return_path_raw or "")

    feats["ident_display_name_present"] = 1.0 if bool(display_name.strip()) else 0.0
    feats["ident_address_parsing_failure"] = 1.0 if not from_domain else 0.0

    # 1. Domain Mismatches
    if from_domain and reply_to_domain:
        mismatch = (from_domain.lower() != reply_to_domain.lower())
        feats["ident_from_reply_to_mismatch"] = 1.0 if mismatch else 0.0
        exps["ident_from_reply_to_mismatch"] = (
            f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain})."
            if mismatch else "Reply-To matches From domain."
        )
    else:
        feats["ident_from_reply_to_mismatch"] = 0.0

    if from_domain and return_path_domain:
        mismatch = (from_domain.lower() != return_path_domain.lower())
        feats["ident_from_return_path_mismatch"] = 1.0 if mismatch else 0.0
    else:
        feats["ident_from_return_path_mismatch"] = 0.0

    # 2. Organizational Domain Mismatch (via Public Suffix List)
    if from_domain and reply_to_domain:
        from_org = get_organizational_domain(from_domain)
        reply_org = get_organizational_domain(reply_to_domain)
        feats["ident_sender_org_domain_mismatch"] = 1.0 if (from_org != reply_org) else 0.0
    else:
        feats["ident_sender_org_domain_mismatch"] = 0.0

    # 3. Subdomain depth
    if from_domain:
        parts = from_domain.split(".")
        feats["ident_subdomain_depth"] = float(max(0, len(parts) - 2))
    else:
        feats["ident_subdomain_depth"] = 0.0

    # 4. Display Name / Domain Inconsistency
    dn_lower = display_name.lower()
    inconsistent = False
    if from_domain and ("@" in dn_lower or ".com" in dn_lower or ".net" in dn_lower or ".org" in dn_lower):
        if from_domain not in dn_lower:
            inconsistent = True
    feats["ident_display_name_domain_inconsistency"] = 1.0 if inconsistent else 0.0

    # 5. Freemail / Disposable detection
    from_dom_clean = (from_domain or "").lower()
    feats["ident_freemail_sender"] = 1.0 if from_dom_clean in FREEMAIL_DOMAINS else 0.0
    feats["ident_disposable_sender"] = 1.0 if from_dom_clean in DISPOSABLE_DOMAINS else 0.0

    # 6. Executive / Role Spoofing Indicator
    role_spoof = False
    if any(role in dn_lower for role in ROLE_KEYWORDS):
        tld = from_dom_clean.rsplit(".", 1)[-1] if "." in from_dom_clean else ""
        if (
            from_dom_clean in FREEMAIL_DOMAINS
            or feats["ident_subdomain_depth"] > 1
            or feats["ident_from_reply_to_mismatch"] == 1.0
            or tld in {"xyz", "top", "icu", "club", "buzz", "click", "download"}
        ):
            role_spoof = True
    feats["ident_display_name_role_spoof"] = 1.0 if role_spoof else 0.0

    return feats, exps
