"""
Feature Group 3: Cryptographic Authentication Signals (SPF, DKIM, DMARC).
Translates cryptographic and policy evaluations into deterministic,
calibrated numerical features without inventing absent data.
"""
from typing import Dict, Any, Tuple, Optional
from app.features.schema import (
    SPF_RESULT_ENCODING,
    DKIM_RESULT_ENCODING,
    DMARC_RESULT_ENCODING,
    DMARC_POLICY_ENCODING,
    ALIGNMENT_ENCODING,
)


def extract_authentication_signals(
    auth_results: Optional[Dict[str, Any]] = None,
    raw_evidence_available: bool = False,
) -> Tuple[Dict[str, float], Dict[str, str]]:
    """
    Extracts structured authentication telemetry.
    Distinguishes 'none' (not configured) from 'fail' (configured and rejected).
    """
    feats: Dict[str, float] = {}
    exps: Dict[str, str] = {}

    if not raw_evidence_available or not auth_results:
        # Explicit missing values when authentication evidence was not evaluated
        feats["auth_spf_result"] = SPF_RESULT_ENCODING["unknown"]
        feats["auth_spf_pass"] = -1.0
        feats["auth_spf_fail"] = -1.0

        feats["auth_dkim_result"] = DKIM_RESULT_ENCODING["unknown"]
        feats["auth_dkim_pass"] = -1.0
        feats["auth_dkim_fail"] = -1.0
        feats["auth_dkim_signature_count"] = -1.0
        feats["auth_dkim_body_hash_failure"] = -1.0

        feats["auth_dmarc_result"] = DMARC_RESULT_ENCODING["unknown"]
        feats["auth_dmarc_pass"] = -1.0
        feats["auth_dmarc_policy"] = DMARC_POLICY_ENCODING["unknown"]
        feats["auth_alignment_dmarc"] = ALIGNMENT_ENCODING["unknown"]
        return feats, exps

    # 1. SPF Evaluation
    spf = auth_results.get("spf", {})
    spf_res_str = str(spf.get("result", "none")).lower()
    feats["auth_spf_result"] = SPF_RESULT_ENCODING.get(spf_res_str, SPF_RESULT_ENCODING["unknown"])
    if spf_res_str == "pass":
        feats["auth_spf_pass"] = 1.0
        feats["auth_spf_fail"] = 0.0
    elif spf_res_str in ("fail", "softfail", "permerror"):
        feats["auth_spf_pass"] = 0.0
        feats["auth_spf_fail"] = 1.0
    elif spf_res_str in ("none", "neutral"):
        feats["auth_spf_pass"] = 0.0
        feats["auth_spf_fail"] = 0.0
    else:
        feats["auth_spf_pass"] = -1.0
        feats["auth_spf_fail"] = -1.0

    # 2. DKIM Evaluation
    dkim = auth_results.get("dkim", {})
    dkim_res_str = str(dkim.get("status", dkim.get("result", "none"))).lower()
    feats["auth_dkim_result"] = DKIM_RESULT_ENCODING.get(dkim_res_str, DKIM_RESULT_ENCODING["unknown"])
    if dkim_res_str == "pass":
        feats["auth_dkim_pass"] = 1.0
        feats["auth_dkim_fail"] = 0.0
    elif dkim_res_str in ("fail", "permerror"):
        feats["auth_dkim_pass"] = 0.0
        feats["auth_dkim_fail"] = 1.0
    elif dkim_res_str in ("none", "neutral"):
        feats["auth_dkim_pass"] = 0.0
        feats["auth_dkim_fail"] = 0.0
    else:
        feats["auth_dkim_pass"] = -1.0
        feats["auth_dkim_fail"] = -1.0

    feats["auth_dkim_signature_count"] = float(dkim.get("signature_count", 1 if dkim.get("signatures") else 0))
    feats["auth_dkim_body_hash_failure"] = 1.0 if "body hash mismatch" in str(dkim.get("reason", "")).lower() else 0.0

    # 3. DMARC Evaluation
    dmarc = auth_results.get("dmarc", {})
    dmarc_res_str = str(dmarc.get("status", dmarc.get("result", "none"))).lower()
    feats["auth_dmarc_result"] = DMARC_RESULT_ENCODING.get(dmarc_res_str, DMARC_RESULT_ENCODING["unknown"])
    feats["auth_dmarc_pass"] = 1.0 if dmarc_res_str == "pass" else (0.0 if dmarc_res_str == "fail" else -1.0)

    policy_str = str(dmarc.get("policy", "none")).lower()
    feats["auth_dmarc_policy"] = DMARC_POLICY_ENCODING.get(policy_str, DMARC_POLICY_ENCODING["unknown"])

    alignment = dmarc.get("alignment", {})
    spf_aligned = alignment.get("spf_aligned", False)
    dkim_aligned = alignment.get("dkim_aligned", False)
    if spf_aligned and dkim_aligned:
        feats["auth_alignment_dmarc"] = ALIGNMENT_ENCODING["strict_pass"]
    elif spf_aligned or dkim_aligned:
        feats["auth_alignment_dmarc"] = ALIGNMENT_ENCODING["relaxed_pass"]
    elif dmarc_res_str != "none":
        feats["auth_alignment_dmarc"] = ALIGNMENT_ENCODING["fail"]
    else:
        feats["auth_alignment_dmarc"] = ALIGNMENT_ENCODING["none"]

    return feats, exps
