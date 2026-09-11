# VERTEX Forensic Feature Engineering Engine

**Version:** 1.0.0  
**Status:** Production-Ready (Phase D1)  
**Smart India Hackathon 2026 — SIH26106**

---

## 1. Overview

The VERTEX Forensic Feature Engineering Engine translates raw email evidence (.eml bytes), MIME trees, security headers, cryptographic proofs (SPF, DKIM, DMARC), transit relay hops, IP intelligence, domain lookalikes, URL topologies, attachment metadata, textual stylometry, and Business Email Compromise (BEC) semantic cues into a strictly versioned, auditable, deterministic numeric feature vector.

This engine establishes the deterministic feature foundation for subsequent machine learning models (LightGBM, XGBoost, and neural classifiers) while ensuring:
- **Zero Target Leakage:** Targets (`normalized_label`, `threat_type`, `source_dataset`, `original_label`) are strictly quarantined in metadata and never exposed as ML signals.
- **Explicit Missing Value Handling:** Unobserved evidence or missing fields are explicitly assigned calibrated defaults (e.g. `-1.0` for missing cryptographic/relay telemetry), completely avoiding `NaN` or infinite values.
- **Offline Reliability:** All features are extracted using local heuristics, regex patterns, and local databases (e.g., GeoLite2) without making live network requests.
- **Dual Input Support:** Seamlessly extracts full forensic depth from raw RFC-822 bytes or falls back gracefully to structured tabular records.

---

## 2. Feature Groups Summary

The engine registers **125 deterministic forensic features** across **11 specialized groups**:

| Group ID | Name | Feature Count | Primary Telemetry Measured |
|---|---|---|---|
| **1** | `message_basics` | 12 | Subject/body lengths, word/line counts, HTML/plain flags, MIME part and header counts |
| **2** | `header_signals` | 15 | RFC 5322 mandatory header presence, security headers, mailer tokens, duplicate header injection |
| **3** | `authentication_signals` | 12 | SPF result/pass/fail, DKIM status/pass/fail/signatures, DMARC verdict/policy/alignment |
| **4** | `identity_consistency` | 10 | Display name analysis, From vs Reply-To / Return-Path domain mismatches, PSL root alignment, freemail/disposable sender, executive role spoofing |
| **5** | `relay_path` | 12 | Received hop count, unique/IPv4/IPv6/private/public IP counts, transit delays, timestamp ordering anomalies |
| **6** | `ip_infrastructure` | 8 | Originating IP presence, private/public status, version (v4/v6), ASN/Org/Country resolution, cloud hosting footprint, attribution confidence |
| **7** | `domain_signals` | 11 | Sender domain length, label count, subdomain depth, digit/hyphen counts, punycode (`xn--`), suspicious TLDs, ccTLDs, homoglyphs, Shannon entropy |
| **8** | `url_signals` | 12 | URL counts, HTTP vs HTTPS, IP literal URLs, max/avg lengths, query/port/userinfo presence, shortener detection, suspicious TLDs |
| **9** | `attachment_signals` | 9 | Attachment counts, executable/archive/script/macro extensions, double extensions, MIME type mismatches, max size, RFC 822 wrappers |
| **10** | `content_structure` | 12 | Uppercase/digit/punctuation ratios, exclamation/question counts, currency symbols, excessive capitalization, repeated characters, hidden CSS text, unicode anomalies |
| **11** | `bec_phish_signals` | 12 | Urgency score, credential harvesting cues, wire transfer / payment requests, account verification cues, secrecy commands, banking changes, gift card requests, invoice terms, executive titles |

**Total Registered Features:** 125 features

---

## 3. Architecture & Directory Structure

```
backend/app/features/
├── __init__.py           # Package exports
├── version.py            # FORENSIC_FEATURE_VERSION = "1.0.0"
├── schema.py             # FeatureDefinition, FeatureVector, and categorical encodings
├── registry.py           # Canonical FEATURE_REGISTRY and helper query functions
├── validators.py         # Leakage detection, NaN checks, and schema validation
├── extractor.py          # ForensicFeatureExtractor unified orchestrator
├── cli.py                # Batch feature extraction CLI and quality reporting
└── groups/
    ├── __init__.py
    ├── message_basics.py
    ├── header_signals.py
    ├── authentication_signals.py
    ├── identity_consistency.py
    ├── relay_path.py
    ├── ip_infrastructure.py
    ├── domain_signals.py
    ├── url_signals.py
    ├── attachment_signals.py
    ├── content_structure.py
    └── bec_phish_signals.py
```

---

## 4. Usage

### Python API

```python
from app.features import ForensicFeatureExtractor

extractor = ForensicFeatureExtractor()

# Extract from raw .eml RFC822 bytes:
with open("sample.eml", "rb") as f:
    raw_bytes = f.read()
vector = extractor.extract_from_raw_bytes(raw_bytes, record_id="sample_01")

# Or extract from a canonical record / dictionary:
record = {
    "record_id": "rec_123",
    "source_dataset": "corpus",
    "subject": "Urgent wire transfer",
    "body": "Please process payment immediately.",
    "sender": "ceo@spoofed-domain.xyz",
    "normalized_label": "phishing",
}
vector = extractor.extract_from_canonical_record(record)

# Access pure numeric features (guaranteed zero target leakage):
numeric_features = vector.get_features_only()
print(f"Extracted {len(numeric_features)} features.")
```

### Batch CLI

```bash
# Extract features across all dataset splits (train, val, test, holdout)
PYTHONPATH=backend python3 -m app.features.cli --split all --workers 4

# Export schema definition JSON
python3 -c "from app.features import export_feature_schema_json; print(export_feature_schema_json())"
```

---

## 5. Quality Assurance

Every feature vector satisfies:
1. **Schema Adherence:** Exact match with `FEATURE_REGISTRY`.
2. **Numeric Cleanliness:** Zero `NaN`, `Inf`, or `null` values.
3. **No Target Leakage:** Targets (`normalized_label`, `threat_type`) strictly quarantined in `FeatureVector` metadata.
4. **Offline Execution:** Zero external network calls.
