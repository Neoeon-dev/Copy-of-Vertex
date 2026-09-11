# VERTEX Forensic Tabular Model Card (v1.0.0)

## Model Overview
- **Model Type:** Multiclass LightGBM Classifier (LightGBM)
- **Calibration:** Uncalibrated probability scaling
- **Version:** `1.0.0`
- **Input Dimensions:** 125 canonical forensic features (11 forensic groups)
- **Target Classes:** `0: legitimate`, `1: spam`, `2: phishing`
- **Date Built:** 2026-09-06 14:23:06 UTC

## Intended Use & Forensic Scope
- **Primary Purpose:** Explainable forensic threat classification of enterprise and institutional emails.
- **Core Capability:** Differentiates high-consequence targeted phishing / BEC threats from commercial bulk spam and benign traffic.
- **Out of Scope:** Does not rely on remote external reputation lookups at inference time; all 125 features are computed deterministically from MIME RFC822 artifacts and parsed evidence.

## Validation Performance
- **Accuracy:** `0.9090`
- **Macro F1:** `0.9006`
- **Phishing F1:** `0.8828`
- **Phishing PR-AUC:** `0.9480`
- **Brier Score:** `0.1356`
- **Expected Calibration Error (ECE):** `0.0170`

## Test Set Performance (Unseen Test Split)
- **Test Samples:** `4547`
- **Accuracy:** `0.9202`
- **Macro F1:** `0.9124`
- **Weighted F1:** `0.9203`
- **Phishing Precision:** `0.8921`
- **Phishing Recall:** `0.8987`
- **Phishing F1:** `0.8954`
- **Phishing PR-AUC:** `0.9608`
- **Phishing ROC-AUC:** `0.9863`
- **Test Brier Score:** `0.1233`
- **Test Log Loss:** `0.2255`
- **Test ECE:** `0.0249`

## Holdout Independent Evaluation (Evaluated Strictly Once)
> [!IMPORTANT]
> Evaluated strictly once after all model selection and calibration decisions were finalized.
- **Holdout Samples:** `2000`
- **Holdout Accuracy:** `0.4040`
- **Holdout Macro F1:** `0.2877`
- **Holdout Phishing Recall:** `0.8080`
- **Holdout Phishing Precision:** `0.4469`
- **Holdout Phishing F1:** `0.5755`
- **Holdout Phishing PR-AUC:** `0.6885`
- **Holdout Brier Score:** `0.5252`
- **Holdout ECE:** `0.2154`

## Feature Group Ablation Summary
**Baseline (All 125 Features):** Macro F1 = 0.8898 | Phishing PR-AUC = 0.9371

| Rank | Feature Group | Features | Macro F1 Drop | Phishing PR-AUC Drop | Status |
|:----:|:--------------|:--------:|:-------------:|:--------------------:|:-------|
|  1   | content_structure    |    12    |        0.0681 |               0.0545 | Crucial       |
|  2   | message_basics       |    12    |        0.0401 |               0.0478 | Crucial       |
|  3   | url_signals          |    12    |        0.0179 |               0.0116 | Crucial       |
|  4   | domain_signals       |    11    |        0.0149 |               0.0068 | Crucial       |
|  5   | bec_phish_signals    |    12    |        0.0057 |               0.0045 | Significant   |
|  6   | identity_consistency |    10    |        0.0026 |               0.0003 | Significant   |
|  7   | header_signals       |    15    |        0.0007 |               0.0031 | Complementary |
|  8   | relay_path           |    12    |        0.0004 |              -0.0011 | Complementary |
|  9   | attachment_signals   |    9     |       -0.0007 |              -0.0012 | Complementary |
|  10  | authentication_signals |    12    |       -0.0010 |              -0.0026 | Complementary |
|  11  | ip_infrastructure    |    8     |       -0.0016 |              -0.0013 | Complementary |

## Source-Aware Breakdown (Test Set)
| Source Dataset | Samples | Accuracy | Macro F1 | Phishing Recall | Phishing Prec |
|:---------------|--------:|---------:|---------:|----------------:|--------------:|
| hf_seven_phishing/TREC-05 |    1084 |   0.9170 |   0.6202 |          0.0000 |        0.0000 |
| hf_seven_phishing/TREC-07 |    1021 |   0.9598 |   0.6457 |          0.0000 |        0.0000 |
| hf_seven_phishing/CEAS-08 |     707 |   0.9448 |   0.6442 |          0.9290 |        0.9905 |
| hf_seven_phishing/Enron |     550 |   0.8418 |   0.8418 |          0.8453 |        0.8423 |
| hf_seven_phishing/TREC-06 |     327 |   0.8777 |   0.5651 |          0.0000 |        0.0000 |
| zenodo_8339691/Nigerian_Fraud |     312 |   0.9327 |   0.3217 |          0.9327 |        1.0000 |
| spamassassin_public_corpus |     244 |   0.9918 |   0.9829 |          0.0000 |        0.0000 |
| zenodo_8339691/Nazario |     158 |   0.8608 |   0.3084 |          0.8608 |        1.0000 |
| hf_seven_phishing/Assassin |      88 |   0.8750 |   0.5704 |          0.0000 |        0.0000 |
| hf_seven_phishing/Ling |      56 |   0.8214 |   0.5316 |          0.0000 |        0.0000 |

## Recommended Operational Thresholds
- **Balanced Triage (F1 optimal):** Threshold = `0.50`
- **High-Recall SOC Queue:** Threshold = `0.05`
- **Autonomous Inline Block (FPR < 0.5%):** Threshold = `0.95`
