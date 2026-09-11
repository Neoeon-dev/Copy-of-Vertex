"""
Automated unit tests for Phase D3 Semantic NLP & Transformer pipeline.
Tests text preprocessing, tokenization, baselines, calibrations, leakages, and inference contracts.
"""
import os
import json
import pytest
import numpy as np
import torch
from transformers import AutoTokenizer

from app.ml.version import LABEL_TO_INT, INT_TO_LABEL, TARGET_CLASSES
from app.ml.semantic.preprocessor import EmailTextPreprocessor, SEMANTIC_PREPROCESSING_VERSION
from app.ml.semantic.tokenizer import (
    load_semantic_tokenizer,
    analyze_sequence_lengths,
    head_tail_truncate,
    TOKENIZER_VERSION,
    SPECIAL_TOKENS,
)
from app.ml.semantic.baseline import TfidfLogisticBaseline
from app.ml.semantic.dataset import EmailTextDataset, compute_class_weights_tensor
from app.ml.semantic.calibrator import TemperatureScalingCalibrator, compute_ece
from app.ml.semantic.evaluator import (
    evaluate_predictions,
    evaluate_short_text_robustness,
    evaluate_source_generalization,
    analyze_model_errors,
)


@pytest.fixture
def preprocessor():
    return EmailTextPreprocessor()


@pytest.fixture
def tokenizer():
    return load_semantic_tokenizer()


# 1. Tokenizer initialization & special tokens
def test_tokenizer_initialization(tokenizer):
    assert tokenizer is not None
    for token in SPECIAL_TOKENS:
        token_id = tokenizer.convert_tokens_to_ids(token)
        assert token_id != tokenizer.unk_token_id, f"Special token {token} not recognized"


# 2. Text preprocessing basic functionality
def test_preprocessing_basic(preprocessor):
    subj = "Test Subject"
    body = "Test email body content."
    res = preprocessor.format_email(subj, body)
    assert "[SUBJECT] Test Subject" in res
    assert "[BODY] Test email body content." in res


# 3. Unicode normalization (NFKC)
def test_unicode_normalization(preprocessor):
    # Full-width characters and ligatures
    text = "Ｔｅｓｔ ﬃ café"
    clean = preprocessor.clean_text(text)
    assert "Test" in clean
    assert "ffi" in clean
    assert "café" in clean


# 4. Empty subject handling
def test_empty_subject_handling(preprocessor):
    res_none = preprocessor.format_email(None, "Body here")
    res_empty = preprocessor.format_email("", "Body here")
    assert "[SUBJECT] [EMPTY]" in res_none
    assert "[SUBJECT] [EMPTY]" in res_empty


# 5. Empty body handling
def test_empty_body_handling(preprocessor):
    res_none = preprocessor.format_email("Subject here", None)
    res_empty = preprocessor.format_email("Subject here", "")
    assert "[BODY] [EMPTY]" in res_none
    assert "[BODY] [EMPTY]" in res_empty


# 6. Very short text handling (< 5 words)
def test_very_short_text_handling(preprocessor):
    short_body = "Hello please call."
    clean = preprocessor.clean_text(short_body)
    assert clean == "Hello please call."
    words = clean.split()
    assert len(words) < 5


# 7. Long text handling & truncation
def test_long_text_truncation(tokenizer):
    long_text = "word " * 500
    tokens = tokenizer.encode(long_text, max_length=128, truncation=True)
    assert len(tokens) <= 128


# 8. URL replacement and normalization
def test_url_replacement(preprocessor):
    text = "Check this out https://secure-bank.example.com/login and http://foo.org/bar?id=123"
    clean = preprocessor.clean_text(text)
    assert "https://secure-bank.example.com/login" not in clean
    assert "[URL]" in clean

    strip_prep = EmailTextPreprocessor(url_mode="strip")
    stripped = strip_prep.clean_text(text)
    assert "[URL]" not in stripped
    assert "http" not in stripped


# 9. HTML normalization & stripping
def test_html_normalization(preprocessor):
    html_text = "<html><head><style>body {color:red;}</style><script>alert(1);</script></head><body><h1>Hello</h1> &amp; welcome to &quot;our&quot; service</body></html>"
    clean = preprocessor.clean_text(html_text)
    assert "alert(1)" not in clean
    assert "color:red" not in clean
    assert "<h1>" not in clean
    assert "Hello & welcome to \"our\" service" in clean


# 10. Subject / Body combination modes
def test_subject_body_combination_modes(preprocessor):
    s = "Urgent Notice"
    b = "Please reset password"
    both = preprocessor.format_email(s, b, part_mode="both")
    subj_only = preprocessor.format_email(s, b, part_mode="subject_only")
    body_only = preprocessor.format_email(s, b, part_mode="body_only")

    assert "[SUBJECT]" in both and "[BODY]" in both
    assert "[SUBJECT]" in subj_only and "[BODY]" not in subj_only
    assert "[BODY]" in body_only and "[SUBJECT]" not in body_only


# 11. Label mapping contract
def test_label_mapping_contract():
    assert LABEL_TO_INT["legitimate"] == 0
    assert LABEL_TO_INT["spam"] == 1
    assert LABEL_TO_INT["phishing"] == 2
    assert INT_TO_LABEL[0] == "legitimate"
    assert INT_TO_LABEL[1] == "spam"
    assert INT_TO_LABEL[2] == "phishing"
    assert TARGET_CLASSES == ["legitimate", "spam", "phishing"]


# 12. Target leakage prevention
def test_target_leakage_prevention(preprocessor):
    text = "This is a legitimate message from enron with threat_type benign"
    clean = preprocessor.clean_text(text)
    # Ensure preprocessor doesn't inject target metadata
    assert "normalized_label" not in clean
    assert "source_dataset" not in clean


# 13. Probability validity & bounds
def test_probability_validity():
    y_true = np.array([0, 1, 2, 0])
    y_prob = np.array([
        [0.8, 0.1, 0.1],
        [0.05, 0.9, 0.05],
        [0.1, 0.1, 0.8],
        [0.7, 0.2, 0.1],
    ])
    metrics = evaluate_predictions(y_true, y_prob)
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert 0.0 <= metrics["macro_f1"] <= 1.0
    assert 0.0 <= metrics["brier_score"] <= 2.0
    assert 0.0 <= metrics["ece"] <= 1.0


# 14. Probability sum to 1.0
def test_probability_sum_constraint():
    logits = np.array([[2.0, 1.0, 0.1], [-1.0, 3.0, 0.5]])
    calibrator = TemperatureScalingCalibrator(temperature=1.5)
    probs = calibrator.predict_proba(logits)
    np.testing.assert_allclose(np.sum(probs, axis=1), [1.0, 1.0], rtol=1e-5)


# 15. TF-IDF Baseline model inference
def test_tfidf_baseline_fit_predict():
    texts = [
        "[SUBJECT] Meeting tomorrow [BODY] Let us sync at 10am.",
        "[SUBJECT] Cheap pharmacy pills [BODY] Buy now for huge discount!",
        "[SUBJECT] URGENT: Verify account [BODY] Your credentials have expired at [URL]",
    ]
    labels = np.array([0, 1, 2])
    model = TfidfLogisticBaseline(max_features=500)
    model.fit(texts, labels)
    preds = model.predict(texts)
    probs = model.predict_proba(texts)
    assert len(preds) == 3
    assert probs.shape == (3, 3)
    np.testing.assert_allclose(np.sum(probs, axis=1), [1.0, 1.0, 1.0], rtol=1e-5)


# 16. Calibrator serialization and temperature scaling
def test_calibrator_fit_and_serialization(tmp_path):
    calibrator = TemperatureScalingCalibrator()
    logits = np.array([[3.0, 0.5, -1.0], [0.1, 2.5, 0.0], [-0.5, 0.2, 3.1]])
    labels = np.array([0, 1, 2])
    calibrator.fit(logits, labels)
    assert calibrator.temperature > 0.0

    save_path = str(tmp_path / "temperature.json")
    calibrator.save(save_path)
    loaded = TemperatureScalingCalibrator.load(save_path)
    assert loaded.temperature == calibrator.temperature
    assert loaded.is_fitted == calibrator.is_fitted


# 17. Sequence length analysis statistics
def test_analyze_sequence_lengths(tokenizer):
    texts = ["Short email", "A slightly longer email with several tokens to tokenize"]
    stats = analyze_sequence_lengths(texts, tokenizer, max_lengths=[4, 8, 16])
    assert stats["sample_count"] == 2
    assert "mean_length" in stats
    assert "truncation_rates" in stats
    assert "4" in stats["truncation_rates"]


# 18. Head-tail truncation logic
def test_head_tail_truncate():
    input_ids = list(range(100))  # 100 tokens
    truncated = head_tail_truncate(input_ids, max_length=20, cls_token_id=101, sep_token_id=102)
    assert len(truncated) == 20
    assert truncated[0] == 101
    assert truncated[-1] == 102


# 19. Short-text stress test metrics calculation
def test_short_text_stress_test():
    bodies = ["Hi", "Meeting at noon today please attend", "This is a much longer message with plenty of text " * 5]
    y_true = np.array([0, 0, 1])
    y_prob = np.array([
        [0.8, 0.1, 0.1],
        [0.9, 0.05, 0.05],
        [0.1, 0.8, 0.1],
    ])
    results = evaluate_short_text_robustness(bodies, y_true, y_prob)
    assert "<5" in results
    assert ">50" in results
    assert results["<5"]["count"] == 1


# 20. Source-aware generalization evaluation
def test_source_aware_evaluation():
    sources = ["source_a", "source_a", "source_b"]
    y_true = np.array([0, 1, 2])
    y_prob = np.array([
        [0.8, 0.1, 0.1],
        [0.1, 0.8, 0.1],
        [0.1, 0.1, 0.8],
    ])
    res = evaluate_source_generalization(sources, y_true, y_prob)
    assert "source_a" in res
    assert "source_b" in res
    assert res["source_a"]["sample_count"] == 2
    assert res["source_b"]["sample_count"] == 1


# 21. Preprocessing determinism
def test_preprocessing_determinism(preprocessor):
    raw = "Subject: Urgent!!!\n\nClick https://example.com/login now & win $100."
    res1 = preprocessor.clean_text(raw)
    res2 = preprocessor.clean_text(raw)
    assert res1 == res2


# 22. Error analysis and case studies
def test_model_error_analysis():
    texts = ["text1", "text2"]
    record_ids = ["rec1", "rec2"]
    sources = ["src1", "src2"]
    y_true = np.array([0, 2])
    y_prob = np.array([
        [0.2, 0.1, 0.7],  # Legit predicted as Phishing (error)
        [0.1, 0.1, 0.8],  # Phish predicted as Phishing (correct)
    ])
    analysis = analyze_model_errors(texts, record_ids, sources, y_true, y_prob)
    assert analysis["overall_summary"]["correct_count"] == 1
    assert analysis["overall_summary"]["incorrect_count"] == 1
    assert analysis["error_quadrants"]["legitimate_to_phishing"]["count"] == 1


# 23. Class weights tensor calculation
def test_class_weights_calculation():
    labels = np.array([0, 0, 0, 1, 2])
    weights = compute_class_weights_tensor(labels, num_classes=3)
    assert len(weights) == 3
    assert weights[1] > weights[0]
    assert weights[2] > weights[0]


# 24. Preprocessor config provenance
def test_preprocessor_config_provenance(preprocessor):
    cfg = preprocessor.get_config()
    assert cfg["version"] == SEMANTIC_PREPROCESSING_VERSION
    assert cfg["url_mode"] == "replace"
    assert cfg["strip_html"] is True
