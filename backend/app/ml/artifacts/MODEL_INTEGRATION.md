# Forensic ML Runtime

VERTEX currently integrates the teammate-trained **Forensic Tabular LightGBM** model only.

## Runtime contract

- 125 canonical forensic features are extracted from the email evidence.
- Classes: `legitimate`, `spam`, `phishing`.
- The API returns class probabilities, confidence, a 0-1 model risk score, model version, feature count, latency, and the highest-gain active features.
- Feature importance is training gain. It is not a causal explanation or SHAP attribution.
- The model metadata selects **uncalibrated** probability outputs; the UI does not call them calibrated probabilities.
- The separate semantic transformer and fusion artifacts are intentionally not enabled in this deployment yet.

## Artifact integrity

The model files in this directory are the runtime copies used by the backend Docker image:

- `lightgbm_model.pkl`
- `calibrated_model.pkl` (same model bytes; retained for compatibility with the training layout)
- `feature_importances.json`
- `metadata.json`
