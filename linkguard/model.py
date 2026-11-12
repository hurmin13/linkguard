"""Inference for checked-in JSON models; no pickle loading or outbound network."""
from __future__ import annotations

import json
import math
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Mapping

MODEL_PATH = Path(__file__).resolve().parents[1] / "artifacts" / "model.json"


@lru_cache(maxsize=1)
def load_model() -> dict:
    """Load the bundled portable model. Never accepts arbitrary uploaded models."""
    bundle = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    if bundle.get("format_version") != 1:
        raise ValueError("Unsupported model format")
    if bundle.get("model_type") not in {"logistic_regression", "random_forest", "char_ngram_logistic"}:
        raise ValueError("Unsupported model type")
    if not bundle.get("feature_names"):
        raise ValueError("Model has no features")
    from .features import FEATURE_NAMES, FEATURE_VERSION
    if bundle["feature_names"] != list(FEATURE_NAMES):
        raise ValueError("Model and feature schema do not match; retrain the model")
    if bundle.get("metadata", {}).get("feature_version") != FEATURE_VERSION:
        raise ValueError("Model and feature versions do not match; retrain the model")
    return bundle


def predict_score(feature_dict: Mapping[str, float], bundle: dict | None = None,
                  domain_text: str | None = None) -> float:
    """Return the classifier's phishing score (not a calibrated real-world probability)."""
    bundle = load_model() if bundle is None else bundle
    parameters = bundle["parameters"]
    if bundle["model_type"] == "char_ngram_logistic":
        if not isinstance(domain_text, str) or not domain_text or len(domain_text) > 253:
            raise ValueError("Registered domain text is required for this model")
        domain = domain_text.lower()
        if not domain.isascii() or any(c.isspace() for c in domain):
            raise ValueError("Domain text must be normalized ASCII without whitespace")
        lower, upper = parameters["ngram_range"]
        counts = Counter(domain[start:start + width] for width in range(lower, upper + 1)
                         for start in range(len(domain) - width + 1))
        vocabulary = parameters["vocabulary"]
        weighted = []
        for token, count in counts.items():
            index = vocabulary.get(token)
            if index is not None:
                tf = 1.0 + math.log(count) if parameters["sublinear_tf"] else float(count)
                weighted.append((index, tf * parameters["idf"][index]))
        norm = math.sqrt(sum(weight * weight for _, weight in weighted))
        logit = parameters["intercept"]
        if norm:
            logit += sum(parameters["coef"][index] * weight / norm for index, weight in weighted)
        if logit >= 0:
            return 1.0 / (1.0 + math.exp(-logit))
        exp_logit = math.exp(logit)
        return exp_logit / (1.0 + exp_logit)
    features = [float(feature_dict[name]) for name in bundle["feature_names"]]
    if not all(math.isfinite(value) for value in features):
        raise ValueError("Features must all be finite")
    if bundle["model_type"] == "logistic_regression":
        logit = parameters["intercept"] + sum(
            ((value - mean) / scale) * coefficient
            for value, mean, scale, coefficient in zip(
                features, parameters["mean"], parameters["scale"], parameters["coef"], strict=True
            )
        )
        if logit >= 0:
            return 1.0 / (1.0 + math.exp(-logit))
        exp_logit = math.exp(logit)
        return exp_logit / (1.0 + exp_logit)
    if bundle["model_type"] == "random_forest":
        # sklearn's tree predictor casts observations to float32 before comparing.
        import struct
        features = [struct.unpack("f", struct.pack("f", value))[0] for value in features]
        scores = []
        for tree in parameters["trees"]:
            index = 0
            while tree["left"][index] != -1:
                feature_index = tree["feature"][index]
                index = (tree["left"][index] if features[feature_index] <= tree["threshold"][index]
                         else tree["right"][index])
            scores.append(tree["phishing_probability"][index])
        if not scores:
            raise ValueError("Model contains no trees")
        return sum(scores) / len(scores)
    raise ValueError("Unsupported model type")


def model_info() -> dict:
    """Return report metadata and the frozen default decision threshold."""
    return load_model()["metadata"]
