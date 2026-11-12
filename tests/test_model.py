"""Portable inference parity and the checked-in evaluation audit."""

import hashlib
import json
from pathlib import Path

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from linkguard.features import FEATURE_NAMES, extract_features
from linkguard.model import load_model, predict_score
from linkguard.urltools import parse_url
from scripts.train import classification_metrics, export_model

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("kind", ["logistic_regression", "random_forest"])
def test_portable_json_matches_sklearn_on_unseen_rows(kind):
    rng = np.random.default_rng(231)
    X = rng.normal(size=(120, len(FEATURE_NAMES)))
    y = (X[:, 0] + X[:, 1] * 0.4 > 0).astype(int)
    estimator = (
        make_pipeline(StandardScaler(), LogisticRegression())
        if kind == "logistic_regression"
        else RandomForestClassifier(n_estimators=9, max_depth=4, random_state=42)
    )
    estimator.fit(X[:90], y[:90])
    bundle = json.loads(json.dumps(export_model(estimator, kind, {})))
    actual = [predict_score(dict(zip(FEATURE_NAMES, row, strict=True)), bundle) for row in X[90:]]
    np.testing.assert_allclose(actual, estimator.predict_proba(X[90:])[:, 1], atol=1e-12, rtol=0)


@pytest.mark.parametrize("sublinear_tf", [False, True])
def test_portable_character_model_matches_tfidf_on_unseen_and_repeated_ngrams(sublinear_tf):
    # Synthetic labels exercise serialization only; they are not evaluation data.
    train_domains = [
        "alpha.example", "beta.example", "gamma.example", "delta.example",
        "aaaaa.example", "ababa.example", "verify-111.example", "login-222.example",
    ]
    estimator = make_pipeline(
        TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=1,
                        sublinear_tf=sublinear_tf, norm="l2", lowercase=True),
        LogisticRegression(C=4.0, random_state=42),
    )
    estimator.fit(train_domains, [0, 0, 0, 0, 1, 1, 1, 1])
    bundle = json.loads(json.dumps(export_model(estimator, "char_ngram_logistic", {})))
    unseen = ["aaaaaaa.example", "ababa-111.example", "ALPHA.EXAMPLE", "zzzzz.zz", "xn--bcher-kva.de"]
    assert estimator.steps[0][1].transform(["zzzzz.zz"]).nnz == 0
    actual = [predict_score({}, bundle, domain_text=value) for value in unseen]
    np.testing.assert_allclose(actual, estimator.predict_proba(unseen)[:, 1], atol=1e-12, rtol=0)
    with pytest.raises(ValueError, match="domain text is required"):
        predict_score({}, bundle)


def test_confusion_matrix_uses_phishing_as_positive():
    metrics = classification_metrics(np.array([0, 0, 1, 1]), np.array([0.1, 0.8, 0.2, 0.9]), 0.5)
    assert (metrics["tn"], metrics["fp"], metrics["fn"], metrics["tp"]) == (1, 1, 1, 1)
    assert metrics["fpr"] == metrics["precision"] == metrics["recall"] == metrics["f1"] == 0.5


def test_bundled_model_accepts_current_feature_schema():
    bundle = load_model()
    assert bundle["feature_names"] == FEATURE_NAMES
    score = predict_score(extract_features("https://example.org/login"), bundle, domain_text="example.org")
    assert 0 <= score <= 1


def test_bundled_score_is_invariant_to_same_domain_url_format_changes():
    urls = [
        "https://example.org", "http://example.org", "https://www.example.org/",
        "https://example.org/login?next=home", "https://account@example.org:8443/#token",
    ]
    scores = [
        predict_score(extract_features(value), domain_text=parse_url(value)["registered_domain"])
        for value in urls
    ]
    assert max(scores) - min(scores) < 1e-12


def test_evaluation_artifacts_preserve_split_and_selection_integrity():
    metrics = json.loads((ROOT / "artifacts" / "metrics.json").read_text())
    curve = json.loads((ROOT / "artifacts" / "threshold_curve.json").read_text())
    bundle = load_model()
    assert metrics["selection"]["test_used_for_selection"] is False
    assert all(count == 0 for count in metrics["split"]["domain_overlap"].values())
    assert sum(metrics["split"][part]["rows"] for part in ("train", "validation", "test")) == metrics["preprocessing"]["usable_rows"]
    for part in ("train", "validation", "test"):
        split = metrics["split"][part]
        assert split["rows"] == split["legitimate"] + split["phishing"]
        assert split["legitimate"] > 0 and split["phishing"] > 0
    assert curve["dataset"] == "validation"
    assert curve["model"] == bundle["model_type"] == metrics["selection"]["model"]
    assert bundle["metadata"]["threshold"] == metrics["selection"]["threshold"]
    for row in curve["rows"]:
        assert sum(row[k] for k in ("tp", "fp", "tn", "fn")) == metrics["split"]["validation"]["rows"]
    assert metrics["export_validation"]["classes_checked"] == [0, 1]
    assert metrics["export_validation"]["max_absolute_score_difference"] < 1e-10


def test_model_report_was_generated_with_current_feature_extractor():
    metrics = json.loads((ROOT / "artifacts" / "metrics.json").read_text())
    # urltools also contains comparison-only policy that can change independently
    # of the model. Its full-file training hash is provenance, not a runtime lock.
    for name in ("features",):
        actual = hashlib.sha256((ROOT / "linkguard" / f"{name}.py").read_bytes()).hexdigest()
        assert actual == metrics["source_fingerprints"][f"{name}_sha256"], "Re-train after changing preprocessing"
