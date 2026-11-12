"""Classification, independent domain observations, and no-fetch guarantees."""

import socket
import urllib.request

import pytest

import linkguard.model as model
from linkguard.service import analyze_text


@pytest.fixture
def fixed_model(monkeypatch):
    monkeypatch.setattr(model, "load_model", lambda: {"test_fixture": True})
    monkeypatch.setattr(model, "predict_score", lambda features, bundle, domain_text=None: 0.6)


def test_domain_mismatch_is_independent_of_ml_classification(fixed_model):
    url = "https://example.org.login-check.example.com/auth"
    low = analyze_text(url, "example.org", threshold=0.7)[0]
    high = analyze_text(url, "example.org", threshold=0.5)[0]
    assert low["score"] == high["score"] == 0.6
    assert low["verdict"] == "낮은 의심"
    assert high["verdict"] == "의심"
    assert low["domain_match"] == high["domain_match"] == "불일치"


def test_threshold_boundary_is_inclusive(fixed_model):
    assert analyze_text("https://example.org", threshold=0.6)[0]["verdict"] == "의심"


def test_invalid_url_does_not_hide_valid_result(fixed_model):
    rows = analyze_text("https://example.org/notice https://example.org:99999/")
    assert rows[0]["error"] is None
    assert rows[0]["score"] == 0.6
    assert rows[1]["verdict"] == "분석 불가"
    assert rows[1]["score"] is None
    assert rows[1]["error"]


def test_missing_model_keeps_domain_information(monkeypatch):
    def missing():
        raise FileNotFoundError("No local artifact")

    monkeypatch.setattr(model, "load_model", missing)
    row = analyze_text("https://example.org/", "example.org")[0]
    assert row["host"] == "example.org"
    assert row["domain_match"] == "일치"
    assert row["score"] is None
    assert row["verdict"] == "분석 불가"
    assert row["error"]


@pytest.mark.parametrize("threshold", [-0.1, 1.1, float("nan"), float("inf")])
def test_invalid_threshold_is_rejected(threshold):
    with pytest.raises(ValueError):
        analyze_text("https://example.org/", threshold=threshold)


def test_inference_never_resolves_or_fetches_input_url(monkeypatch, fixed_model):
    def no_network(*args, **kwargs):
        raise AssertionError("URL inspection attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(urllib.request, "urlopen", no_network)
    rows = analyze_text("https://example.org/login https://bit.ly/demo", "example.org")
    assert len(rows) == 2
    assert all(row["error"] is None for row in rows)
    assert any("최종 목적지" in value for value in rows[1]["limitations"])


def test_userinfo_explanation_names_actual_host(fixed_model):
    row = analyze_text("https://example.org@notice.example.com/", "example.org")[0]
    assert row["host"] == "notice.example.com"
    assert row["domain_match"] == "불일치"
    assert any("@ 뒤" in value for value in row["observations"])
