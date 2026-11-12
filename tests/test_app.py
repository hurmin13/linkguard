"""Headless tests for the three demo flows without browser or site requests."""

from pathlib import Path

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]


def app():
    return AppTest.from_file(str(ROOT / "app.py"), default_timeout=30).run()


def test_message_inspection_and_domain_comparison():
    at = app()
    assert not at.exception
    at.text_area(key="input_text").input(
        "안내 https://example.org/notice\n확인 https://example.org.login-check.example.com/auth"
    )
    at.text_input(key="expected_domain").input("example.org")
    at.button(key="analyze").click().run()
    assert not at.exception
    rows = at.session_state["results"]
    assert len(rows) == 2
    assert [row["domain_match"] for row in rows] == ["일치", "불일치"]
    assert all(row["score"] is not None for row in rows)
    assert all(row["error"] is None for row in rows)


def test_changed_input_and_clear_remove_stale_results():
    at = app()
    at.text_area(key="input_text").input("https://example.org/")
    at.button(key="analyze").click().run()
    assert at.session_state["results"]
    at.text_area(key="input_text").input("https://example.com/").run()
    assert at.session_state["results"] == []
    at.button(key="analyze").click().run()
    at.button(key="clear").click().run()
    assert not at.exception
    assert at.text_area(key="input_text").value == ""
    assert at.text_input(key="expected_domain").value == ""
    assert at.session_state["results"] == []


def test_invalid_input_is_not_presented_as_safe():
    at = app()
    at.text_area(key="input_text").input("javascript:alert(1)")
    at.button(key="analyze").click().run()
    assert not at.exception
    row = at.session_state["results"][0]
    assert row["verdict"] == "분석 불가"
    assert row["score"] is None


def test_builtin_table_csv_cannot_export_an_active_formula():
    at = app()
    at.text_area(key="input_text").input("=1+1")
    at.button(key="analyze").click().run()
    assert not at.exception
    table = at.tabs[0].dataframe[0].value
    assert table.iloc[0]["입력 URL"] == "'=1+1"
    assert at.session_state["results"][0]["input_url"] == "=1+1"


def test_sensitivity_changes_validation_not_frozen_test_metrics():
    at = app()
    fixed = [(m.label, m.value) for m in at.tabs[1].metric[:4]]
    at.slider(key="eval_threshold").set_value(0.1).run()
    assert not at.exception
    low = [m.value for m in at.tabs[1].metric[8:11]]
    assert [(m.label, m.value) for m in at.tabs[1].metric[:4]] == fixed
    at.slider(key="eval_threshold").set_value(0.9).run()
    high = [m.value for m in at.tabs[1].metric[8:11]]
    assert not at.exception
    assert [(m.label, m.value) for m in at.tabs[1].metric[:4]] == fixed
    assert low != high
