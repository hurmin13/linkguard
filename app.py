"""LinkGuard: Korean URL inspection and model evaluation interface.

Run from the repository root: python -m streamlit run app.py
"""

from __future__ import annotations

import csv
import io
from html import escape
import json
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"

st.set_page_config(
    page_title="LinkGuard · 피싱 URL 검사",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown("<style>" + (ROOT / "assets" / "theme.css").read_text(encoding="utf-8") + "</style>", unsafe_allow_html=True)


def markup(content: str) -> None:
    """Render trusted layout markup. Escape all variable text before calling."""
    st.markdown("".join(line.strip() for line in content.splitlines()), unsafe_allow_html=True)


def domain_markup(host: str, registered: str) -> str:
    """Highlight only an actual DNS-label suffix; supplied host text stays inert."""
    if registered and (host == registered or host.endswith("." + registered)):
        prefix = host[:-len(registered)]
        return (f'<span class="lg-domain-prefix">{escape(prefix)}</span>'
                f'<span class="lg-domain-registered">{escape(registered)}</span>')
    return f'<span class="lg-domain-prefix">{escape(host)}</span>'


def render_domain_guide() -> None:
    markup('''<aside class="lg-aside">
      <div class="lg-aside-label">주소를 읽는 법</div>
      <h3>익숙한 이름보다,<br>실제 도메인을 확인하세요.</h3>
      <p>주소 앞에 서비스 이름이 있어도<br>다른 사이트로 연결될 수 있어요.</p>
      <div class="lg-domain-demo">
        <div class="lg-example">구조 설명용 예시</div>
        <div class="lg-domain-text"><span class="lg-domain-prefix">example.org.login-check.</span><span class="lg-domain-registered">example.com</span></div>
        <div class="lg-domain-caption">실제 등록 도메인 · example.com</div>
      </div>
      <ul class="lg-scope-list">
        <li><span class="lg-scope-number">01</span><div><strong>문자에서 링크만 추출</strong><small>한 번에 최대 30개 주소를 확인합니다.</small></div></li>
        <li><span class="lg-scope-number">02</span><div><strong>점수와 도메인을 함께 비교</strong><small>낮은 점수여도 도메인은 다를 수 있어요.</small></div></li>
        <li><span class="lg-scope-number">03</span><div><strong>대상 페이지에 접속하지 않음</strong><small>주소 문자열을 분석하며 웹페이지 내용은 확인하지 않습니다.</small></div></li>
      </ul>
    </aside>''')



def read_artifact(name: str) -> dict[str, Any]:
    """Only read bundled metadata; no user-supplied paths are accepted."""
    try:
        value = json.loads((ARTIFACTS / name).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def get_model_info() -> dict[str, Any]:
    try:
        from linkguard.model import model_info

        value = model_info()
        return value if isinstance(value, dict) else {}
    except (ImportError, OSError, ValueError, KeyError, TypeError):
        return {}


def safe_number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
        return number if pd.notna(number) else default
    except (TypeError, ValueError):
        return default


def percentage(value: Any) -> str:
    return f"{safe_number(value) * 100:.1f}%"


def model_name(key: str) -> str:
    return {
        "logistic_regression": "로지스틱 회귀",
        "random_forest": "랜덤 포레스트",
        "char_ngram_logistic": "도메인 문자 n-gram 로지스틱 회귀",
    }.get(str(key), str(key) or "확인 중")


def set_example(kind: str) -> None:
    examples = {
        "single": ("https://example.org/notice", "example.org"),
        "domain": (
            "https://example.org.login-check.example.com/auth",
            "example.org",
        ),
        "message": (
            "[예시 안내] 공지사항을 확인해 주세요.\n"
            "https://example.org/notice\n"
            "계정 확인 안내: https://example.org.login-check.example.com/auth",
            "example.org",
        ),
    }
    st.session_state["input_text"], st.session_state["expected_domain"] = examples[kind]
    st.session_state["results"] = []
    st.session_state["sample_loaded"] = True
    st.session_state.pop("last_request", None)


def clear_input() -> None:
    st.session_state["input_text"] = ""
    st.session_state["expected_domain"] = ""
    st.session_state["results"] = []
    st.session_state["sample_loaded"] = False
    st.session_state.pop("last_request", None)


def invalidate_results() -> None:
    """Never show a previous inspection as though it belongs to edited input."""
    st.session_state["results"] = []
    st.session_state["sample_loaded"] = False
    st.session_state.pop("last_request", None)


def safe_csv_cell(value: Any) -> str:
    """Prevent spreadsheet formula execution when opening an exported CSV."""
    text = "" if value is None else str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def result_csv(results: list[dict[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["입력 URL", "호스트", "등록 가능 도메인", "모델 의심 점수", "모델 분류", "도메인 비교", "관찰 내용", "오류"])
    for row in results:
        score = row.get("score")
        writer.writerow([
            safe_csv_cell(row.get("input_url", "")),
            safe_csv_cell(row.get("host", "")),
            safe_csv_cell(row.get("registered_domain", "")),
            "" if score is None else f"{safe_number(score):.6f}",
            safe_csv_cell(row.get("verdict", "")),
            safe_csv_cell(row.get("domain_match", "")),
            safe_csv_cell(" / ".join(row.get("observations", []))),
            safe_csv_cell(row.get("error", "")),
        ])
    return output.getvalue().encode("utf-8-sig")


def render_result_details(row: dict[str, Any], index: int, *, expanded: bool = False) -> None:
    # The expander title contains no user-controlled URL/host markup.
    comparison = row.get("domain_match", "비교 안 함")
    label = "분석 불가" if row.get("error") else ("도메인 불일치" if comparison == "불일치" else str(row.get("verdict", "")))
    with st.expander(f"링크 {index} · {label} · 상세 확인", expanded=expanded):
        st.code(str(row.get("input_url", "")), language=None, wrap_lines=True)
        if row.get("error"):
            st.warning("모델 분석을 제공할 수 없습니다." if row.get("host") else "이 입력은 URL로 분석할 수 없습니다.")
            st.text(str(row["error"]))
            if not row.get("host"):
                return

        score_col, domain_col = st.columns([1, 2], gap="large")
        with score_col:
            st.caption("머신러닝 결과 · 등록 도메인 특징 모델")
            score = row.get("score")
            st.metric("피싱 의심 점수", "미제공" if score is None else f"{safe_number(score) * 100:.1f} / 100")
            if score is not None:
                width = min(100, max(0, safe_number(score) * 100))
                boundary = min(100, max(0, safe_number(st.session_state.get("last_request", {}).get("threshold", .5)) * 100))
                markup(f'<div class="lg-score-rail" aria-hidden="true"><div class="lg-score-fill" style="width:{width:.2f}%"></div><span class="lg-score-threshold" style="left:{boundary:.2f}%"></span></div>')
                st.caption(f"의심 분류 기준 {boundary:.0f} / 100")
            st.text(str(row.get("verdict", "분석 불가")))
            st.caption("점수는 모델 출력이며 실제 피해 발생 확률이 아닙니다.")
        with domain_col:
            st.caption("도메인 구조 확인 · 규칙 기반")
            host = str(row.get("host", ""))
            registered = str(row.get("registered_domain") or "")
            markup('<div class="lg-result-domain"><div class="lg-aside-label">실제 접속 호스트</div><div class="lg-domain-text">'
                   + domain_markup(host, registered) + '</div></div>')
            st.caption("강조된 부분이 등록 가능 도메인입니다." if registered else "등록 가능 도메인을 구분할 수 없습니다.")
            if comparison == "불일치":
                st.warning("예상한 공식 도메인과 다릅니다. 공식 경로에서 다시 확인하세요.")
            elif comparison == "일치":
                st.info("입력한 기준 도메인과 일치합니다. 이 사실만으로 안전을 보장하지 않습니다.")
            else:
                st.caption("비교할 공식 도메인을 입력하면 일치 여부를 확인할 수 있습니다.")
            if row.get("expected_domain"):
                st.text("비교 기준: " + str(row["expected_domain"]))

        st.markdown("**주소에서 관찰한 특징**")
        st.caption("아래 내용은 URL 구조 관찰 결과이며 모델의 개별 판단 근거와 구분됩니다.")
        observations = row.get("observations") or ["추가로 표시할 구조 관찰 사항이 없습니다."]
        for observation in observations:
            st.text("• " + str(observation))
        if row.get("limitations"):
            st.markdown("**확인 범위**")
            for limitation in row["limitations"]:
                st.text("• " + str(limitation))


def render_results(results: list[dict[str, Any]]) -> None:
    st.divider()
    markup(f'<div class="lg-results-intro"><h2>검사 결과</h2><span class="lg-badge">{len(results)}개 링크 분석 완료</span></div>')
    request = st.session_state.get("last_request", {})
    st.caption(f"분류 기준 {safe_number(request.get('threshold', .5)):.2f} · 대상 페이지에 접속하지 않고 주소를 분석했습니다.")
    mismatch = sum(row.get("domain_match") == "불일치" for row in results)
    if mismatch:
        markup(f'<div class="lg-summary-note"><strong>예상한 도메인과 다른 링크가 {mismatch}개 있어요.</strong><br>모델 점수가 낮더라도 실제 도메인을 확인하고, 공식 경로에서 다시 확인하세요. 도메인 불일치만으로 피싱을 확정하지 않습니다.</div>')
    else:
        markup('<div class="lg-summary-note neutral">점수와 도메인 비교 결과를 함께 확인하세요. 낮은 의심 점수나 도메인 일치만으로 사이트의 안전을 확정할 수 없습니다.</div>')
    summary_cols = st.columns(4)
    summary_cols[0].metric("추출한 링크", len(results))
    summary_cols[1].metric("모델 의심", sum(r.get("verdict") == "의심" for r in results))
    summary_cols[2].metric("도메인 불일치", sum(r.get("domain_match") == "불일치" for r in results))
    summary_cols[3].metric("분석 불가", sum(bool(r.get("error")) for r in results))
    table = []
    for index, row in enumerate(results, 1):
        score = row.get("score")
        table.append({
            "번호": index,
            # Streamlit also offers a built-in CSV export for this table.
            "입력 URL": safe_csv_cell(row.get("input_url", "")),
            "등록 가능 도메인": row.get("registered_domain", ""),
            "의심 점수": "—" if score is None else f"{safe_number(score) * 100:.1f}",
            "모델 분류": row.get("verdict", "분석 불가"),
            "도메인 비교": row.get("domain_match", "비교 안 함"),
        })
    st.dataframe(
        pd.DataFrame(table),
        hide_index=True,
        width="stretch",
        column_config={"입력 URL": st.column_config.TextColumn(width="large")},
    )
    st.caption("낮은 의심 점수도 안전을 보장하지 않습니다. 공식 앱이나 직접 입력한 공식 주소로 재확인하세요.")
    first_attention = next((i for i, row in enumerate(results, 1)
                            if row.get("domain_match") == "불일치" or row.get("error") or row.get("verdict") == "의심"), 1)
    for index, row in enumerate(results, 1):
        render_result_details(row, index, expanded=index == first_attention)
    st.download_button(
        "검사 결과 CSV 내려받기",
        data=result_csv(results),
        file_name="linkguard_results.csv",
        mime="text/csv",
        key="download_results",
    )
    st.caption("같은 등록 도메인은 경로·쿼리·HTTPS 표기가 달라도 같은 점수를 받습니다. 실제 페이지 내용은 확인하지 않습니다.")


def render_inspector(info: dict[str, Any]) -> None:
    markup('''<section class="lg-hero">
      <div class="lg-eyebrow">링크 검사</div>
      <h1>클릭하기 전에,<br><span class="lg-emphasis">링크의 목적지</span>를 확인하세요.</h1>
      <p>의심스러운 URL이나 받은 문자를 붙여 넣으세요.<br>도메인 분석과 머신러닝 점수를 함께 확인할 수 있습니다.</p>
    </section>''')
    for key, default in (("input_text", ""), ("expected_domain", ""), ("results", []), ("sample_loaded", False)):
        st.session_state.setdefault(key, default)

    workspace, guide = st.columns([2.05, 1], gap="large")
    with workspace:
        with st.container(key="scan_workspace"):
            markup('<div class="lg-panel-heading"><strong>검사할 링크를 입력하세요</strong><span>최대 30개 · 20,000자</span></div>')
            st.text_area(
                "검사할 URL 또는 문자", key="input_text", height=155, max_chars=20000,
                placeholder="https://example.org/notice\n또는 링크가 포함된 문자 내용을 붙여 넣으세요.",
                on_change=invalidate_results,
            )
            with st.container(key="example_buttons"):
                examples = st.columns(3)
                examples[0].button("예시 1 · 기본 주소", on_click=set_example, args=("single",), width="stretch")
                examples[1].button("예시 2 · 도메인 혼동", on_click=set_example, args=("domain",), width="stretch")
                examples[2].button("예시 3 · 문자 속 링크", on_click=set_example, args=("message",), width="stretch")
            if st.session_state["sample_loaded"]:
                st.caption("예약 도메인으로 만든 구조 설명용 예시입니다. 실제 피싱 사례나 성능 측정 자료가 아닙니다.")
            st.text_input(
                "예상한 공식 도메인 (선택)", key="expected_domain", placeholder="예: example.org", max_chars=253,
                help="공식 사이트에서 직접 확인한 도메인을 입력하세요. 입력값을 공식 도메인으로 인증하는 기능은 아닙니다.",
                on_change=invalidate_results,
            )
            default_threshold = min(.99, max(.01, safe_number(info.get("threshold"), .5)))
            with st.expander("분류 기준 설정"):
                threshold = st.slider(
                    "이 점수 이상이면 ‘의심’으로 분류", min_value=.01, max_value=.99,
                    value=round(default_threshold, 2), step=.01, key="inspect_threshold",
                    help="낮출수록 더 많은 주소를 의심으로 분류합니다. 변경 후 다시 검사하세요.",
                    on_change=invalidate_results,
                )
                st.caption("도메인 일치 여부는 이 기준과 무관하게 별도로 비교합니다.")
            actions = st.columns([4, 1])
            analyze = actions[0].button("링크 검사하기", type="primary", key="analyze", width="stretch")
            actions[1].button("초기화", key="clear", on_click=clear_input, width="stretch")
            markup('''<div class="lg-field-note"><svg width="13" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V6a4 4 0 0 1 8 0v4"/></svg><span>입력 내용은 검사 기록 파일로 자동 저장하지 않습니다.</span></div>''')
        if analyze:
            st.session_state["results"] = []
            text = st.session_state["input_text"].strip()
            if not text:
                st.warning("검사할 URL이나 문자를 먼저 입력해 주세요.")
            else:
                try:
                    from linkguard.service import analyze_text
                    with st.spinner("주소 구조와 학습 모델을 확인하고 있습니다…"):
                        results = analyze_text(text, expected_domain=st.session_state["expected_domain"].strip() or None, threshold=threshold)
                    st.session_state["results"] = results
                    st.session_state["last_request"] = {"threshold": threshold}
                    if not results:
                        st.warning("검사할 링크를 찾지 못했습니다. HTTP/HTTPS 주소 또는 도메인을 입력해 주세요.")
                except ValueError as exc:
                    st.warning("입력 내용을 확인해 주세요.")
                    st.text(str(exc))
                except (ImportError, OSError):
                    st.error("검사에 필요한 모델 또는 프로그램 파일을 읽지 못했습니다.")
                    st.caption("저장소 파일과 설치 상태를 확인하고 사용 가이드를 참고해 주세요.")
        if not st.session_state["results"]:
            markup('''<div class="lg-empty"><span class="lg-empty-icon" aria-hidden="true">↗</span><div><strong>검사 결과가 이곳에 표시됩니다.</strong><small>점수 · 실제 도메인 · 주소에서 관찰한 특징을 확인하세요.</small></div></div>''')
    with guide:
        render_domain_guide()
    if st.session_state["results"]:
        render_results(st.session_state["results"])


def metric_columns(metrics: dict[str, Any]) -> None:
    cols = st.columns(4)
    for col, label, key in zip(cols, ("피싱 탐지율", "정밀도", "F1", "정상 주소 오탐률"), ("recall", "precision", "f1", "fpr")):
        col.metric(label, percentage(metrics.get(key)))


def confusion_table(metrics: dict[str, Any]) -> pd.DataFrame:
    return pd.DataFrame(
        [[int(safe_number(metrics.get("tn"))), int(safe_number(metrics.get("fp")))],
         [int(safe_number(metrics.get("fn"))), int(safe_number(metrics.get("tp")))]],
        index=["실제 정상", "실제 피싱"],
        columns=["모델: 정상", "모델: 피싱"],
    )


def render_evaluation(info: dict[str, Any]) -> None:
    metrics = read_artifact("metrics.json")
    curve = read_artifact("threshold_curve.json")
    markup('<section class="lg-hero"><div class="lg-eyebrow">모델 평가</div><h1>성능의 숫자 뒤에,<br><span class="lg-emphasis">오탐과 미탐</span>을 함께.</h1></section>')
    st.caption("피싱을 양성 클래스로 평가합니다. 슬라이더는 검증 데이터에만 적용하며 고정 내부 평가 결과는 바뀌지 않습니다.")
    if not metrics:
        st.info("학습 결과가 준비되면 모델 비교와 최종 평가 수치가 표시됩니다.")
        st.code("python -m scripts.download_data\npython -m scripts.train", language="bash")
        return

    st.warning("원본 정상 샘플은 모두 `https://www.` 형식이며 경로·쿼리가 없습니다. 최종 모델은 HTTPS·www·경로·쿼리를 제외해 이 단서에 의존하는 문제를 줄였지만, 데이터 수집 편향은 남아 있습니다. 평가 수치는 실제 링크 탐지 성능을 보장하지 않습니다.")

    selection = metrics.get("selection", {})
    selected = info.get("selected_model") or selection.get("model") or selection.get("selected_model") or curve.get("model", "")
    selected_metrics = metrics.get("models", {}).get(selected, {})
    test = info.get("test_metrics") or selected_metrics.get("test", {})
    frozen_threshold = info.get("threshold", selection.get("threshold", .5))
    st.markdown("**내부 평가 결과 · 고정**")
    st.caption(f"선택 모델: {model_name(str(selected))} · 고정 판정 기준: {safe_number(frozen_threshold):.2f}")
    st.caption("개발 중 모델을 수정하며 같은 내부 평가 분할을 다시 사용했습니다. 새로운 외부 데이터의 독립 검증 결과가 아닙니다.")
    if test:
        metric_columns(test)
        with st.expander("내부 평가 혼동행렬"):
            st.dataframe(confusion_table(test), width="stretch")
            st.caption("오탐 = 정상 주소를 피싱으로 분류 / 미탐 = 피싱 주소를 정상으로 분류")

    comparison_rows = []
    for key, values in metrics.get("models", {}).items():
        validation, test_row = values.get("validation", {}), values.get("test", {})
        comparison_rows.append({
            "모델": model_name(key),
            "선택": "사용 중" if key == selected else "비교용",
            "검증 F1": percentage(validation.get("f1")),
            "내부 평가 F1": percentage(test_row.get("f1")),
            "내부 피싱 탐지율": percentage(test_row.get("recall")),
            "내부 정상 오탐률": percentage(test_row.get("fpr")),
        })
    if comparison_rows:
        st.dataframe(pd.DataFrame(comparison_rows), hide_index=True, width="stretch")
        st.caption("이번 실행의 모델과 판정 기준은 검증 결과로 선택했습니다. 개발 과정에서 내부 평가 결과를 보고 설계를 수정했으므로, 외부 독립 검증은 별도로 필요합니다.")

    st.divider()
    st.markdown("**탐지 민감도 실험 · 검증 데이터**")
    rows = curve.get("rows", [])
    if rows:
        threshold = st.slider(
            "의심으로 분류할 점수 기준",
            .01, .99,
            min(.99, max(.01, round(safe_number(frozen_threshold, .5), 2))),
            .01,
            key="eval_threshold",
        )
        selected_row = min(rows, key=lambda item: abs(safe_number(item.get("threshold")) - threshold))
        actual_threshold = safe_number(selected_row.get("threshold"))
        st.caption(f"아래 수치는 검증 데이터에서 계산한 기준 {actual_threshold:.2f}의 결과입니다. 위 고정 내부 평가 결과에는 영향을 주지 않습니다.")
        metric_columns(selected_row)
        counts = st.columns(3)
        counts[0].metric("탐지한 피싱", int(safe_number(selected_row.get("tp"))))
        counts[1].metric("놓친 피싱", int(safe_number(selected_row.get("fn"))))
        counts[2].metric("정상을 잘못 의심", int(safe_number(selected_row.get("fp"))))
        chart_rows = pd.DataFrame(rows)
        chart = chart_rows.set_index("threshold")[["recall", "fpr"]].rename(columns={"recall": "피싱 탐지율", "fpr": "정상 오탐률"})
        st.line_chart(chart, color=["#c4b5fd", "#f4c37f"], width="stretch")
        st.caption("기준을 낮추면 일반적으로 피싱 탐지는 늘지만 정상 주소에 대한 오탐도 늘어납니다.")
    else:
        st.info("검증 데이터의 기준별 결과 파일이 없어 민감도 실험을 표시할 수 없습니다.")

    with st.expander("데이터와 평가 방법"):
        st.write("UCI PhiUSIIL의 URL에서 등록 가능 도메인을 추출하고 문자 통계 또는 문자 패턴으로 학습합니다. 문자 패턴 모델은 공용 접미사를 포함한 등록 가능 도메인을 사용합니다. HTTPS 사용 여부·www·일반 하위 도메인·경로·쿼리는 입력에서 제외합니다. 원본 정상=1, 피싱=0 라벨을 내부 피싱=1로 변환합니다.")
        st.write("같은 등록 가능 도메인이 학습·검증·내부 평가에 섞이지 않도록 그룹을 나눕니다. 실제 기록된 데이터 정보와 분할 결과는 아래에서 확인할 수 있습니다.")
        st.json({key: metrics[key] for key in ("dataset", "preprocessing", "split", "selection") if key in metrics}, expanded=False)
        st.caption("공개 데이터에서 측정한 결과이며 최신 피싱이나 모든 서비스에서 같은 성능을 보장하지 않습니다.")


def render_guide() -> None:
    markup('<section class="lg-hero"><div class="lg-eyebrow">사용 가이드</div><h1>결과를 읽는<br><span class="lg-emphasis">세 가지 기준.</span></h1><p>하나의 점수보다, 여러 정보를 함께 확인하는 습관이 중요합니다.</p></section>')
    cards = [
        ("01", "의심 점수", "등록 도메인의 문자 패턴을 분석한 모델 출력입니다. 실제 피해 발생 확률이나 사이트의 안전 인증이 아닙니다."),
        ("02", "도메인 비교", "직접 확인한 공식 도메인에 속하는 주소인지 비교합니다. 불일치는 추가 확인이 필요하다는 의미입니다."),
        ("03", "주소 구조", "실제 호스트, 하위 도메인, @ 구문을 확인합니다. 이 설명은 URL 관찰 결과이며 모델의 판단 근거와 구분됩니다."),
    ]
    for col, (index, title, body) in zip(st.columns(3, gap="large"), cards):
        with col:
            markup(f'<div class="lg-guide-card"><div class="lg-guide-index">{index} / READ THE SIGNAL</div><h3>{title}</h3><p>{body}</p></div>')

    st.divider()
    st.markdown("**서비스 사용 순서**")
    st.write("1. URL 또는 링크가 포함된 문자를 붙여 넣습니다.")
    st.write("2. 알고 있는 공식 도메인이 있다면 비교 기준에 입력합니다.")
    st.write("3. ‘링크 검사하기’를 누르고 링크별 상세 결과를 확인합니다.")
    st.write("4. 의심스럽거나 불일치하는 주소는 공식 앱 또는 직접 입력한 공식 주소에서 재확인합니다.")

    with st.expander("이 서비스가 확인하지 않는 것", expanded=True):
        st.write("웹페이지 내용, 로그인 화면, 악성 파일, 인증서 유효성, 실시간 평판, 단축 URL의 최종 목적지는 확인하지 않습니다.")
        st.write("대상 URL에 접속하지 않으며 문자 전체의 사기 여부를 판정하지 않습니다. 검사 결과만으로 링크를 클릭하거나 개인정보를 입력하지 마세요.")
        st.write("원본 정상 샘플은 모두 `https://www.` 형식이며 경로·쿼리가 없습니다. 최종 모델은 이 특징들을 입력에서 제외해 특정 수집 형식에 의존하는 문제를 줄였습니다. 그래도 다른 데이터와 현재 서비스에 대한 별도 검증이 필요합니다.")
        st.write("같은 등록 도메인은 HTTP/HTTPS, www, 하위 도메인, 경로, 쿼리가 달라도 같은 모델 점수를 받습니다. 따라서 정상 도메인의 침해된 페이지, 악성 하위 경로, 공유 호스팅 내 개별 콘텐츠의 위험은 이 모델로 구별할 수 없습니다.")
    with st.expander("개인정보와 입력 범위"):
        st.write("최대 20,000자의 텍스트와 30개의 링크를 처리합니다. 입력은 앱을 실행하는 서버에서 분석되며 별도 검사 기록 파일로 자동 저장하지 않습니다.")
        st.write("인증 토큰·개인정보가 포함된 주소는 사용하지 마세요. 결과 CSV는 사용자가 내려받기를 선택했을 때 생성됩니다. 초기화 버튼으로 현재 입력과 결과를 지울 수 있습니다.")
    with st.expander("모델 파일이 없을 때"):
        st.write("저장소 전체와 의존성을 설치한 후, 데이터 준비와 학습 명령으로 모델을 생성할 수 있습니다.")
        st.code("python -m scripts.download_data\npython -m scripts.train\npython -m streamlit run app.py", language="bash")
    st.markdown("데이터 출처: [UCI PhiUSIIL Phishing URL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) · CC BY 4.0")
    st.caption("LinkGuard는 머신러닝 학습과 피싱 예방 이해를 위한 기말 프로젝트입니다.")


info = get_model_info()
markup('''<header class="lg-topbar">
  <div class="lg-brand"><div class="lg-mark" aria-hidden="true"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m10 13 4-4M8 15l-1 1a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0m2 3 1-1a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0" transform="translate(1 0)"/></svg></div><div><div class="lg-brand-name">LinkGuard</div><div class="lg-brand-sub">URL INTELLIGENCE</div></div></div>
  <div class="lg-session"><span></span>페이지 접속 없는 분석</div>
</header>''')
if not info:
    st.info("모델 파일이 없거나 아직 준비되지 않았습니다. 구조 분석을 이용하거나 사용 가이드의 학습 방법을 확인하세요.")
inspect_tab, evaluate_tab, guide_tab = st.tabs(["URL 검사", "모델 평가", "사용 가이드"])
with inspect_tab:
    render_inspector(info)
with evaluate_tab:
    render_evaluation(info)
with guide_tab:
    render_guide()
markup('<footer class="lg-footer"><span><strong>LinkGuard</strong> &nbsp; · &nbsp; 링크를 확인하는 더 신중한 방법</span><span>교육용 분석 도구 · 낮은 점수는 안전을 보장하지 않습니다.</span></footer>')
