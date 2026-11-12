"""LinkGuard: Korean URL inspection and model evaluation interface.

Run from the repository root: python -m streamlit run app.py
"""

from __future__ import annotations

import csv
import io
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

st.markdown(
    """
<style>
  .stApp { background: #f5f8fc; }
  .block-container { max-width: 1180px; padding-top: 4.5rem; padding-bottom: 3rem; }
  h1,h2,h3 { letter-spacing: -.035em; }
  h1 { font-weight: 780 !important; }
  [data-testid="stMetric"] { background: white; border: 1px solid #e1e8f0;
      padding: 1rem 1.15rem; border-radius: 14px; }
  [data-testid="stMetricLabel"] { color: #61738a; }
  [data-testid="stMetricValue"] { color: #17324d; }
  [data-baseweb="tab-list"] { gap: 1.5rem; border-bottom: 1px solid #dce5ef; }
  [data-baseweb="tab"] { font-weight: 650; padding-left: .2rem; padding-right: .2rem; }
  [data-testid="stTextArea"] textarea { line-height: 1.65; }
  [data-testid="stExpander"] { background: #fff; border-radius: 12px; }
  .lg-kicker { display: inline-block; color: #087f8c; font-weight: 750;
      font-size: .74rem; letter-spacing: .12em; margin-bottom: .45rem; }
  .lg-title { margin: 0; font-size: 2.65rem; font-weight: 800; line-height: 1.1;
      letter-spacing: -.065em; color: #132d48; }
  .lg-subtitle { color: #60758c; margin: .7rem 0 1.6rem; line-height: 1.6; }
  .lg-status { display: inline-block; color: #087f8c; font-size: .78rem;
      background: #e1f3f1; border: 1px solid #c4e6e2; padding: .4rem .7rem;
      border-radius: 40px; font-weight: 650; }
  .lg-note { border-left: 3px solid #118994; padding: .4rem 1rem;
      color: #5b6e82; font-size: .9rem; line-height: 1.7; margin: .6rem 0 1.4rem; }
  .lg-footer { color: #7c8a9b; border-top: 1px solid #dce5ef;
      padding-top: 1rem; font-size: .8rem; margin-top: 2rem; }
  @media (max-width: 640px) {
    .block-container { padding-top: 3.5rem; padding-left: 1rem; padding-right: 1rem; }
    .lg-title { font-size: 2.2rem; }
    [data-baseweb="tab-list"] { gap: .8rem; }
  }
</style>
""",
    unsafe_allow_html=True,
)


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


def render_result_details(row: dict[str, Any], index: int) -> None:
    # The expander title contains no user-controlled URL/host markup.
    with st.expander(f"링크 {index} · 상세 확인", expanded=index == 1):
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
            st.text(str(row.get("verdict", "분석 불가")))
            st.caption("점수는 모델 출력이며 실제 피해 발생 확률이 아닙니다.")
        with domain_col:
            st.caption("도메인 구조 확인 · 규칙 기반")
            st.text("접속 호스트")
            st.code(str(row.get("host", "")), language=None, wrap_lines=True)
            st.text("등록 가능 도메인")
            st.code(str(row.get("registered_domain") or "확인할 수 없음"), language=None, wrap_lines=True)
            comparison = row.get("domain_match", "비교 안 함")
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
    st.subheader("검사 결과")
    request = st.session_state.get("last_request", {})
    st.caption(f"분류 기준 {safe_number(request.get('threshold', .5)):.2f} · 대상 페이지에 접속하지 않고 주소를 분석했습니다.")
    st.info("등록 도메인의 문자 특징으로 계산한 교육용 점수입니다. HTTPS·www·경로·쿼리는 모델 입력에서 제외하므로, 같은 도메인의 서로 다른 경로는 같은 점수를 받습니다. 실제 페이지의 악성 여부는 확인하지 않습니다.")
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
    for index, row in enumerate(results, 1):
        render_result_details(row, index)
    st.download_button(
        "검사 결과 CSV 내려받기",
        data=result_csv(results),
        file_name="linkguard_results.csv",
        mime="text/csv",
        key="download_results",
    )


def render_inspector(info: dict[str, Any]) -> None:
    st.subheader("클릭하기 전에, 주소부터 확인하세요")
    st.caption("URL 하나 또는 링크가 포함된 문자 내용을 입력하세요. 최대 30개 링크, 20,000자까지 검사합니다.")
    for key, default in (("input_text", ""), ("expected_domain", ""), ("results", []), ("sample_loaded", False)):
        st.session_state.setdefault(key, default)

    example_cols = st.columns(3)
    example_cols[0].button("예시 1 · 기본 주소", on_click=set_example, args=("single",), width="stretch")
    example_cols[1].button("예시 2 · 도메인 혼동", on_click=set_example, args=("domain",), width="stretch")
    example_cols[2].button("예시 3 · 문자 속 링크", on_click=set_example, args=("message",), width="stretch")
    if st.session_state["sample_loaded"]:
        st.caption("예시 주소는 예약 도메인을 사용한 교육용 입력입니다. 실제 정상·피싱 사례나 성능 측정 자료가 아닙니다.")

    st.text_area(
        "검사할 URL 또는 문자",
        key="input_text",
        height=170,
        max_chars=20000,
        placeholder="https://example.org/notice\n또는 받은 문자 내용을 붙여 넣으세요.",
        on_change=invalidate_results,
    )
    comparison_col, action_col = st.columns([3, 2], gap="large")
    with comparison_col:
        st.text_input(
            "예상한 공식 도메인 (선택)",
            key="expected_domain",
            placeholder="예: example.org",
            max_chars=253,
            help="공식 사이트에서 직접 확인한 도메인을 입력하세요. 입력한 문자열을 공식 도메인으로 인증하는 기능은 아닙니다.",
            on_change=invalidate_results,
        )
    with action_col:
        st.caption("검사 범위")
        st.write("등록 도메인 특징 분석 · 페이지 접속 없음")
        st.caption("입력 내용은 검사 기록 파일로 자동 저장하지 않습니다.")

    default_threshold = min(.99, max(.01, safe_number(info.get("threshold"), .5)))
    with st.expander("분류 기준 설정"):
        threshold = st.slider(
            "이 점수 이상이면 ‘의심’으로 분류",
            min_value=.01,
            max_value=.99,
            value=round(default_threshold, 2),
            step=.01,
            key="inspect_threshold",
            help="낮출수록 더 많은 주소를 의심으로 분류합니다. 변경 후 다시 검사하세요.",
            on_change=invalidate_results,
        )
        st.caption("도메인 일치 여부는 이 기준과 무관하게 별도로 비교합니다.")

    button_cols = st.columns([3, 1, 6])
    analyze = button_cols[0].button("링크 검사하기", type="primary", key="analyze", width="stretch")
    button_cols[1].button("초기화", key="clear", on_click=clear_input, width="stretch")
    if analyze:
        st.session_state["results"] = []
        text = st.session_state["input_text"].strip()
        if not text:
            st.warning("검사할 URL이나 문자를 먼저 입력해 주세요.")
        else:
            try:
                from linkguard.service import analyze_text

                with st.spinner("주소 구조와 학습 모델을 확인하고 있습니다…"):
                    results = analyze_text(
                        text,
                        expected_domain=st.session_state["expected_domain"].strip() or None,
                        threshold=threshold,
                    )
                st.session_state["results"] = results
                st.session_state["last_request"] = {"threshold": threshold}
                if not results:
                    st.warning("검사할 링크를 찾지 못했습니다. HTTP/HTTPS 주소 또는 도메인을 입력해 주세요.")
            except ValueError as exc:
                st.warning("입력 내용을 확인해 주세요.")
                st.text(str(exc))
            except (ImportError, OSError) as exc:
                st.error("검사에 필요한 모델 또는 프로그램 파일을 읽지 못했습니다.")
                st.caption("저장소 파일과 설치 상태를 확인하고 아래 사용 가이드를 참고해 주세요.")

    if st.session_state["results"]:
        render_results(st.session_state["results"])
    else:
        st.markdown(
            '<div class="lg-note">주소 앞부분의 익숙한 이름만 보고 판단하지 마세요. '
            'LinkGuard는 모델의 의심 점수와 도메인 구조를 구분해서 보여줍니다.</div>',
            unsafe_allow_html=True,
        )


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
    st.subheader("탐지 성능과 오탐을 함께 확인하세요")
    st.caption("피싱을 양성 클래스로 평가합니다. 슬라이더는 검증 데이터에만 적용하며 고정 내부 평가 결과는 바뀌지 않습니다.")
    if not metrics:
        st.info("학습 결과가 준비되면 모델 비교와 최종 평가 수치가 표시됩니다.")
        st.code("python -m scripts.download_data\npython -m scripts.train", language="bash")
        return

    st.warning("원본 정상 샘플은 모두 https://www. 형식이며 경로·쿼리가 없습니다. 최종 모델은 HTTPS·www·경로·쿼리를 제외해 이 단서에 의존하는 문제를 줄였지만, 데이터 수집 편향은 남아 있습니다. 평가 수치는 실제 링크 탐지 성능을 보장하지 않습니다.")

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
        st.line_chart(chart, color=["#087f8c", "#d97757"], width="stretch")
        st.caption("기준을 낮추면 일반적으로 피싱 탐지는 늘지만 정상 주소에 대한 오탐도 늘어납니다.")
    else:
        st.info("검증 데이터의 기준별 결과 파일이 없어 민감도 실험을 표시할 수 없습니다.")

    with st.expander("데이터와 평가 방법"):
        st.write("UCI PhiUSIIL의 URL에서 등록 가능 도메인을 추출하고 문자 통계 또는 문자 패턴으로 학습합니다. 문자 패턴 모델은 공용 접미사를 포함한 등록 가능 도메인을 사용합니다. HTTPS 사용 여부·www·일반 하위 도메인·경로·쿼리는 입력에서 제외합니다. 원본 정상=1, 피싱=0 라벨을 내부 피싱=1로 변환합니다.")
        st.write("같은 등록 가능 도메인이 학습·검증·내부 평가에 섞이지 않도록 그룹을 나눕니다. 실제 기록된 데이터 정보와 분할 결과는 아래에서 확인할 수 있습니다.")
        st.json({key: metrics[key] for key in ("dataset", "preprocessing", "split", "selection") if key in metrics}, expanded=False)
        st.caption("공개 데이터에서 측정한 결과이며 최신 피싱이나 모든 서비스에서 같은 성능을 보장하지 않습니다.")


def render_guide() -> None:
    st.subheader("결과를 읽는 세 가지 기준")
    cols = st.columns(3, gap="large")
    with cols[0]:
        st.markdown("**01 · 의심 점수**")
        st.write("등록 도메인의 문자 특징을 바탕으로 계산한 모델 출력입니다. 점수가 낮더라도 사이트가 안전하다고 확정할 수 없습니다.")
    with cols[1]:
        st.markdown("**02 · 도메인 비교**")
        st.write("직접 확인한 공식 도메인과 주소가 같은 범위에 있는지 비교합니다. 불일치는 확인이 필요한 정보이며 피싱 확정 판정이 아닙니다.")
    with cols[2]:
        st.markdown("**03 · 구조 관찰**")
        st.write("실제 호스트, 하위 도메인, @ 구문 등에서 관찰한 특징입니다. 규칙 기반 설명을 모델의 개별 판단 근거로 해석하지 마세요.")

    st.divider()
    st.markdown("**서비스 사용 순서**")
    st.write("1. URL 또는 링크가 포함된 문자를 붙여 넣습니다.")
    st.write("2. 알고 있는 공식 도메인이 있다면 비교 기준에 입력합니다.")
    st.write("3. ‘링크 검사하기’를 누르고 링크별 상세 결과를 확인합니다.")
    st.write("4. 의심스럽거나 불일치하는 주소는 공식 앱 또는 직접 입력한 공식 주소에서 재확인합니다.")

    with st.expander("이 서비스가 확인하지 않는 것", expanded=True):
        st.write("웹페이지 내용, 로그인 화면, 악성 파일, 인증서 유효성, 실시간 평판, 단축 URL의 최종 목적지는 확인하지 않습니다.")
        st.write("대상 URL에 접속하지 않으며 문자 전체의 사기 여부를 판정하지 않습니다. 검사 결과만으로 링크를 클릭하거나 개인정보를 입력하지 마세요.")
        st.write("원본 정상 샘플은 모두 https://www. 형식이며 경로·쿼리가 없습니다. 최종 모델은 이 특징들을 입력에서 제외해 특정 수집 형식에 의존하는 문제를 줄였습니다. 그래도 다른 데이터와 현재 서비스에 대한 별도 검증이 필요합니다.")
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
title_col, status_col = st.columns([4, 1])
with title_col:
    st.markdown('<div class="lg-kicker">UNDERSTAND BEFORE YOU CLICK</div><div class="lg-title">LinkGuard</div><div class="lg-subtitle">의심스러운 링크를, 이해할 수 있는 정보로.</div>', unsafe_allow_html=True)
with status_col:
    st.markdown('<div class="lg-status">등록 도메인 분석</div>', unsafe_allow_html=True)
    st.caption("머신러닝 · 도메인 비교")

if not info:
    st.info("모델 파일이 없거나 아직 준비되지 않았습니다. 구조 분석을 이용하거나 사용 가이드의 학습 방법을 확인하세요.")

inspect_tab, evaluate_tab, guide_tab = st.tabs(["URL 검사", "모델 평가", "사용 가이드"])
with inspect_tab:
    render_inspector(info)
with evaluate_tab:
    render_evaluation(info)
with guide_tab:
    render_guide()

st.markdown('<div class="lg-footer">LinkGuard · 머신러닝 기반 피싱 URL 검사 및 사칭 도메인 설명 서비스<br>점수는 안전 보증이 아닙니다. 공식 경로에서 한 번 더 확인하세요.</div>', unsafe_allow_html=True)
