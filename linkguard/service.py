"""Combine a learned model with separately labelled structural observations."""

from __future__ import annotations

import math

from .features import extract_features
from .urltools import domain_matches, extract_urls, normalize_expected_domain, parse_url

_shorteners = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "buff.ly", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "url.kr", "me2.do"}


def analyze_text(text: str, expected_domain: str | None = None, threshold: float = 0.5) -> list[dict]:
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("판정 기준은 0~1 사이여야 합니다.")
    expected = normalize_expected_domain(expected_domain)
    urls = extract_urls(text)
    bundle, model_error = None, None
    try:
        from .model import load_model, predict_score
        bundle = load_model()
    except (ImportError, FileNotFoundError, ValueError, OSError, KeyError) as exc:
        model_error = "학습 모델을 불러올 수 없습니다. 모델 파일과 실행 환경을 확인해 주세요."
    results = []
    for url in urls:
        row = {"input_url": url, "normalized_url": url, "host": "", "registered_domain": "",
               "subdomain": "", "suffix": "", "scheme": "", "path": "", "query": "",
               "score": None, "verdict": "분석 불가", "domain_match": "비교 안 함",
               "expected_domain": expected, "observations": [], "error": None, "limitations": []}
        try:
            parsed = parse_url(url)
            row.update(parsed)
            observations = []
            if expected:
                matches = domain_matches(parsed["host"], expected)
                row["domain_match"] = "일치" if matches else "불일치"
                if matches:
                    observations.append("입력 호스트가 비교 도메인 또는 그 하위 도메인에 해당합니다. 콘텐츠의 안전을 보장하지는 않습니다.")
                else:
                    observations.append(f"입력 호스트가 비교 도메인 {expected}에 속하지 않습니다. 외부 인증·결제 등 정상적인 별도 도메인일 수도 있으므로 출처를 확인하세요.")
                    if expected in parsed["host"] or expected in parsed["path"] or expected in parsed["query"]:
                        observations.append("비교 도메인 문자열이 주소 일부에 포함되어 있지만 도메인 일치 조건을 충족하지 않습니다.")
            if parsed["has_userinfo"]:
                observations.append("@ 앞부분은 사용자정보 구문입니다. 실제 접속 호스트는 @ 뒤에 있습니다.")
            if parsed["is_ip"]:
                observations.append("도메인 이름 대신 IP 주소를 사용합니다. 이 특징만으로 피싱을 확정하지 않습니다.")
            if any(label.startswith("xn--") for label in parsed["host"].split(".")):
                observations.append("국제화 도메인(퓨니코드)이 포함되어 있습니다. 문자 모양과 실제 도메인을 함께 확인하세요.")
            if parsed["subdomain"] and len(parsed["subdomain"].split(".")) >= 3:
                observations.append("하위 도메인 단계가 많습니다. 앞부분의 서비스명보다 등록 가능 도메인을 확인하세요.")
            if parsed["scheme"] == "http":
                observations.append("HTTP 주소입니다. HTTPS를 사용하더라도 사이트 신뢰성이 보장되는 것은 아닙니다.")
            else:
                observations.append("HTTPS 구문을 사용합니다. 인증서 유효성이나 사이트 안전 여부를 확인한 것은 아닙니다.")
            if not parsed["suffix_known"] and not parsed["is_ip"]:
                row["limitations"].append("내장 Public Suffix List에서 접미사를 찾지 못해 호스트 전체를 표시합니다. 등록 가능 도메인 구분은 제한됩니다.")
            if parsed["registered_domain"] in _shorteners:
                row["limitations"].append("알려진 단축 URL 서비스 주소입니다. 최종 목적지는 접속하지 않아 확인할 수 없습니다.")
            row["limitations"].append("웹페이지·DNS·리다이렉션은 검사하지 않았습니다. 점수는 실제 피해 발생 확률이 아닙니다.")
            row["observations"] = observations
            if bundle is not None:
                score = float(predict_score(extract_features(url), bundle, domain_text=parsed["registered_domain"] or parsed["host"]))
                if not math.isfinite(score) or not 0 <= score <= 1:
                    raise ValueError("모델 점수 형식이 올바르지 않습니다.")
                row["score"] = score
                row["verdict"] = "의심" if score >= threshold else "낮은 의심"
            else:
                row["error"] = model_error
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            row["error"] = str(exc)
            row["score"] = None
            row["verdict"] = "분석 불가"
        results.append(row)
    return results
