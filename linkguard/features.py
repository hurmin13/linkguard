"""Registered-domain lexical features, independent of URL formatting.

PhiUSIIL's benign URLs all use https://www. with no path/query. Those are
collection shortcuts, so the deployed model deliberately excludes them.
Full URL structure remains available separately in the rule-based inspector.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from .urltools import parse_url

FEATURE_VERSION = "domain-lexical-v2"
FEATURE_NAMES = [
    "label_length", "digit_ratio", "alpha_ratio", "vowel_ratio", "hyphen_ratio",
    "label_entropy", "unique_char_ratio", "longest_digit_run", "longest_alpha_run",
    "has_ip", "has_punycode", "suffix_length",
]
FEATURE_LABELS = {
    "label_length": "등록 도메인 이름 길이", "digit_ratio": "숫자 비율",
    "alpha_ratio": "영문자 비율", "vowel_ratio": "영어 모음 비율",
    "hyphen_ratio": "하이픈 비율", "label_entropy": "문자 분포 엔트로피",
    "unique_char_ratio": "서로 다른 문자 비율", "longest_digit_run": "최장 연속 숫자 길이",
    "longest_alpha_run": "최장 연속 영문자 길이", "has_ip": "IP 주소 여부",
    "has_punycode": "국제화 도메인 여부", "suffix_length": "공용 접미사 길이",
}

def extract_features(url: str) -> dict[str, float]:
    """Return the same features for paths/subdomains of one registered domain."""
    parsed = parse_url(url)
    domain = parsed["registered_domain"] or parsed["host"]
    suffix = parsed["suffix"]
    label = domain[:-(len(suffix) + 1)] if suffix and domain.endswith("." + suffix) else domain
    counts = Counter(label)
    n = max(1, len(label))
    values = [
        len(label),
        sum(c.isdigit() for c in label) / n,
        sum("a" <= c <= "z" for c in label) / n,
        sum(c in "aeiou" for c in label) / n,
        label.count("-") / n,
        -sum((count / n) * math.log2(count / n) for count in counts.values()),
        len(counts) / n,
        max((len(s) for s in re.findall(r"[0-9]+", label)), default=0),
        max((len(s) for s in re.findall(r"[a-z]+", label)), default=0),
        int(parsed["is_ip"]),
        int(any(p.startswith("xn--") for p in domain.split("."))),
        len(suffix),
    ]
    return dict(zip(FEATURE_NAMES, map(float, values), strict=True))
