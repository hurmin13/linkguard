"""URL authority and input-boundary regressions using inert reserved domains."""

import pytest

from linkguard.features import FEATURE_NAMES, extract_features
from linkguard.urltools import (
    domain_matches,
    extract_urls,
    normalize_expected_domain,
    parse_url,
)


def test_authority_is_not_a_brand_substring():
    value = parse_url("https://example.org.login-check.example.com/auth")
    assert value["host"] == "example.org.login-check.example.com"
    assert value["registered_domain"] == "example.com"
    assert not domain_matches(value["host"], "example.org")


def test_userinfo_does_not_change_actual_host():
    value = parse_url("https://example.org@notice.example.com/login")
    assert value["has_userinfo"] is True
    assert value["host"] == "notice.example.com"
    assert value["registered_domain"] == "example.com"
    assert not domain_matches(value["host"], "example.org")


@pytest.mark.parametrize("host, expected, result", [
    ("example.org", "example.org", True),
    ("login.example.org", "example.org", True),
    ("notexample.org", "example.org", False),
    ("example.org.example.com", "example.org", False),
    ("192.0.2.10", "192.0.2.10", True),
    ("x.192.0.2.10", "192.0.2.10", False),
])
def test_domain_match_uses_dns_label_boundary(host, expected, result):
    assert domain_matches(host, expected) is result


def test_public_and_private_suffixes_have_correct_boundaries():
    assert parse_url("https://www.example.co.uk/")["registered_domain"] == "example.co.uk"
    assert parse_url("https://alice.github.io/")["registered_domain"] == "alice.github.io"
    assert parse_url("https://bob.github.io/")["registered_domain"] == "bob.github.io"


def test_international_domain_normalization():
    value = parse_url("https://bücher.de/konto")
    assert value["host"] == "xn--bcher-kva.de"
    assert value["unicode_host"] == "bücher.de"
    assert normalize_expected_domain("bücher.de") == value["host"]


def test_ipv6_authority_and_port_are_preserved():
    value = parse_url("https://[2001:db8::1]:8443/login")
    assert value["is_ip"] is True
    assert value["host"] == "2001:db8::1"
    assert value["port"] == 8443
    assert value["normalized_url"] == "https://[2001:db8::1]:8443/login"


def test_ipv4_is_not_mistaken_for_domain():
    value = parse_url("http://192.0.2.10/check")
    assert value["is_ip"] is True
    assert value["registered_domain"] == "192.0.2.10"


@pytest.mark.parametrize("url", [
    "", "javascript:alert(1)", "data:text/html,example", "ftp://example.org/file",
    "https://", "https://example.org:70000/", "https://example.org:abc/",
    "https://exam ple.org/", "https://example.org/ab\ncd",
    "https://example.org/ab\x00cd", "https://example.org\\@example.com/",
    "https://999.999.999.999/", "https://127.1/", "https://[not-ipv6]/",
    "https://example.org%2eevil.example/", "https://localhost/",
])
def test_ambiguous_or_unsupported_urls_fail(url):
    with pytest.raises(ValueError):
        parse_url(url)


@pytest.mark.parametrize("value", [
    "example.org/path", "example.org?token=x", "example.org#part",
    "example.org:8443", "name@example.org",
])
def test_expected_domain_requires_domain_only(value):
    with pytest.raises(ValueError):
        normalize_expected_domain(value)


def test_expected_domain_is_normalized():
    assert normalize_expected_domain("HTTPS://EXAMPLE.ORG/") == "example.org"
    assert normalize_expected_domain(" ") is None


@pytest.mark.parametrize("value", ["co.uk", "github.io"])
def test_public_suffix_cannot_be_used_as_trusted_domain(value):
    with pytest.raises(ValueError):
        normalize_expected_domain(value)


def test_text_extraction_deduplicates_without_losing_order():
    text = "공지 (https://example.org/a). 다른 링크 https://example.com/b! 다시 https://example.org/a"
    assert extract_urls(text) == ["https://example.org/a", "https://example.com/b"]


def test_text_extraction_preserves_balanced_path_parentheses():
    assert extract_urls("안내 https://example.org/a(b).") == ["https://example.org/a(b)"]


def test_single_bare_address_is_supported():
    assert extract_urls("example.org/login") == ["example.org/login"]
    assert parse_url("example.org/login")["normalized_url"] == "https://example.org/login"


def test_input_limits_are_explicit_not_silent_truncation():
    with pytest.raises(ValueError):
        extract_urls("https://example.org/" + "x" * 20000)
    with pytest.raises(ValueError):
        extract_urls(" ".join(f"https://example.org/{i}" for i in range(31)))
    with pytest.raises(ValueError):
        parse_url("https://example.org/" + "x" * 8192)


def test_feature_schema_and_normalized_equivalence():
    import math

    values = extract_features("HTTPS://EXAMPLE.ORG/notice?id=12")
    assert list(values) == FEATURE_NAMES
    assert all(math.isfinite(value) for value in values.values())
    assert values == extract_features("https://example.org/notice?id=12")


def test_model_features_do_not_learn_scheme_www_or_path_format_shortcuts():
    expected = extract_features("https://example.org")
    variants = [
        "http://example.org", "https://www.example.org/", "https://example.org/login",
        "https://mail.example.org/a/b?token=123#part", "https://account@example.org:8443/verify",
    ]
    assert all(extract_features(value) == expected for value in variants)
