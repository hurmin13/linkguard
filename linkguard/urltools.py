"""Parse URLs without network requests. All supplied URLs remain inert text."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

import idna
import tldextract

MAX_URL_LENGTH = 8192
MAX_TEXT_LENGTH = 20000
MAX_URLS = 30
_extract = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)
_url_pattern = re.compile(r"https?://[^\s<>\"'“”‘’]+", re.IGNORECASE)


def parse_url(value: str) -> dict:
    """Return normalized URL components; never resolve DNS or fetch a page."""
    if not isinstance(value, str):
        raise ValueError("URL은 문자열로 입력해 주세요.")
    raw = value.strip()
    if not raw:
        raise ValueError("URL을 입력해 주세요.")
    if len(raw) > MAX_URL_LENGTH:
        raise ValueError(f"URL은 {MAX_URL_LENGTH:,}자 이하여야 합니다.")
    if any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in raw):
        raise ValueError("URL 내부에 공백이나 제어 문자를 사용할 수 없습니다.")
    if "\\" in raw:
        raise ValueError("역슬래시가 포함된 주소는 해석이 모호해 분석하지 않습니다.")
    candidate = raw
    if raw.startswith("//"):
        candidate = "https:" + raw
    elif "://" not in raw:
        # A host:port is allowed, but javascript:, data:, mailto: etc. are not.
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", raw) and not re.match(
            r"^[^/:]+:\d+(?:[/?#]|$)", raw
        ):
            raise ValueError("HTTP 또는 HTTPS 주소만 분석할 수 있습니다.")
        candidate = "https://" + raw
    try:
        parts = urlsplit(candidate)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError("HTTP 또는 HTTPS 주소만 분석할 수 있습니다.")
        host = parts.hostname
        port = parts.port  # also checks the port range
        if not host or "%" in host:
            raise ValueError("유효한 호스트 이름이 필요합니다.")
        host = host.rstrip(".").lower()
        is_ip = False
        try:
            ip = ipaddress.ip_address(host)
            host = ip.compressed
            is_ip = True
            unicode_host = host
        except ValueError:
            try:
                host = idna.encode(host, uts46=True, std3_rules=True).decode("ascii")
                unicode_host = idna.decode(host)
            except idna.IDNAError as exc:
                raise ValueError("호스트 이름의 형식이 올바르지 않습니다.") from exc
            if "." not in host or len(host) > 253:
                raise ValueError("도메인 이름 또는 IP 주소를 입력해 주세요.")
            if re.fullmatch(r"[0-9.]+", host):
                raise ValueError("올바른 IP 주소 형식이 아닙니다.")
        extracted = _extract(host) if not is_ip else None
        suffix = extracted.suffix if extracted else ""
        # A missing PSL suffix is explicitly reported; do not guess last two labels.
        registered_domain = extracted.top_domain_under_public_suffix if suffix else host
        subdomain = extracted.subdomain if suffix else ""
        has_userinfo = "@" in parts.netloc
        userinfo = parts.netloc.rsplit("@", 1)[0] + "@" if has_userinfo else ""
        authority_host = f"[{host}]" if is_ip and ":" in host else host
        authority = userinfo + authority_host + (f":{port}" if port is not None else "")
        normalized = urlunsplit((scheme, authority, parts.path, parts.query, parts.fragment))
    except (ValueError, UnicodeError) as exc:
        raise ValueError(str(exc) or "URL 형식이 올바르지 않습니다.") from exc
    return {
        "input_url": value,
        "normalized_url": normalized,
        "scheme": scheme,
        "host": host,
        "unicode_host": unicode_host,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "suffix": suffix,
        "path": parts.path,
        "query": parts.query,
        "fragment": parts.fragment,
        "port": port,
        "is_ip": is_ip,
        "has_userinfo": has_userinfo,
        "suffix_known": bool(suffix),
    }


def extract_urls(text: str, limit: int = MAX_URLS) -> list[str]:
    """Extract explicit HTTP(S) links, or accept a single bare URL/domain.

    Duplicate literal URLs are removed in input order. Too many links are an
    error rather than silently skipping a potentially important link.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("URL 또는 링크가 포함된 문자를 입력해 주세요.")
    if len(text) > MAX_TEXT_LENGTH:
        raise ValueError(f"입력은 {MAX_TEXT_LENGTH:,}자 이하여야 합니다.")
    if not 1 <= limit <= MAX_URLS:
        raise ValueError(f"검사 개수는 1~{MAX_URLS} 사이여야 합니다.")
    raw_matches = _url_pattern.findall(text)
    if raw_matches:
        candidates = []
        for value in raw_matches:
            # Strip surrounding prose punctuation; keep balanced URL parentheses.
            value = value.rstrip(".,;!，。；！")
            for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
                while value.endswith(closing) and value.count(closing) > value.count(opening):
                    value = value[:-1]
            candidates.append(value)
    else:
        value = text.strip()
        if any(c.isspace() for c in value):
            raise ValueError("HTTP/HTTPS 링크를 찾지 못했습니다. 링크 주소를 포함해 주세요.")
        candidates = [value]
    urls = list(dict.fromkeys(candidates))
    if len(urls) > limit:
        raise ValueError(f"한 번에 서로 다른 링크 {limit}개까지 검사할 수 있습니다.")
    return urls


def normalize_expected_domain(value: str | None) -> str | None:
    if not value or not value.strip():
        return None
    parts = parse_url(value)
    if parts["suffix_known"] and not parts["registered_domain"]:
        raise ValueError("공용 접미사 자체는 비교 기준으로 사용할 수 없습니다. 소유한 구체적인 도메인을 입력해 주세요.")
    if parts["path"] not in ("", "/") or parts["query"] or parts["fragment"] or parts["has_userinfo"] or parts["port"] is not None:
        raise ValueError("비교할 공식 도메인은 경로·포트 없이 입력해 주세요. 예: example.org")
    return parts["host"]


def domain_matches(host: str, expected: str) -> bool:
    """Exact host or a DNS-label-bounded subdomain, never substring matching."""
    try:
        ipaddress.ip_address(expected)
        return host == expected
    except ValueError:
        return host == expected or host.endswith("." + expected)
