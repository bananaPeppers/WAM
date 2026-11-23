"""Pure URL and origin helpers -- no database, network, or Flask here.

Answers the small local questions the extension needs: is the connection
secure, and does a form post to a different origin than the page it's on?
Comparing origins locally means a full URL never has to be sent anywhere.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

# Default ports so that "http://a.com" and "http://a.com:80" compare equal.
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_INVALID_ORIGIN = ("", "", None)

# DNS treats these Unicode separator characters as dots during IDNA handling.
_DOT_TRANSLATION = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")

# Only flag leetspeak spellings of the protected email labels themselves
# (g00gle, outl00k, off1ce), so web3.com or 1password.com don't get flagged.
_DIGIT_CONFUSABLES = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"}
)
_PROTECTED_EMAIL_LABELS = frozenset({"mail", "google", "outlook", "live", "office"})

# Not a real public-suffix list, just the common two-label country suffixes,
# so something like portal.example.co.uk isn't mistaken for a nested domain.
_COMMON_TWO_LABEL_SUFFIXES = frozenset(
    {
        "ac.uk",
        "co.in",
        "co.jp",
        "co.nz",
        "co.uk",
        "co.za",
        "com.au",
        "com.br",
        "com.cn",
        "com.mx",
        "com.sg",
        "edu.au",
        "gov.uk",
        "net.au",
        "net.nz",
        "org.au",
        "org.nz",
        "org.uk",
    }
)
_DOMAIN_SUFFIX_MARKERS = frozenset({"co", "com", "edu", "gov", "io", "net", "org"})
_MAX_ORDINARY_SUBDOMAIN_LABELS = 4

_QR_QUERY_KEYS = frozenset({"qr", "qrcode", "qr_code", "qrid", "qr_id", "scan_id"})
_QR_TRACKING_KEYS = frozenset({"utm_medium", "utm_source"})
_QR_TRACKING_VALUES = frozenset({"qr", "qrcode", "qr-code", "scan"})
_QR_PATH_SEGMENTS = frozenset({"qr", "qrcode", "qr-code"})

_RISKY_DOWNLOAD_EXTENSIONS = frozenset(
    {
        ".apk",
        ".appx",
        ".bat",
        ".cmd",
        ".com",
        ".cpl",
        ".deb",
        ".dmg",
        ".exe",
        ".hta",
        ".iso",
        ".jar",
        ".js",
        ".jse",
        ".lnk",
        ".msi",
        ".msix",
        ".pkg",
        ".ps1",
        ".reg",
        ".rpm",
        ".scr",
        ".vbe",
        ".vbs",
        ".wsf",
    }
)
_ORDINARY_DOWNLOAD_EXTENSIONS = frozenset(
    {
        ".7z",
        ".avi",
        ".csv",
        ".doc",
        ".docx",
        ".gif",
        ".gz",
        ".jpeg",
        ".jpg",
        ".json",
        ".mov",
        ".mp3",
        ".mp4",
        ".pdf",
        ".png",
        ".ppt",
        ".pptx",
        ".rar",
        ".svg",
        ".tar",
        ".tgz",
        ".txt",
        ".webm",
        ".webp",
        ".xls",
        ".xlsx",
        ".xml",
        ".zip",
    }
)
_DOWNLOAD_EXTENSIONS = _RISKY_DOWNLOAD_EXTENSIONS | _ORDINARY_DOWNLOAD_EXTENSIONS
_LOCAL_CONTENT_SCHEMES = frozenset({"blob", "data", "file"})
_RISKY_LINK_SCHEMES = _LOCAL_CONTENT_SCHEMES | {"javascript"}


def _hostname_text(hostname: str) -> str:
    """Normalize harmless textual variants before validating a hostname."""
    # Don't casefold yet - that can turn ß into "ss" and hide that this was
    # an international domain to begin with.
    value = hostname.strip().translate(_DOT_TRANSLATION)
    if value.endswith(".."):
        return ""
    value = value.removesuffix(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value


def canonicalize_hostname(hostname: str | None) -> str:
    """Return a validated ASCII hostname, canonical IP literal, or ``""``.

    Case, a trailing root dot, and the IDNA dot variants are all treated as
    equivalent. Unicode labels get encoded to ASCII IDNA, IPv6 literals get
    compressed. Anything invalid (bad labels, a port mistaken for a
    hostname, a malformed IP) fails closed to an empty string.
    """
    if not hostname or not isinstance(hostname, str):
        return ""

    value = _hostname_text(hostname)
    if not value:
        return ""

    try:
        return ipaddress.ip_address(value).compressed.casefold()
    except ValueError:
        pass

    # A colon here isn't part of a hostname, and an all-numeric dotted value
    # that failed IPv4 validation (999.999.999.999) shouldn't fall back to
    # being treated as a DNS name.
    if ":" in value or ("." in value and re.fullmatch(r"[0-9.]+", value)):
        return ""

    labels = value.split(".")
    if any(not label for label in labels):
        return ""

    ascii_labels: list[str] = []
    try:
        for label in labels:
            ascii_label = label.encode("idna").decode("ascii").casefold()
            # Python's built-in IDNA codec maps a few modern IDNs (e.g. faß.de)
            # to unrelated ASCII instead of erroring. Reject those rather than
            # risk comparing the wrong origin.
            if any(not character.isascii() for character in label) and not ascii_label.startswith(
                "xn--"
            ):
                return ""
            if not _DNS_LABEL.fullmatch(ascii_label):
                return ""
            ascii_labels.append(ascii_label)
    except UnicodeError:
        return ""

    canonical = ".".join(ascii_labels)
    if len(canonical) > 253:
        return ""
    return canonical


def normalize_host(url: str) -> str:
    """Return the lowercase hostname of ``url`` without port, or "" if unknown."""
    if not url or not isinstance(url, str):
        return ""
    try:
        parts = urlsplit(url if "://" in url else "//" + url)
        return canonicalize_hostname(parts.hostname)
    except (UnicodeError, ValueError):
        return ""


def is_https(url: str) -> bool:
    """True only when ``url`` uses the secure ``https`` scheme."""
    return origin_of(url)[0] == "https"


def origin_of(url: str) -> tuple[str, str, int | None]:
    """Return the (scheme, host, port) origin triple for ``url``.

    Missing ports are filled in from the scheme's default so that equivalent
    URLs produce equal origins. Returns ("", "", None) for unusable input.
    """
    if not url or not isinstance(url, str):
        return _INVALID_ORIGIN
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.casefold()
        host = canonicalize_hostname(parts.hostname)
        port = parts.port
    except (UnicodeError, ValueError):
        # non-numeric port, unmatched IPv6 bracket, etc.
        return _INVALID_ORIGIN
    if not scheme or not host:
        return _INVALID_ORIGIN
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
    return (scheme, host, port)


def same_origin(url_a: str, url_b: str) -> bool:
    """True when both URLs share scheme, host, and (effective) port.

    An empty or unparseable URL is never the same origin as anything -- if
    we can't tell, treat it as cross-origin.
    """
    origin_a = origin_of(url_a)
    origin_b = origin_of(url_b)
    if origin_a == _INVALID_ORIGIN or origin_b == _INVALID_ORIGIN:
        return False
    return origin_a == origin_b


def _script_of(letter: str) -> str | None:
    """Return the major script name for a letter when it is known."""
    if not letter.isalpha():
        return None
    if letter.isascii():
        return "LATIN"
    name = unicodedata.name(letter, "")
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if script in name:
            return script
    return None


def is_suspicious_hostname(hostname: str | None) -> bool:
    """Flag hostname look-alike signals: punycode/IDNA labels, mixed
    Latin/Cyrillic/Greek letters in one label, or digit substitutions in a
    protected-email label. Ordinary ASCII hostnames and IPs never trigger
    this.
    """
    if not hostname or not isinstance(hostname, str):
        return False

    raw = _hostname_text(hostname)
    if not raw:
        return False
    # Check for non-ASCII before the stdlib IDNA conversion, since its
    # compatibility mappings could otherwise hide it.
    if any(not character.isascii() for character in raw):
        return True
    canonical = canonicalize_hostname(hostname)
    if not canonical:
        return False

    try:
        ipaddress.ip_address(canonical)
        return False
    except ValueError:
        pass

    canonical_labels = canonical.split(".")
    if any(label.startswith("xn--") for label in canonical_labels):
        return True

    for label in raw.split("."):
        scripts = {_script_of(character) for character in label}
        scripts.discard(None)
        if len(scripts) > 1:
            return True

    for label in canonical_labels:
        skeleton = label.translate(_DIGIT_CONFUSABLES)
        if skeleton != label and skeleton in _PROTECTED_EMAIL_LABELS:
            return True

    return False


def has_suspicious_hostname_nesting(hostname: str | None) -> bool:
    """Detect domain-like suffixes or excessive depth inside subdomains.

    ``login.bank.com.evil.net`` is suspicious because ``com`` shows up inside
    the subdomain part while the real registered domain is ``evil.net``.
    Five or more subdomain labels also counts as excessive. Not a real
    public-suffix-list check -- just recognizes common two-label country
    suffixes so ``portal.example.co.uk`` doesn't trip this.
    """
    canonical = canonicalize_hostname(hostname)
    if not canonical:
        return False

    try:
        ipaddress.ip_address(canonical)
        return False
    except ValueError:
        pass

    labels = canonical.split(".")
    if len(labels) < 3:
        return False

    final_pair = ".".join(labels[-2:])
    suffix_labels = 2 if final_pair in _COMMON_TWO_LABEL_SUFFIXES else 1
    registrable_index = len(labels) - suffix_labels - 1
    if registrable_index <= 0:
        return False

    subdomain_labels = labels[:registrable_index]
    if any(label in _DOMAIN_SUFFIX_MARKERS for label in subdomain_labels):
        return True
    return len(subdomain_labels) > _MAX_ORDINARY_SUBDOMAIN_LABELS


def has_qr_landing_signal(url: str | None, referrer: str | None = None) -> bool:
    """Return whether a direct navigation carries an explicit QR marker.

    Browsers don't expose whether a camera actually scanned a QR code, so
    this just looks for a direct navigation (empty referrer) plus a
    QR-specific query key, tracking value, or path segment.
    """
    if not url or not isinstance(url, str) or referrer:
        return False
    try:
        parts = urlsplit(url)
        if parts.scheme.casefold() not in {"http", "https"}:
            return False
        if not canonicalize_hostname(parts.hostname):
            return False
        query_pairs = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=100)
    except (UnicodeError, ValueError):
        return False

    for key, value in query_pairs:
        normalized_key = key.casefold()
        if normalized_key in _QR_QUERY_KEYS:
            return True
        if (
            normalized_key in _QR_TRACKING_KEYS
            and value.casefold() in _QR_TRACKING_VALUES
        ):
            return True

    try:
        path_segments = {
            segment.casefold()
            for segment in unquote(parts.path).split("/")
            if segment
        }
    except (UnicodeError, ValueError):
        return False
    return bool(path_segments & _QR_PATH_SEGMENTS)


def _decoded_path(url: str) -> tuple[str, str]:
    """Return ``(scheme, path)`` with at most two percent-decoding passes."""
    try:
        parts = urlsplit(url)
    except (UnicodeError, ValueError):
        return ("", "")
    path = parts.path
    for _ in range(2):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    return (parts.scheme.casefold(), path.casefold().rstrip(" ."))


def _has_download_extension(path: str, extensions: frozenset[str]) -> bool:
    return any(path.endswith(extension) for extension in extensions)


def looks_like_download_url(url: str | None) -> bool:
    """Return whether a target structurally resembles downloadable content."""
    if not url or not isinstance(url, str):
        return False
    scheme, path = _decoded_path(url)
    if scheme in _LOCAL_CONTENT_SCHEMES:
        return True
    if scheme and scheme not in {"http", "https"}:
        return False
    return _has_download_extension(path, _DOWNLOAD_EXTENSIONS)


def _resolved_target(page_url: str, target_url: str) -> str:
    try:
        return urljoin(page_url, target_url)
    except (TypeError, UnicodeError, ValueError):
        return ""


def is_risky_download_target(
    page_url: str | None,
    target_url: str | None,
    download_attribute: bool = False,
) -> bool:
    """Detect executable, script, local-content, or insecure download links."""
    if not isinstance(page_url, str) or not isinstance(target_url, str):
        return False
    resolved = _resolved_target(page_url, target_url)
    if not resolved or not (download_attribute or looks_like_download_url(resolved)):
        return False

    target_scheme, target_path = _decoded_path(resolved)
    if target_scheme in _RISKY_LINK_SCHEMES:
        return True
    if _has_download_extension(target_path, _RISKY_DOWNLOAD_EXTENSIONS):
        return True

    try:
        page_scheme = urlsplit(page_url).scheme.casefold()
    except (UnicodeError, ValueError):
        return False
    return page_scheme == "https" and target_scheme == "http"


def is_cross_origin_download(
    page_url: str | None,
    target_url: str | None,
    download_attribute: bool = False,
) -> bool:
    """Return whether a structurally identified download leaves page origin."""
    if not isinstance(page_url, str) or not isinstance(target_url, str):
        return False
    resolved = _resolved_target(page_url, target_url)
    if not resolved or not (download_attribute or looks_like_download_url(resolved)):
        return False
    scheme, _ = _decoded_path(resolved)
    if scheme not in {"http", "https"}:
        return True
    return not same_origin(page_url, resolved)
