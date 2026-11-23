"""Makes sure private information never leaves the browser.

Recognises protected webmail hosts (Gmail / Outlook) by exact hostname, and
builds a ``SafeFeatureSummary`` containing only approved, non-personal
fields -- a password, username, page text, or full URL never make it onto
that object in the first place.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from url_utils import (
    canonicalize_hostname,
    has_suspicious_hostname_nesting,
    is_suspicious_hostname,
)

# --- Allow-list and protected hosts -----------------------------------------

# The ONLY input keys the Privacy Guard will copy into a safe summary.
ALLOWED_INPUT_FIELDS = frozenset(
    {
        "event_type",
        "is_https",
        "has_password_field",
        "form_posts_cross_origin",
        "link_count",
        "has_qr_landing_signal",
        "has_download_link",
        "has_risky_download_link",
        "has_cross_origin_download_link",
        "hostname",  # used locally to decide protected mode; never forwarded
    }
)

# Keys that are obviously personal. Listed explicitly so the gateway can give a
# clear "we do not accept this" message instead of a generic rejection.
PERSONAL_FIELDS = frozenset(
    {
        "password",
        "username",
        "email",
        "phone",
        "phone_number",
        "page_text",
        "full_url",
        "url",
        "message",
        "card_number",
        "credit_card",
        "cookie",
        "field_value",
        "field_values",
        "form_values",
    }
)

# Exact hostnames that receive the special, content-free "protected mode".
PROTECTED_EMAIL_HOSTS = frozenset(
    {
        "mail.google.com",
        "outlook.live.com",
        "outlook.office.com",
    }
)


def is_protected_email_host(hostname: str | None) -> bool:
    """True only for an exact protected webmail hostname.

    A look-alike such as ``mail.google.com.evil.com`` or ``rnail.google.com``
    must return False, or a phishing page could pass itself off as webmail.
    """
    return canonicalize_hostname(hostname) in PROTECTED_EMAIL_HOSTS


def find_personal_fields(payload: dict) -> list[str]:
    """Return any keys in ``payload`` that name personal information."""
    if not isinstance(payload, dict):
        return []
    return sorted(k for k in payload if str(k).lower() in PERSONAL_FIELDS)


def unexpected_fields(payload: dict) -> list[str]:
    """Return any keys in ``payload`` that are not on the allow-list."""
    if not isinstance(payload, dict):
        return []
    return sorted(k for k in payload if k not in ALLOWED_INPUT_FIELDS)


# --- The safe object that may cross the network -----------------------------


@dataclass(frozen=True)
class SafeFeatureSummary:
    """Approved, non-personal description of a page event.

    No password, username, page text, hostname, or full URL here on
    purpose. ``host_category`` records only whether the page is a
    recognised email site, not which one.
    """

    event_type: str
    is_https: bool
    has_password_field: bool
    form_posts_cross_origin: bool
    link_count: int
    host_category: str  # "normal" or "protected_email"
    protected_mode: bool
    # True when the hostname looks like a phishing look-alike (punycode/IDN,
    # mixed scripts, digit-swapped webmail labels). A boolean only -- the
    # hostname itself is still never stored or forwarded.
    hostname_looks_suspicious: bool = False
    # True when the address structure is deceptive, e.g. a real domain hidden
    # inside subdomains (login.bank.com.evil.net) or excessive nesting.
    hostname_nesting_suspicious: bool = False
    # Non-personal link/QR signals from the scanner (no href/URL is ever stored).
    has_qr_landing_signal: bool = False
    has_download_link: bool = False
    has_risky_download_link: bool = False
    has_cross_origin_download_link: bool = False

    def to_ai_payload(self) -> dict:
        """The exact dict that may be forwarded for optional AI analysis.

        It is just the approved fields; there is nothing to strip because
        nothing personal was ever stored on this object.
        """
        return asdict(self)

    def cache_key(self) -> str:
        """A stable key for caching identical, repeated warnings."""
        return "|".join(
            str(part)
            for part in (
                self.event_type,
                self.is_https,
                self.has_password_field,
                self.form_posts_cross_origin,
                self.host_category,
            )
        )


class PrivacyGuard:
    """Builds :class:`SafeFeatureSummary` objects from raw browser signals."""

    def build_safe_summary(self, raw_signals: dict) -> SafeFeatureSummary:
        """Copy only approved fields into a safe summary.

        Personal or unexpected keys in ``raw_signals`` are ignored. The
        hostname, if given, is used to decide protected mode and the host
        category, then discarded -- it never appears on the returned object.
        """
        if not isinstance(raw_signals, dict):
            raise ValueError("raw_signals must be a dict of page signals.")

        hostname = raw_signals.get("hostname")
        protected = is_protected_email_host(hostname)
        # A recognised (exact) protected host is never a look-alike.
        suspicious = False if protected else is_suspicious_hostname(hostname)
        nested = False if protected else has_suspicious_hostname_nesting(hostname)

        return SafeFeatureSummary(
            event_type=str(raw_signals.get("event_type", "other")),
            is_https=bool(raw_signals.get("is_https", False)),
            has_password_field=bool(raw_signals.get("has_password_field", False)),
            form_posts_cross_origin=bool(
                raw_signals.get("form_posts_cross_origin", False)
            ),
            link_count=int(raw_signals.get("link_count", 0) or 0),
            host_category="protected_email" if protected else "normal",
            protected_mode=protected,
            hostname_looks_suspicious=suspicious,
            hostname_nesting_suspicious=nested,
            has_qr_landing_signal=bool(raw_signals.get("has_qr_landing_signal", False)),
            has_download_link=bool(raw_signals.get("has_download_link", False)),
            has_risky_download_link=bool(
                raw_signals.get("has_risky_download_link", False)
            ),
            has_cross_origin_download_link=bool(
                raw_signals.get("has_cross_origin_download_link", False)
            ),
        )
