"""Local threat checks.

``ThreatAnalyzer`` turns a :class:`SafeFeatureSummary` into a verdict using
simple local rules -- no network, no AI. Most pages are decided here, which
is what keeps WAM cheap and private. It also flags cases that are unclear
enough to be worth an optional AI call.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from privacy_guard import SafeFeatureSummary

# Severity ordering used to pick the overall level from several findings.
_SEVERITY = {"safe": 0, "info": 1, "warning": 2, "danger": 3}


@dataclass(frozen=True)
class ThreatFinding:
    """One concrete reason WAM is (or is not) concerned about a page."""

    code: str
    level: str  # "info" | "warning" | "danger"
    message: str
    advice: str


@dataclass(frozen=True)
class ThreatResult:
    """The analyzer's verdict for one page event."""

    level: str  # "safe" | "info" | "warning" | "danger" | "limited" | "unclear"
    findings: list[ThreatFinding] = field(default_factory=list)
    needs_ai: bool = False


def _overall_level(findings: list[ThreatFinding]) -> str:
    if not findings:
        return "safe"
    return max((f.level for f in findings), key=lambda lvl: _SEVERITY.get(lvl, 0))


class ThreatAnalyzer:
    """Applies local warning rules to a safe feature summary."""

    def analyze(self, summary: SafeFeatureSummary) -> ThreatResult:
        # Protected webmail pages are intentionally checked less, and never AI.
        if summary.protected_mode:
            return ThreatResult(
                level="limited",
                findings=[
                    ThreatFinding(
                        code="protected_mode_active",
                        level="info",
                        message="Protected mode: email content not scanned.",
                        advice="WAM checks only basic page safety on webmail sites.",
                    )
                ],
                needs_ai=False,
            )

        findings: list[ThreatFinding] = []

        # Look-alike hostname (punycode/IDN, mixed scripts, digit-swapped
        # webmail label) - escalate to danger if it's also asking for a password.
        if summary.hostname_looks_suspicious:
            findings.append(
                ThreatFinding(
                    code="lookalike_hostname",
                    level="danger" if summary.has_password_field else "warning",
                    message="This site's address looks like a look-alike of a trusted site.",
                    advice="Check the spelling of the web address carefully before continuing.",
                )
            )

        # Real domain hidden inside subdomains, or just too many of them.
        if summary.hostname_nesting_suspicious:
            findings.append(
                ThreatFinding(
                    code="suspicious_hostname_nesting",
                    level="danger" if summary.has_password_field else "warning",
                    message="This web address hides a different site inside a longer name.",
                    advice="Read the address from the right: the real site is the part before the final '/'.",
                )
            )

        # A password field on a non-HTTPS page is a serious red flag.
        if summary.has_password_field and not summary.is_https:
            findings.append(
                ThreatFinding(
                    code="insecure_password_field",
                    level="danger",
                    message="This page asks for a password over an insecure (HTTP) connection.",
                    advice="Do not enter your password. Look for 'https' and a lock icon.",
                )
            )

        # A login form that posts to a different site is classic phishing.
        if summary.has_password_field and summary.form_posts_cross_origin:
            findings.append(
                ThreatFinding(
                    code="cross_origin_login_form",
                    level="danger",
                    message="This login form sends your details to a different website.",
                    advice="Check the real address of the site before signing in.",
                )
            )
        elif summary.form_posts_cross_origin:
            findings.append(
                ThreatFinding(
                    code="cross_origin_form",
                    level="warning",
                    message="A form on this page submits to a different website.",
                    advice="Make sure you trust where this form is sending information.",
                )
            )

        # A plain insecure page (no password) is a milder warning.
        if not summary.is_https and not summary.has_password_field:
            findings.append(
                ThreatFinding(
                    code="insecure_page",
                    level="warning",
                    message="This page is not using a secure (HTTPS) connection.",
                    advice="Avoid entering personal information on insecure pages.",
                )
            )

        # Download link to an app/script file, or an insecure download
        # served over HTTP from an HTTPS page.
        if summary.has_risky_download_link:
            findings.append(
                ThreatFinding(
                    code="risky_download_link",
                    level="warning",
                    message="This page links to a download that could be unsafe (an app or script file).",
                    advice="Only download and open files from sources you trust.",
                )
            )

        # QR codes are a common way to hide where a link actually goes.
        if summary.has_qr_landing_signal and summary.has_password_field:
            findings.append(
                ThreatFinding(
                    code="qr_landing_login",
                    level="warning",
                    message="You may have reached this login page from a QR code.",
                    advice="QR codes can hide the real address. Check the site name before signing in.",
                )
            )
        elif summary.has_qr_landing_signal:
            findings.append(
                ThreatFinding(
                    code="qr_landing",
                    level="info",
                    message="This page may have been opened from a QR code.",
                    advice="Check that the web address is the one you expected.",
                )
            )

        if findings:
            return ThreatResult(level=_overall_level(findings), findings=findings, needs_ai=False)

        # Nothing fired, but a login form that looks fine is still the
        # ambiguous case AI help is actually useful for.
        if summary.event_type == "login_form":
            return ThreatResult(
                level="unclear",
                findings=[
                    ThreatFinding(
                        code="login_form_detected",
                        level="info",
                        message="A login form was detected and passed local checks.",
                        advice="Confirm the website address matches the service you expect.",
                    )
                ],
                needs_ai=True,
            )

        # Nothing notable.
        return ThreatResult(level="safe", findings=[], needs_ai=False)
