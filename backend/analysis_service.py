"""The warning pipeline: ties the Privacy Guard, Threat Analyzer, and AI
budget together with an (injectable) AI client.

For one page event, decides whether the local verdict is enough or whether
a single optional AI call is worth making -- and makes sure protected
webmail pages never reach the AI.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ai_client import AIUnavailableError
from ai_budget import AIBudgetManager
from privacy_guard import PrivacyGuard, SafeFeatureSummary
from threat_rules import ThreatAnalyzer, ThreatFinding

_LOCAL_ONLY_NOTE = "AI check unavailable—local checks only."


@dataclass(frozen=True)
class AnalysisResult:
    """Final verdict returned to the gateway / UI."""

    level: str
    source: str  # local | ai | ai-cached | local-protected | local-only
    findings: list[ThreatFinding] = field(default_factory=list)
    explanation: str | None = None
    note: str | None = None

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "source": self.source,
            "findings": [asdict(f) for f in self.findings],
            "explanation": self.explanation,
            "note": self.note,
        }


class AnalysisService:
    def __init__(
        self,
        guard: PrivacyGuard,
        analyzer: ThreatAnalyzer,
        budget: AIBudgetManager,
        ai_client,
    ) -> None:
        self.guard = guard
        self.analyzer = analyzer
        self.budget = budget
        self.ai_client = ai_client

    def analyze_raw(self, raw_signals: dict) -> AnalysisResult:
        """Build a safe summary from raw signals, then analyze it."""
        summary = self.guard.build_safe_summary(raw_signals)
        return self.analyze_summary(summary)

    def analyze_summary(self, summary: SafeFeatureSummary) -> AnalysisResult:
        verdict = self.analyzer.analyze(summary)

        # Protected webmail: local only, never any AI call.
        if summary.protected_mode:
            return AnalysisResult(
                level=verdict.level,
                source="local-protected",
                findings=verdict.findings,
                note="Protected mode: email content not scanned.",
            )

        # A clear local verdict needs no AI.
        if not verdict.needs_ai:
            return AnalysisResult(
                level=verdict.level,
                source="local",
                findings=verdict.findings,
            )

        # Unclear case: reuse a cached AI result if we have one.
        key = summary.cache_key()
        cached = self.budget.cache_get(key)
        if cached is not None:
            return AnalysisResult(
                level=cached.level,
                source="ai-cached",
                findings=cached.findings,
                explanation=cached.explanation,
            )

        # Respect the shared daily budget before calling out.
        if not self.budget.can_call():
            return AnalysisResult(
                level="warning",
                source="local-only",
                findings=verdict.findings,
                note=_LOCAL_ONLY_NOTE,
            )

        try:
            explanation = self.ai_client.explain(summary.to_ai_payload())
        except AIUnavailableError:
            return AnalysisResult(
                level="warning",
                source="local-only",
                findings=verdict.findings,
                note=_LOCAL_ONLY_NOTE,
            )

        self.budget.record_call()
        result = AnalysisResult(
            level="warning",
            source="ai",
            findings=verdict.findings,
            explanation=explanation,
        )
        self.budget.cache_put(key, result)
        return result
