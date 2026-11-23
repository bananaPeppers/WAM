"""Flask app and entry point.

This is the boundary between the browser extension and the backend: it
validates the incoming payload, rejects anything personal or off the
allow-list, runs the analysis pipeline, and keeps an anonymous usage
counter. The AI key and daily budget live inside the service it calls.
"""

from __future__ import annotations

from flask import Flask, jsonify, request

import settings
from ai_budget import AIBudgetManager
from ai_client import GeminiClient
from analysis_service import AnalysisService
from privacy_guard import PrivacyGuard, find_personal_fields, unexpected_fields
from repository import ThreatRepository, build_repository
from threat_rules import ThreatAnalyzer

REQUIRED_FIELDS = ("event_type",)


def build_default_service() -> AnalysisService:
    """Wire up the real pipeline from runtime settings."""
    return AnalysisService(
        guard=PrivacyGuard(),
        analyzer=ThreatAnalyzer(),
        budget=AIBudgetManager(daily_limit=settings.get_ai_daily_limit()),
        ai_client=GeminiClient(api_key=settings.get_gemini_api_key()),
    )


def create_app(
    service: AnalysisService | None = None,
    repository: ThreatRepository | None = None,
) -> Flask:
    app = Flask(__name__)
    service = service or build_default_service()
    repository = repository or build_repository(settings.get_database_config())

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/rules")
    def rules():
        return jsonify({"rules": repository.get_rules()})

    @app.get("/stats")
    def stats():
        return jsonify({"counts": repository.get_counts()})

    @app.post("/analyze")
    def analyze():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "A JSON object body is required."}), 400

        # Privacy first: refuse anything personal or off the allow-list.
        personal = find_personal_fields(payload)
        if personal:
            return (
                jsonify(
                    {
                        "error": "Personal information is not accepted.",
                        "fields": personal,
                    }
                ),
                400,
            )
        unexpected = unexpected_fields(payload)
        if unexpected:
            return (
                jsonify({"error": "Unexpected fields.", "fields": unexpected}),
                400,
            )

        missing = [name for name in REQUIRED_FIELDS if name not in payload]
        if missing:
            return (
                jsonify({"error": "Missing required fields.", "fields": missing}),
                400,
            )

        try:
            result = service.analyze_raw(payload)
        except ValueError as error:
            return jsonify({"error": str(error)}), 400

        repository.increment_counter(result.source)
        return jsonify(result.to_dict()), 200

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=True)
