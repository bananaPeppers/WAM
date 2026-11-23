"""Optional connection to Google Gemini.

Disabled unless an API key is configured, so the rest of the app works fine
without any key or network access. Only the approved, non-personal
``SafeFeatureSummary`` fields are ever passed in here -- no password, page
text, or full URL.
"""

from __future__ import annotations


class AIUnavailableError(Exception):
    """Raised when AI help cannot be provided (no key, quota, or network)."""


class GeminiClient:
    """Thin wrapper around Google Gemini. Disabled without an API key."""

    def __init__(self, api_key: str | None = None, model: str = "gemini-1.5-flash") -> None:
        self.api_key = api_key
        self.model = model

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def explain(self, safe_payload: dict) -> str:
        """Return a short, plain-language note about the safe feature flags.

        Raises :class:`AIUnavailableError` if no key is configured or the call
        fails, so the caller can fall back to local-only warnings.
        """
        if not self.api_key:
            raise AIUnavailableError("No Gemini API key configured.")

        try:
            # Lazy import so google-generativeai doesn't need to be installed
            # when no key is configured.
            import google.generativeai as genai  # type: ignore

            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel(self.model)
            prompt = (
                "You are a browser safety helper. Using only these non-personal "
                "security flags, explain in one or two plain sentences what a "
                "non-technical user should check. Do not invent details.\n"
                f"Flags: {safe_payload}"
            )
            response = model.generate_content(prompt)
            text = (getattr(response, "text", "") or "").strip()
            if not text:
                raise AIUnavailableError("Gemini returned an empty response.")
            return text
        except AIUnavailableError:
            raise
        except Exception as error:  # network, auth, quota, import, ...
            raise AIUnavailableError(f"Gemini call failed: {error}") from error
