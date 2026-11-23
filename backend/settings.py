"""Runtime settings for the WAM backend.

Values come, in order of priority, from environment variables, then an
optional ``config.py`` you create from ``config.example.py`` (git-ignored,
holds your self-hosted MariaDB details), then safe defaults. None of this is
required to run the app.
"""

from __future__ import annotations

import os

try:  # your private config, if present
    import config as _user_config  # type: ignore
except Exception:  # noqa: BLE001 - any import problem means "no user config"
    _user_config = None


def _from_user(name: str, default=None):
    return getattr(_user_config, name, default) if _user_config else default


def get_database_config() -> dict | None:
    """Return the MariaDB connection dict, or None to use in-memory storage."""
    env_host = os.environ.get("WAM_DB_HOST")
    if env_host:
        return {
            "host": env_host,
            "port": int(os.environ.get("WAM_DB_PORT", "3306")),
            "user": os.environ.get("WAM_DB_USER", ""),
            "password": os.environ.get("WAM_DB_PASSWORD", ""),
            "database": os.environ.get("WAM_DB_NAME", ""),
        }
    return _from_user("DATABASE", None)


def get_gemini_api_key() -> str | None:
    return os.environ.get("WAM_GEMINI_API_KEY") or _from_user("GEMINI_API_KEY", None)


def get_ai_daily_limit() -> int:
    env_value = os.environ.get("WAM_AI_DAILY_LIMIT")
    if env_value:
        return int(env_value)
    return int(_from_user("AI_DAILY_LIMIT", 5))
