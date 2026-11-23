"""Shared-data storage: threat rules and anonymous usage totals.

Stores only the shared security rules and anonymous daily counts -- never
private browsing history. Sits behind a small interface so the self-hosted
MariaDB backend can be swapped for an in-memory store when no database is
configured.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

# Shared, non-personal rules surfaced to the extension. These describe the same
# local checks the analyzer performs, as human-readable guidance.
DEFAULT_RULES = [
    {
        "code": "insecure_password_field",
        "level": "danger",
        "message": "Password field on an insecure (HTTP) page.",
    },
    {
        "code": "cross_origin_login_form",
        "level": "danger",
        "message": "Login form submits to a different website.",
    },
    {
        "code": "cross_origin_form",
        "level": "warning",
        "message": "Form submits to a different website.",
    },
    {
        "code": "insecure_page",
        "level": "warning",
        "message": "Page is not served over HTTPS.",
    },
]


@runtime_checkable
class ThreatRepository(Protocol):
    def get_rules(self) -> list[dict]:
        """Return the shared threat rules."""

    def increment_counter(self, name: str) -> None:
        """Add one to an anonymous daily counter."""

    def get_counts(self) -> dict[str, int]:
        """Return today's anonymous counters."""


class InMemoryThreatRepository:
    """Default repository: keeps rules and counts in memory. No setup needed."""

    def __init__(self, rules: list[dict] | None = None) -> None:
        self._rules = list(rules if rules is not None else DEFAULT_RULES)
        self._counts: dict[str, int] = {}

    def get_rules(self) -> list[dict]:
        return list(self._rules)

    def increment_counter(self, name: str) -> None:
        self._counts[name] = self._counts.get(name, 0) + 1

    def get_counts(self) -> dict[str, int]:
        return dict(self._counts)


class MariaDBThreatRepository:
    """Storage backed by a self-hosted MariaDB server.

    PyMySQL is imported lazily so this module still loads when the driver
    isn't installed -- it's only needed if this repository actually gets used.
    """

    def __init__(self, database_config: dict) -> None:
        self.config = database_config
        self._ensure_schema()

    def _connect(self):
        import pymysql  # lazy import; only needed with a real DB

        return pymysql.connect(
            host=self.config.get("host", "127.0.0.1"),
            port=int(self.config.get("port", 3306)),
            user=self.config["user"],
            password=self.config["password"],
            database=self.config["database"],
            autocommit=True,
            cursorclass=pymysql.cursors.DictCursor,
        )

    def _ensure_schema(self) -> None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS threat_rules (
                        code    VARCHAR(64) PRIMARY KEY,
                        level   VARCHAR(16) NOT NULL,
                        message VARCHAR(255) NOT NULL
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS usage_counters (
                        day   DATE NOT NULL,
                        name  VARCHAR(64) NOT NULL,
                        total INT NOT NULL DEFAULT 0,
                        PRIMARY KEY (day, name)
                    )
                    """
                )
                for rule in DEFAULT_RULES:
                    cursor.execute(
                        """
                        INSERT IGNORE INTO threat_rules (code, level, message)
                        VALUES (%s, %s, %s)
                        """,
                        (rule["code"], rule["level"], rule["message"]),
                    )

    def get_rules(self) -> list[dict]:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT code, level, message FROM threat_rules")
                return list(cursor.fetchall())

    def increment_counter(self, name: str) -> None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO usage_counters (day, name, total)
                    VALUES (CURDATE(), %s, 1)
                    ON DUPLICATE KEY UPDATE total = total + 1
                    """,
                    (name,),
                )

    def get_counts(self) -> dict[str, int]:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT name, total FROM usage_counters WHERE day = CURDATE()"
                )
                return {row["name"]: row["total"] for row in cursor.fetchall()}


def build_repository(database_config: dict | None) -> ThreatRepository:
    """Return a MariaDB repository when configured and reachable, else memory.

    Falls back to in-memory storage so the server still starts even if the
    database is temporarily unreachable.
    """
    if not database_config:
        return InMemoryThreatRepository()
    try:
        return MariaDBThreatRepository(database_config)
    except Exception as error:  # driver missing, DB unreachable, bad config
        print(f"[WAM] MariaDB unavailable ({error}); using in-memory storage.")
        return InMemoryThreatRepository()
