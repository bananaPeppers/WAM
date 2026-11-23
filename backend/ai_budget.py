"""Keeps optional AI usage cheap and predictable.

Enforces a shared daily call limit and caches results so an identical
warning doesn't spend budget twice. ``clock`` is injectable so the current
day doesn't have to come from the real system clock.
"""

from __future__ import annotations

from datetime import date
from typing import Callable


class AIBudgetManager:
    def __init__(
        self,
        daily_limit: int = 5,
        clock: Callable[[], date] | None = None,
    ) -> None:
        self.daily_limit = daily_limit
        self._clock = clock or date.today
        self._count_by_day: dict[str, int] = {}
        self._cache: dict[str, object] = {}

    def _today(self) -> str:
        return self._clock().isoformat()

    def remaining(self) -> int:
        """Calls still allowed today (never negative)."""
        used = self._count_by_day.get(self._today(), 0)
        return max(0, self.daily_limit - used)

    def can_call(self) -> bool:
        """True when at least one AI call is still within today's budget."""
        return self.remaining() > 0

    def record_call(self) -> None:
        """Count one AI call against today's budget."""
        today = self._today()
        self._count_by_day[today] = self._count_by_day.get(today, 0) + 1

    def cache_get(self, key: str):
        """Return a cached result for ``key`` or ``None`` on a miss."""
        return self._cache.get(key)

    def cache_put(self, key: str, value) -> None:
        """Remember a result so an identical case need not call AI again."""
        self._cache[key] = value
