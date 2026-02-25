from __future__ import annotations

from collections import Counter
from typing import Dict

_COUNTER = Counter()


def increment(name: str) -> None:
    key = str(name or "").strip()
    if not key:
        return
    _COUNTER[key] += 1


def snapshot() -> Dict[str, int]:
    return dict(_COUNTER)
