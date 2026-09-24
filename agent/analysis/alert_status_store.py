from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Literal

AlertStatus = Literal["resolved", "deleted"]


class AlertStatusStore:
    """
    Tracks a small piece of state Wazuh itself has no concept of:
    whether an analyst has resolved or deleted an alert from the
    dashboard's view.

    Wazuh's own alert index is never written to or mutated here, and
    "deleted" does not erase anything on disk -- it only records that
    this alert_id should stay hidden from the dashboard. The
    underlying alert, analysis log entry, and any audit/decision log
    entries tied to it are untouched, so nothing needed for the audit
    trail is ever lost through this store.
    """

    def __init__(self, path: str | Path = "logs/alert_status.json") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}

        text = self.path.read_text(encoding="utf-8").strip()
        return json.loads(text) if text else {}

    def _write(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_all(self) -> dict[str, Any]:
        with self._lock:
            return self._read()

    def set_status(
        self, alert_id: str, status: AlertStatus, by: str
    ) -> dict[str, Any]:
        with self._lock:
            data = self._read()
            entry = {"status": status, "by": by, "at": time.time()}
            data[alert_id] = entry
            self._write(data)
            return entry
