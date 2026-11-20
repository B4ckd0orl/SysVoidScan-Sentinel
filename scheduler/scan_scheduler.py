import logging
#!/usr/bin/env python3
"""
Scan Scheduler for SysVoidScan v3.0 Sentinel.
Cron-like scheduling for automated recurring scans.
"""

import json
import os
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field, asdict
import uuid
import signal


@dataclass
class ScheduledScan:
    id: str
    target: str
    scan_type: str
    cron_expression: str
    options: Dict = field(default_factory=dict)
    enabled: bool = True
    last_run: Optional[float] = None
    next_run: Optional[float] = None
    notifications: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


CRON_PRESETS = {
    "hourly": "0 * * * *",
    "every_6h": "0 */6 * * *",
    "daily": "0 2 * * *",
    "daily_midnight": "0 0 * * *",
    "weekly": "0 2 * * 0",
    "weekly_monday": "0 2 * * 1",
    "biweekly": "0 2 1,15 * *",
    "monthly": "0 2 1 * *",
    "quarterly": "0 2 1 1,4,7,10 *",
}


class ScanScheduler:
    """Cron-like scheduler for automated security scans."""

    def __init__(self, storage_path: str = "data/scheduled_scans.json"):
        self.storage_path = storage_path
        self.scheduled_scans: Dict[str, ScheduledScan] = {}
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._scan_callback: Optional[Callable] = None
        self._interval = 60
        self._load()

    def _load(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r") as f:
                    data = json.load(f)
                for scan_id, scan_data in data.items():
                    self.scheduled_scans[scan_id] = ScheduledScan(**scan_data)
            except Exception:
                self.scheduled_scans = {}

    def _save(self):
        os.makedirs(os.path.dirname(self.storage_path) or ".", exist_ok=True)
        data = {sid: scan.to_dict() for sid, scan in self.scheduled_scans.items()}
        with open(self.storage_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _parse_cron(self, cron_expr: str) -> Dict:
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return {}
        return {
            "minute": parts[0],
            "hour": parts[1],
            "day": parts[2],
            "month": parts[3],
            "weekday": parts[4],
        }

    def _cron_matches(self, cron_expr: str, dt: datetime) -> bool:
        parts = self._parse_cron(cron_expr)
        if not parts:
            return False
        checks = [
            (parts["minute"], dt.minute),
            (parts["hour"], dt.hour),
            (parts["day"], dt.day),
            (parts["month"], dt.month),
            (parts["weekday"], dt.weekday()),
        ]
        for pattern, value in checks:
            if pattern == "*":
                continue
            if "/" in pattern:
                _, step = pattern.split("/")
                if value % int(step) != 0:
                    return False
            elif "-" in pattern:
                start, end = pattern.split("-")
                if not (int(start) <= value <= int(end)):
                    return False
            elif "," in pattern:
                if value not in [int(x) for x in pattern.split(",")]:
                    return False
            else:
                if value != int(pattern):
                    return False
        return True

    def _calculate_next_run(self, cron_expr: str, after: Optional[datetime] = None) -> float:
        if after is None:
            after = datetime.now()
        check_time = after + timedelta(minutes=1)
        check_time = check_time.replace(second=0, microsecond=0)
        for _ in range(60 * 24 * 7):
            if self._cron_matches(cron_expr, check_time):
                return check_time.timestamp()
            check_time += timedelta(minutes=1)
        return time.time() + 86400

    def set_scan_callback(self, callback: Callable):
        self._scan_callback = callback

    def add_scan(self, target: str, scan_type: str = "full", cron: str = "daily", options: Optional[Dict] = None, notifications: Optional[List[str]] = None, tags: Optional[List[str]] = None) -> str:
        scan_id = str(uuid.uuid4())[:8]
        cron_expr = CRON_PRESETS.get(cron, cron)
        next_run = self._calculate_next_run(cron_expr)
        scan = ScheduledScan(
            id=scan_id,
            target=target,
            scan_type=scan_type,
            cron_expression=cron_expr,
            options=options or {},
            next_run=next_run,
            notifications=notifications or [],
            tags=tags or [],
        )
        self.scheduled_scans[scan_id] = scan
        self._save()
        return scan_id

    def remove_scan(self, scan_id: str) -> bool:
        if scan_id in self.scheduled_scans:
            del self.scheduled_scans[scan_id]
            self._save()
            return True
        return False

    def enable_scan(self, scan_id: str) -> bool:
        if scan_id in self.scheduled_scans:
            self.scheduled_scans[scan_id].enabled = True
            self._save()
            return True
        return False

    def disable_scan(self, scan_id: str) -> bool:
        if scan_id in self.scheduled_scans:
            self.scheduled_scans[scan_id].enabled = False
            self._save()
            return True
        return False

    def get_schedule(self) -> List[Dict]:
        result = []
        for scan in self.scheduled_scans.values():
            d = scan.to_dict()
            if scan.last_run:
                d["last_run_human"] = datetime.fromtimestamp(scan.last_run).strftime("%Y-%m-%d %H:%M:%S")
            if scan.next_run:
                d["next_run_human"] = datetime.fromtimestamp(scan.next_run).strftime("%Y-%m-%d %H:%M:%S")
                d["next_run_in"] = f"{int((scan.next_run - time.time()) / 60)} minutes"
            result.append(d)
        return result

    def _tick(self):
        now = time.time()
        for scan_id, scan in list(self.scheduled_scans.items()):
            if not scan.enabled or not scan.next_run:
                continue
            if now >= scan.next_run:
                scan.last_run = now
                scan.next_run = self._calculate_next_run(scan.cron_expression, datetime.now())
                self._save()
                if self._scan_callback:
                    try:
                        self._scan_callback(scan)
                    except Exception:
                        logging.exception("scan_scheduler.py: exception")
                        pass

    def _loop(self):
        while self.running:
            self._tick()
            time.sleep(self._interval)

    def start(self, interval: int = 60):
        if self.running:
            return
        self.running = True
        self._interval = interval
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def run_now(self, scan_id: str) -> bool:
        if scan_id in self.scheduled_scans:
            scan = self.scheduled_scans[scan_id]
            if self._scan_callback:
                try:
                    self._scan_callback(scan)
                    scan.last_run = time.time()
                    scan.next_run = self._calculate_next_run(scan.cron_expression, datetime.now())
                    self._save()
                    return True
                except Exception:
                    return False
        return False

    def get_preset_crons(self) -> Dict[str, str]:
        return dict(CRON_PRESETS)

    def list_tags(self) -> List[str]:
        tags = set()
        for scan in self.scheduled_scans.values():
            tags.update(scan.tags)
        return sorted(tags)

    def get_scans_by_tag(self, tag: str) -> List[ScheduledScan]:
        return [s for s in self.scheduled_scans.values() if tag in s.tags]
