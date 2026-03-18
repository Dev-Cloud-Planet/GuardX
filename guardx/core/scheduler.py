"""
GuardX Scan Scheduler Module
Manages scheduled and recurring security scans using cron expressions.
"""

import sqlite3
import json
import threading
import time
import uuid
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Callable


class CronParser:
    """Simple cron expression parser for scheduling.

    Supports 5-field cron format: minute hour day_of_month month day_of_week
    Examples:
      - "0 9 * * *" - Every day at 9:00 AM
      - "0 9 * * 1-5" - Weekdays at 9:00 AM
      - "30 8 * * 1" - Every Monday at 8:30 AM
    """

    def __init__(self, cron_expr: str):
        """Parse cron expression.

        Args:
            cron_expr: 5-field cron string
        """
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {cron_expr}")

        self.minute = self._parse_field(parts[0], 0, 59)
        self.hour = self._parse_field(parts[1], 0, 23)
        self.day = self._parse_field(parts[2], 1, 31)
        self.month = self._parse_field(parts[3], 1, 12)
        self.weekday = self._parse_field(parts[4], 0, 6)  # 0=Monday, 6=Sunday

    def _parse_field(self, field: str, min_val: int, max_val: int) -> List[int]:
        """Parse single cron field.

        Args:
            field: Field string (e.g., "0", "*", "1-5", "*/2")
            min_val: Minimum allowed value
            max_val: Maximum allowed value

        Returns:
            List of valid values for this field
        """
        if field == "*":
            return list(range(min_val, max_val + 1))

        if field.startswith("*/"):
            # Handle step values like */2
            try:
                step = int(field.split("/")[1])
                return list(range(min_val, max_val + 1, step))
            except (ValueError, IndexError):
                raise ValueError(f"Invalid step field: {field}")

        if "-" in field:
            # Handle ranges like 1-5
            try:
                start, end = field.split("-")
                start, end = int(start), int(end)
                return list(range(start, end + 1))
            except (ValueError, IndexError):
                raise ValueError(f"Invalid range field: {field}")

        # Single value
        try:
            val = int(field)
            if min_val <= val <= max_val:
                return [val]
            raise ValueError(f"Value {val} out of range [{min_val}, {max_val}]")
        except ValueError:
            raise ValueError(f"Invalid field: {field}")

    def should_run(self, dt: datetime) -> bool:
        """Check if a cron job should run at given datetime.

        Args:
            dt: Datetime to check

        Returns:
            True if job should run at this time
        """
        # Python weekday: 0=Monday, 6=Sunday
        # Cron weekday: 0=Monday, 6=Sunday (same)
        return (
            dt.minute in self.minute and
            dt.hour in self.hour and
            dt.day in self.day and
            dt.month in self.month and
            dt.weekday() in self.weekday
        )


class ScanScheduler:
    """Manages scheduled recurring scans.

    Tracks cron schedules, runs scans on schedule, and stores run history.
    """

    def __init__(self, db_path: str = None):
        """Initialize scan scheduler.

        Args:
            db_path: Path to SQLite database for schedules.
                    Defaults to ~/.guardx/schedules.db
        """
        if db_path is None:
            guardx_dir = Path.home() / ".guardx"
            guardx_dir.mkdir(exist_ok=True)
            db_path = guardx_dir / "schedules.db"

        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._callback = None

        self._init_db()

    def _get_conn(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        conn = self._get_conn()
        cursor = conn.cursor()

        # Schedules table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                cron_expr TEXT NOT NULL,
                phases TEXT NOT NULL,
                name TEXT,
                created_at TEXT NOT NULL,
                enabled INTEGER DEFAULT 1
            )
        """)

        # Schedule history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schedule_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                schedule_id TEXT NOT NULL,
                last_run TEXT,
                next_run TEXT,
                run_count INTEGER DEFAULT 0,
                last_status TEXT,
                FOREIGN KEY(schedule_id) REFERENCES schedules(id) ON DELETE CASCADE
            )
        """)

        conn.commit()
        conn.close()

    def set_callback(self, callback: Callable[[str], None]) -> None:
        """Set callback function to execute when scheduled scan runs.

        Args:
            callback: Function(schedule_id) to call when scan should run
        """
        self._callback = callback

    def add_schedule(self, target: str, cron_expr: str, phases: List[str],
                    name: str = "") -> str:
        """Add a new scheduled scan.

        Args:
            target: Target URL or IP for scan
            cron_expr: 5-field cron expression (e.g., "0 9 * * *")
            phases: List of phases to execute (e.g., ["attack", "defense"])
            name: Optional name for this schedule

        Returns:
            schedule_id (UUID)

        Raises:
            ValueError: If cron expression is invalid or phases are invalid
        """
        # Validate cron expression
        try:
            CronParser(cron_expr)
        except ValueError as e:
            raise ValueError(f"Invalid cron expression: {str(e)}")

        # Validate phases
        valid_phases = {"attack", "defense", "report"}
        if not all(p in valid_phases for p in phases):
            raise ValueError(f"Invalid phase. Must be one of: {valid_phases}")

        schedule_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO schedules (id, target, cron_expr, phases, name, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (schedule_id, target, cron_expr, json.dumps(phases), name, now))

            # Create history entry
            cursor.execute("""
                INSERT INTO schedule_history (schedule_id, run_count)
                VALUES (?, 0)
            """, (schedule_id,))

            conn.commit()
            conn.close()

        return schedule_id

    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a scheduled scan.

        Args:
            schedule_id: ID of schedule to remove

        Returns:
            True if schedule was removed, False if not found
        """
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM schedules WHERE id = ?", (schedule_id,))
            if not cursor.fetchone():
                conn.close()
                return False

            cursor.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
            conn.commit()
            conn.close()

        return True

    def get_schedule(self, schedule_id: str) -> Optional[Dict]:
        """Get a specific schedule.

        Args:
            schedule_id: ID of schedule to retrieve

        Returns:
            Schedule dictionary or None if not found
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT s.*, h.last_run, h.next_run, h.run_count, h.last_status
            FROM schedules s
            LEFT JOIN schedule_history h ON s.id = h.schedule_id
            WHERE s.id = ?
        """, (schedule_id,))

        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return {
            'id': row['id'],
            'target': row['target'],
            'cron_expr': row['cron_expr'],
            'phases': json.loads(row['phases']),
            'name': row['name'],
            'created_at': row['created_at'],
            'enabled': bool(row['enabled']),
            'last_run': row['last_run'],
            'next_run': row['next_run'],
            'run_count': row['run_count'],
            'last_status': row['last_status']
        }

    def list_schedules(self) -> List[Dict]:
        """List all scheduled scans.

        Returns:
            List of schedule dictionaries
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT s.*, h.last_run, h.next_run, h.run_count, h.last_status
            FROM schedules s
            LEFT JOIN schedule_history h ON s.id = h.schedule_id
            ORDER BY s.created_at DESC
        """)

        rows = cursor.fetchall()
        conn.close()

        schedules = []
        for row in rows:
            schedules.append({
                'id': row['id'],
                'target': row['target'],
                'cron_expr': row['cron_expr'],
                'phases': json.loads(row['phases']),
                'name': row['name'],
                'created_at': row['created_at'],
                'enabled': bool(row['enabled']),
                'last_run': row['last_run'],
                'next_run': row['next_run'],
                'run_count': row['run_count'],
                'last_status': row['last_status']
            })

        return schedules

    def start(self) -> None:
        """Start the scheduler background thread.

        The scheduler checks every minute if any scans should run.
        """
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the scheduler gracefully."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None

    def _scheduler_loop(self) -> None:
        """Main scheduler loop - runs in background thread."""
        while self._running:
            try:
                self._check_and_execute()
                # Check every 60 seconds
                time.sleep(60)
            except Exception:
                # Silently continue on errors
                time.sleep(60)

    def _check_and_execute(self) -> None:
        """Check all schedules and execute ones that should run."""
        schedules = self.list_schedules()
        now = datetime.utcnow()

        for schedule in schedules:
            if not schedule['enabled']:
                continue

            try:
                parser = CronParser(schedule['cron_expr'])
                if parser.should_run(now):
                    self._run_scheduled_scan(schedule['id'])
            except Exception:
                pass

    def _run_scheduled_scan(self, schedule_id: str) -> None:
        """Execute a scheduled scan.

        Args:
            schedule_id: ID of schedule to run
        """
        if not self._callback:
            return

        try:
            schedule = self.get_schedule(schedule_id)
            if not schedule:
                return

            # Update next_run and run_count before executing
            with self._lock:
                conn = self._get_conn()
                cursor = conn.cursor()

                cursor.execute("""
                    UPDATE schedule_history
                    SET last_run = ?, run_count = run_count + 1, last_status = 'running'
                    WHERE schedule_id = ?
                """, (datetime.utcnow().isoformat(), schedule_id))

                conn.commit()
                conn.close()

            # Execute callback
            self._callback(schedule_id)

            # Update status to success
            with self._lock:
                conn = self._get_conn()
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE schedule_history
                    SET last_status = 'success'
                    WHERE schedule_id = ?
                """, (schedule_id,))
                conn.commit()
                conn.close()

        except Exception as e:
            # Update status to failed
            with self._lock:
                conn = self._get_conn()
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE schedule_history
                    SET last_status = ?
                    WHERE schedule_id = ?
                """, (f"failed: {str(e)}", schedule_id))
                conn.commit()
                conn.close()


# Global singleton instance
_scheduler = None


def get_scheduler(db_path: str = None) -> ScanScheduler:
    """Get or create global scheduler instance.

    Args:
        db_path: Optional custom path to schedules database

    Returns:
        ScanScheduler instance
    """
    global _scheduler
    if _scheduler is None:
        _scheduler = ScanScheduler(db_path)
    return _scheduler
