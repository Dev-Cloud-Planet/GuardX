"""
GuardX SQLite Database Module
Manages scan history, findings, actions, and fixes.
"""

import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path


class Database:
    """SQLite database for scan history and findings."""

    def __init__(self, db_path: str = None):
        """Initialize database connection."""
        if db_path is None:
            # Try env variable first, then multiple fallbacks
            db_path = os.environ.get("GUARDX_DB_PATH")
            if not db_path:
                # List of candidate directories in priority order
                candidates = [
                    Path.home() / ".guardx",
                    Path(__file__).resolve().parent.parent.parent / "data",
                    Path("/tmp") / "guardx",
                ]
                for candidate in candidates:
                    try:
                        candidate.mkdir(parents=True, exist_ok=True)
                        test_file = candidate / ".write_test"
                        test_file.touch()
                        test_file.unlink()
                        db_path = candidate / "history.db"
                        break
                    except (OSError, PermissionError):
                        continue
                else:
                    # Last resort: /tmp direct
                    db_path = Path("/tmp") / "guardx_history.db"

        self.db_path = str(db_path)
        self.init_db()

    def _get_conn(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Create tables if they don't exist."""
        conn = self._get_conn()
        cursor = conn.cursor()

        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                phase TEXT DEFAULT 'attack',
                score_before INTEGER DEFAULT 0,
                score_after INTEGER DEFAULT 0
            )
        """)

        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                status TEXT DEFAULT 'open',
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        # Actions table (tools executed during scan)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                input TEXT,
                output TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        # Fixes table (applied patches)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fixes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                command TEXT NOT NULL,
                result TEXT,
                verified INTEGER DEFAULT 0,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
            )
        """)

        conn.commit()
        conn.close()

    def save_scan(self, scan_id: str, target: str) -> str:
        """Create a new scan record.

        Args:
            scan_id: Unique scan identifier
            target: Target URL or IP

        Returns:
            The scan_id
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        now = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO scans (id, target, started_at)
            VALUES (?, ?, ?)
        """, (scan_id, target, now))

        conn.commit()
        conn.close()
        return scan_id

    def update_scan(self, scan_id: str, **kwargs):
        """Update scan record fields.

        Args:
            scan_id: Scan identifier
            **kwargs: Fields to update (phase, finished_at, score_before, score_after)
        """
        if not kwargs:
            return

        conn = self._get_conn()
        cursor = conn.cursor()

        allowed_fields = {'phase', 'finished_at', 'score_before', 'score_after'}
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not fields:
            conn.close()
            return

        set_clause = ', '.join([f"{k} = ?" for k in fields.keys()])
        values = list(fields.values()) + [scan_id]

        cursor.execute(f"UPDATE scans SET {set_clause} WHERE id = ?", values)
        conn.commit()
        conn.close()

    def get_scan(self, scan_id: str) -> dict:
        """Get scan by ID.

        Args:
            scan_id: Scan identifier

        Returns:
            Dictionary with scan data or None
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()

        return dict(row) if row else None

    def get_all_scans(self) -> list:
        """Get all scans ordered by date.

        Returns:
            List of scan dictionaries
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans ORDER BY started_at DESC")
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def save_finding(self, scan_id: str, severity: str, title: str,
                     description: str, evidence: str = "") -> int:
        """Save a finding for a scan.

        Args:
            scan_id: Scan identifier
            severity: critical, high, medium, low, info
            title: Finding title
            description: Finding description
            evidence: Evidence or proof of finding

        Returns:
            Finding ID
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        now = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO findings (scan_id, severity, title, description, evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, severity, title, description, evidence, now))

        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return finding_id

    def get_findings(self, scan_id: str, severity: str = None) -> list:
        """Get findings for a scan.

        Args:
            scan_id: Scan identifier
            severity: Filter by severity (optional)

        Returns:
            List of finding dictionaries
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        if severity:
            cursor.execute("""
                SELECT * FROM findings
                WHERE scan_id = ? AND severity = ?
                ORDER BY severity DESC
            """, (scan_id, severity))
        else:
            cursor.execute("""
                SELECT * FROM findings
                WHERE scan_id = ?
                ORDER BY severity DESC
            """, (scan_id,))

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def update_finding(self, finding_id: int, **kwargs):
        """Update finding record.

        Args:
            finding_id: Finding identifier
            **kwargs: Fields to update (status, severity, title, description, evidence)
        """
        if not kwargs:
            return

        conn = self._get_conn()
        cursor = conn.cursor()

        allowed_fields = {'status', 'severity', 'title', 'description', 'evidence'}
        fields = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not fields:
            conn.close()
            return

        set_clause = ', '.join([f"{k} = ?" for k in fields.keys()])
        values = list(fields.values()) + [finding_id]

        cursor.execute(f"UPDATE findings SET {set_clause} WHERE id = ?", values)
        conn.commit()
        conn.close()

    def save_action(self, scan_id: str, phase: str, tool_name: str,
                   tool_input: str, tool_output: str) -> int:
        """Save tool execution action.

        Args:
            scan_id: Scan identifier
            phase: Phase (attack, defense, report)
            tool_name: Name of tool executed
            tool_input: Input to tool
            tool_output: Output from tool

        Returns:
            Action ID
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        now = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO actions (scan_id, phase, tool_name, input, output, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, phase, tool_name, tool_input, tool_output, now))

        action_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return action_id

    def get_actions(self, scan_id: str) -> list:
        """Get all actions for a scan.

        Args:
            scan_id: Scan identifier

        Returns:
            List of action dictionaries
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM actions
            WHERE scan_id = ?
            ORDER BY timestamp ASC
        """, (scan_id,))

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def save_fix(self, finding_id: int, command: str, result: str,
                verified: bool = False) -> int:
        """Save applied fix for a finding.

        Args:
            finding_id: Finding identifier
            command: Command or fix applied
            result: Result of applying fix
            verified: Whether fix was verified

        Returns:
            Fix ID
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        now = datetime.utcnow().isoformat()
        cursor.execute("""
            INSERT INTO fixes (finding_id, command, result, verified, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (finding_id, command, result, 1 if verified else 0, now))

        fix_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return fix_id

    def get_fixes(self, scan_id: str) -> list:
        """Get all fixes applied in a scan.

        Args:
            scan_id: Scan identifier

        Returns:
            List of fix dictionaries
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT f.* FROM fixes f
            JOIN findings fd ON f.finding_id = fd.id
            WHERE fd.scan_id = ?
            ORDER BY f.timestamp DESC
        """, (scan_id,))

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def get_scan_summary(self, scan_id: str) -> dict:
        """Get summary of findings and fixes for a scan.

        Args:
            scan_id: Scan identifier

        Returns:
            Dictionary with counts by severity and fix status
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        # Count findings by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM findings
            WHERE scan_id = ?
            GROUP BY severity
        """, (scan_id,))

        severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}

        # Count findings by status
        cursor.execute("""
            SELECT status, COUNT(*) as count
            FROM findings
            WHERE scan_id = ?
            GROUP BY status
        """, (scan_id,))

        status_counts = {row['status']: row['count'] for row in cursor.fetchall()}

        # Count fixes
        cursor.execute("""
            SELECT COUNT(*) as count, SUM(verified) as verified_count
            FROM fixes
            WHERE finding_id IN (
                SELECT id FROM findings WHERE scan_id = ?
            )
        """, (scan_id,))

        fix_row = cursor.fetchone()
        total_fixes = fix_row['count'] if fix_row else 0
        verified_fixes = fix_row['verified_count'] if fix_row and fix_row['verified_count'] else 0

        conn.close()

        return {
            'severity_counts': severity_counts,
            'status_counts': status_counts,
            'total_findings': sum(severity_counts.values()),
            'total_fixes': total_fixes,
            'verified_fixes': verified_fixes
        }


# Singleton instance
_db = None

def get_db(db_path: str = None) -> Database:
    """Get or create database singleton.

    Args:
        db_path: Optional custom database path

    Returns:
        Database instance
    """
    global _db
    if _db is None:
        _db = Database(db_path)
    return _db
