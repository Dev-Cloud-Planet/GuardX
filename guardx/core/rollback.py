"""
GuardX Rollback Management Module
Manages backups and rollback of SSH-applied fixes.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


class RollbackManager:
    """Manages backups and rollback of SSH-applied fixes.

    Tracks all backups created during remediation and allows restoring
    files to previous states if fixes need to be reverted.
    """

    def __init__(self, backups_file: str = None):
        """Initialize rollback manager.

        Args:
            backups_file: Path to JSON file storing backup metadata.
                         Defaults to ~/.guardx/backups.json
        """
        if backups_file is None:
            guardx_dir = Path.home() / ".guardx"
            guardx_dir.mkdir(exist_ok=True)
            backups_file = guardx_dir / "backups.json"

        self.backups_file = str(backups_file)
        self.backups = self._load_backups()
        self.current_session_id = None

    def _load_backups(self) -> Dict:
        """Load backup metadata from file.

        Returns:
            Dictionary with session_id -> list of backups
        """
        if not os.path.exists(self.backups_file):
            return {}

        try:
            with open(self.backups_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}

    def _save_backups(self) -> None:
        """Persist backup metadata to file."""
        os.makedirs(os.path.dirname(self.backups_file), exist_ok=True)
        with open(self.backups_file, 'w') as f:
            json.dump(self.backups, f, indent=2)

    def set_session_id(self, session_id: str) -> None:
        """Set current session ID for tracking backups.

        Args:
            session_id: Unique identifier for current scan/session
        """
        self.current_session_id = session_id
        if session_id not in self.backups:
            self.backups[session_id] = []

    def create_backup(self, ssh_client, file_path: str) -> str:
        """Create backup of a file via SSH.

        Args:
            ssh_client: Paramiko SSH client (connected and authenticated)
            file_path: Absolute path to file on remote system

        Returns:
            Path to backup file (e.g., /path/to/file.guardx.20260310_143052.bak)

        Raises:
            RuntimeError: If backup creation fails or no session ID set
        """
        if not self.current_session_id:
            raise RuntimeError("No session ID set. Call set_session_id() first.")

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{file_path}.guardx.{timestamp}.bak"

        try:
            # Copy file to backup location via SSH
            # cp /path/to/file /path/to/file.guardx.TIMESTAMP.bak
            cmd = f"cp {file_path} {backup_path}"
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0:
                error_msg = stderr.read().decode('utf-8', errors='ignore')
                raise RuntimeError(f"Backup failed: {error_msg}")

            # Verify backup exists
            if not self.verify_backup(ssh_client, backup_path):
                raise RuntimeError(f"Backup verification failed for {backup_path}")

            # Track backup metadata
            backup_metadata = {
                'file_path': file_path,
                'backup_path': backup_path,
                'timestamp': datetime.utcnow().isoformat(),
                'session_id': self.current_session_id
            }
            self.backups[self.current_session_id].append(backup_metadata)
            self._save_backups()

            return backup_path

        except Exception as e:
            raise RuntimeError(f"Failed to create backup for {file_path}: {str(e)}")

    def verify_backup(self, ssh_client, backup_path: str) -> bool:
        """Verify that a backup file exists and is readable.

        Args:
            ssh_client: Paramiko SSH client (connected and authenticated)
            backup_path: Path to backup file

        Returns:
            True if backup exists and is readable, False otherwise
        """
        try:
            # Use test command to check file exists and is readable
            cmd = f"test -r {backup_path} && echo 'OK'"
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            exit_code = stdout.channel.recv_exit_status()
            return exit_code == 0
        except Exception:
            return False

    def rollback(self, ssh_client, file_path: str, backup_path: str) -> str:
        """Restore a file from its backup.

        Args:
            ssh_client: Paramiko SSH client (connected and authenticated)
            file_path: Path to file to restore
            backup_path: Path to backup to restore from

        Returns:
            Result message describing the rollback operation

        Raises:
            RuntimeError: If rollback fails
        """
        try:
            # Verify backup exists first
            if not self.verify_backup(ssh_client, backup_path):
                raise RuntimeError(f"Backup file not found or not readable: {backup_path}")

            # Restore file from backup: cp backup original
            cmd = f"cp {backup_path} {file_path}"
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0:
                error_msg = stderr.read().decode('utf-8', errors='ignore')
                raise RuntimeError(f"Rollback failed: {error_msg}")

            msg = f"Rolled back {file_path} from {backup_path}"

            # Update backup metadata status (optional)
            if self.current_session_id in self.backups:
                for backup in self.backups[self.current_session_id]:
                    if (backup['file_path'] == file_path and
                        backup['backup_path'] == backup_path):
                        backup['rolled_back'] = True
                        backup['rolled_back_at'] = datetime.utcnow().isoformat()
                self._save_backups()

            return msg

        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"Rollback failed for {file_path}: {str(e)}")

    def rollback_all(self, ssh_client) -> List[str]:
        """Rollback all backups from current session.

        Args:
            ssh_client: Paramiko SSH client (connected and authenticated)

        Returns:
            List of rollback result messages

        Raises:
            RuntimeError: If no session ID is set
        """
        if not self.current_session_id:
            raise RuntimeError("No session ID set. Call set_session_id() first.")

        results = []
        session_backups = self.backups.get(self.current_session_id, [])

        # Sort by reverse timestamp to rollback in reverse order
        sorted_backups = sorted(
            session_backups,
            key=lambda x: x['timestamp'],
            reverse=True
        )

        for backup in sorted_backups:
            try:
                result = self.rollback(
                    ssh_client,
                    backup['file_path'],
                    backup['backup_path']
                )
                results.append(result)
            except RuntimeError as e:
                results.append(f"FAILED: {str(e)}")

        return results

    def list_backups(self, session_id: str = None) -> List[Dict]:
        """List all tracked backups.

        Args:
            session_id: Optional session ID to filter by.
                       If None, returns backups for current session.

        Returns:
            List of backup metadata dictionaries
        """
        if session_id is None:
            session_id = self.current_session_id

        if session_id is None:
            # Return all backups if no session specified
            all_backups = []
            for backups in self.backups.values():
                all_backups.extend(backups)
            return all_backups

        return self.backups.get(session_id, [])

    def get_backup_summary(self) -> Dict:
        """Get summary of all backups.

        Returns:
            Dictionary with backup statistics
        """
        total_backups = sum(len(b) for b in self.backups.values())
        rolled_back = 0
        for session_backups in self.backups.values():
            rolled_back += sum(
                1 for b in session_backups if b.get('rolled_back', False)
            )

        return {
            'total_sessions': len(self.backups),
            'total_backups': total_backups,
            'rolled_back': rolled_back,
            'current_session_id': self.current_session_id
        }


# Global singleton instance
_rollback_manager = None


def get_rollback_manager(backups_file: str = None) -> RollbackManager:
    """Get or create global rollback manager instance.

    Args:
        backups_file: Optional custom path to backups metadata file

    Returns:
        RollbackManager instance
    """
    global _rollback_manager
    if _rollback_manager is None:
        _rollback_manager = RollbackManager(backups_file)
    return _rollback_manager
