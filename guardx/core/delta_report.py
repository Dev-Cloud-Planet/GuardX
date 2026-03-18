"""
GuardX Delta Report Module
Compares two scans to identify new, resolved, and unchanged findings.
"""

from typing import Dict, List, Optional
from datetime import datetime


class DeltaReporter:
    """Generates delta reports comparing two scans.

    Identifies new findings, resolved findings, and unchanged findings
    between two security scans. Also calculates score changes.
    """

    def __init__(self, db_handle=None):
        """Initialize delta reporter.

        Args:
            db_handle: Optional database handle for fetching scan data.
                      If provided, used to load findings from DB.
        """
        self.db = db_handle

    def compare(self, scan_id_old: str, scan_id_new: str) -> Dict:
        """Compare two scans and generate delta report.

        Args:
            scan_id_old: ID of baseline/old scan
            scan_id_new: ID of new scan to compare

        Returns:
            Dictionary containing:
            {
                'new_findings': List[dict] - Findings in new scan not in old
                'resolved_findings': List[dict] - Findings in old scan not in new
                'unchanged_findings': List[dict] - Findings in both scans
                'score_change': int - Change in security score (positive = improved)
                'baseline_scan_id': str - Old scan ID
                'current_scan_id': str - New scan ID
                'comparison_timestamp': str - When comparison was done
                'summary': dict - Summary statistics
            }

        Raises:
            ValueError: If either scan ID is invalid or not found
        """
        if not self.db:
            raise ValueError("Database handle required for scan comparison")

        # Fetch scan data
        old_scan = self.db.get_scan(scan_id_old)
        new_scan = self.db.get_scan(scan_id_new)

        if not old_scan:
            raise ValueError(f"Scan not found: {scan_id_old}")
        if not new_scan:
            raise ValueError(f"Scan not found: {scan_id_new}")

        # Fetch findings for both scans
        old_findings = self.db.get_findings(scan_id_old)
        new_findings = self.db.get_findings(scan_id_new)

        # Normalize findings to comparable format
        old_findings_map = self._normalize_findings(old_findings)
        new_findings_map = self._normalize_findings(new_findings)

        # Calculate deltas
        new_vulns = []
        resolved_vulns = []
        unchanged_vulns = []

        # Find new findings
        for key, finding in new_findings_map.items():
            if key not in old_findings_map:
                new_vulns.append(finding)
            else:
                # Check if severity changed
                old_severity = old_findings_map[key].get('severity')
                new_severity = finding.get('severity')
                if old_severity == new_severity:
                    unchanged_vulns.append(finding)
                else:
                    # Severity changed - could be resolved (lower severity)
                    # or regression (higher severity)
                    if self._severity_rank(new_severity) < self._severity_rank(old_severity):
                        resolved_vulns.append({
                            **finding,
                            'old_severity': old_severity,
                            'resolution_type': 'severity_reduced'
                        })
                    else:
                        new_vulns.append({
                            **finding,
                            'old_severity': old_severity,
                            'resolution_type': 'severity_increased'
                        })

        # Find resolved findings (in old but not in new)
        for key, finding in old_findings_map.items():
            if key not in new_findings_map:
                resolved_vulns.append({
                    **finding,
                    'resolution_type': 'completely_resolved'
                })

        # Calculate score change
        old_score = int(old_scan.get('score_after', 0) or old_scan.get('score_before', 0))
        new_score = int(new_scan.get('score_after', 0) or new_scan.get('score_before', 0))
        score_change = new_score - old_score

        # Build summary
        summary = {
            'new_findings_count': len(new_vulns),
            'resolved_findings_count': len(resolved_vulns),
            'unchanged_findings_count': len(unchanged_vulns),
            'total_findings_old': len(old_findings),
            'total_findings_new': len(new_findings),
            'net_change': len(new_vulns) - len(resolved_vulns),
            'security_score_old': old_score,
            'security_score_new': new_score,
            'score_change': score_change,
            'improvement': score_change > 0
        }

        # Breakdown by severity
        summary['new_by_severity'] = self._count_by_severity(new_vulns)
        summary['resolved_by_severity'] = self._count_by_severity(resolved_vulns)

        return {
            'new_findings': new_vulns,
            'resolved_findings': resolved_vulns,
            'unchanged_findings': unchanged_vulns,
            'score_change': score_change,
            'baseline_scan_id': scan_id_old,
            'current_scan_id': scan_id_new,
            'baseline_date': old_scan.get('started_at'),
            'current_date': new_scan.get('started_at'),
            'comparison_timestamp': datetime.utcnow().isoformat(),
            'summary': summary
        }

    def _normalize_findings(self, findings: List) -> Dict:
        """Create normalized map of findings for comparison.

        Args:
            findings: List of finding dictionaries from database

        Returns:
            Dict mapping (title, severity) -> finding dict
        """
        normalized = {}
        for finding in findings:
            # Use title and severity as key for matching
            # (assumes same vulnerability won't be found twice with same severity)
            key = (finding.get('title', ''), finding.get('severity', ''))
            normalized[key] = {
                'id': finding.get('id'),
                'title': finding.get('title'),
                'severity': finding.get('severity'),
                'description': finding.get('description'),
                'evidence': finding.get('evidence'),
                'status': finding.get('status'),
                'created_at': finding.get('created_at')
            }
        return normalized

    def _severity_rank(self, severity: str) -> int:
        """Get numeric rank for severity level (lower = more severe).

        Args:
            severity: Severity string (critical, high, medium, low, info)

        Returns:
            Numeric rank
        """
        ranks = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'info': 4
        }
        return ranks.get(severity.lower(), 99)

    def _count_by_severity(self, findings: List) -> Dict[str, int]:
        """Count findings by severity level.

        Args:
            findings: List of findings

        Returns:
            Dictionary mapping severity -> count
        """
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1

        return counts

    def generate_delta_summary(self, delta_report: Dict) -> str:
        """Generate human-readable summary of delta report.

        Args:
            delta_report: Delta report dictionary from compare()

        Returns:
            Formatted summary string
        """
        summary = delta_report['summary']
        baseline_date = delta_report.get('baseline_date', 'unknown')
        current_date = delta_report.get('current_date', 'unknown')

        lines = [
            "=" * 60,
            "DELTA SECURITY REPORT",
            "=" * 60,
            f"Baseline Scan: {baseline_date}",
            f"Current Scan: {current_date}",
            "",
            "SUMMARY",
            "-" * 60,
            f"Total Findings (Baseline): {summary['total_findings_old']}",
            f"Total Findings (Current): {summary['total_findings_new']}",
            f"Net Change: {summary['net_change']:+d}",
            "",
            f"New Findings: {summary['new_findings_count']}",
            f"Resolved Findings: {summary['resolved_findings_count']}",
            f"Unchanged Findings: {summary['unchanged_findings_count']}",
            "",
            "SECURITY SCORE",
            "-" * 60,
            f"Baseline Score: {summary['security_score_old']}",
            f"Current Score: {summary['security_score_new']}",
            f"Change: {summary['score_change']:+d}",
            f"Status: {'IMPROVED' if summary['improvement'] else 'DEGRADED'}",
            "",
            "NEW FINDINGS BY SEVERITY",
            "-" * 60,
        ]

        new_by_sev = summary['new_by_severity']
        lines.extend([
            f"  Critical: {new_by_sev['critical']}",
            f"  High:     {new_by_sev['high']}",
            f"  Medium:   {new_by_sev['medium']}",
            f"  Low:      {new_by_sev['low']}",
            f"  Info:     {new_by_sev['info']}",
            "",
            "RESOLVED FINDINGS BY SEVERITY",
            "-" * 60,
        ])

        resolved_by_sev = summary['resolved_by_severity']
        lines.extend([
            f"  Critical: {resolved_by_sev['critical']}",
            f"  High:     {resolved_by_sev['high']}",
            f"  Medium:   {resolved_by_sev['medium']}",
            f"  Low:      {resolved_by_sev['low']}",
            f"  Info:     {resolved_by_sev['info']}",
            "=" * 60,
        ])

        return "\n".join(lines)


# Global singleton instance
_delta_reporter = None


def get_delta_reporter(db_handle=None) -> DeltaReporter:
    """Get or create global delta reporter instance.

    Args:
        db_handle: Optional database handle

    Returns:
        DeltaReporter instance
    """
    global _delta_reporter
    if _delta_reporter is None:
        _delta_reporter = DeltaReporter(db_handle)
    return _delta_reporter
