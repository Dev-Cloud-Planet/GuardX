"""
GuardX Compliance Module
Check findings against security standards (OWASP Top 10, CIS Benchmarks).
"""

from typing import List, Dict


class ComplianceChecker:
    """Check findings against OWASP Top 10 and CIS Benchmarks."""

    OWASP_TOP10 = {
        "A01": {
            "name": "Broken Access Control",
            "findings": ["idor", "auth_bypass", "directory_traversal", "cors_misconfig"]
        },
        "A02": {
            "name": "Cryptographic Failures",
            "findings": ["ssl_tls", "weak_crypto", "exposed_keys"]
        },
        "A03": {
            "name": "Injection",
            "findings": ["sql_injection", "xss", "command_injection", "ssrf", "ldap_injection", "xpath_injection"]
        },
        "A04": {
            "name": "Insecure Design",
            "findings": ["file_upload", "race_condition", "insecure_workflow"]
        },
        "A05": {
            "name": "Security Misconfiguration",
            "findings": ["missing_headers", "exposed_services", "info_disclosure", "ssh_hardening", "debug_enabled"]
        },
        "A06": {
            "name": "Vulnerable Components",
            "findings": ["cve", "outdated_lib", "vulnerable_dependency"]
        },
        "A07": {
            "name": "Authentication Failures",
            "findings": ["auth_bypass", "brute_force", "weak_password", "session_fixation"]
        },
        "A08": {
            "name": "Software Integrity Failures",
            "findings": ["insecure_ci_cd", "unsigned_updates", "unsigned_code"]
        },
        "A09": {
            "name": "Logging and Monitoring Failures",
            "findings": ["insufficient_logging", "log_injection", "sensitive_logs"]
        },
        "A10": {
            "name": "SSRF",
            "findings": ["ssrf", "url_redirect"]
        }
    }

    CIS_BENCHMARKS = {
        "access_control": {
            "description": "Access Control",
            "checks": ["idor", "auth_bypass", "cors_misconfig"]
        },
        "encryption": {
            "description": "Encryption & Cryptography",
            "checks": ["ssl_tls", "weak_crypto", "exposed_keys"]
        },
        "vulnerability_management": {
            "description": "Vulnerability Management",
            "checks": ["cve", "outdated_lib", "unpatched"]
        },
        "data_protection": {
            "description": "Data Protection",
            "checks": ["data_exposure", "sensitive_logs", "pii_disclosure"]
        },
        "logging": {
            "description": "Logging & Monitoring",
            "checks": ["insufficient_logging", "log_injection"]
        }
    }

    def check_owasp(self, findings: List[Dict]) -> Dict:
        """Map findings to OWASP Top 10 categories.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary mapping OWASP categories to matching findings
        """
        result = {}

        for category_id, category in self.OWASP_TOP10.items():
            matching = []

            for finding in findings:
                finding_type = finding.get('title', '').lower().replace(' ', '_')

                for check in category['findings']:
                    if check in finding_type or check in finding.get('description', '').lower():
                        matching.append({
                            'title': finding.get('title'),
                            'severity': finding.get('severity'),
                            'status': finding.get('status')
                        })
                        break

            if matching:
                result[category_id] = {
                    'name': category['name'],
                    'count': len(matching),
                    'findings': matching
                }

        return result

    def check_basic_cis(self, findings: List[Dict]) -> Dict:
        """Check findings against basic CIS benchmarks.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary with CIS benchmark results
        """
        result = {}

        for benchmark_key, benchmark in self.CIS_BENCHMARKS.items():
            matching = []

            for finding in findings:
                finding_type = finding.get('title', '').lower().replace(' ', '_')

                for check in benchmark['checks']:
                    if check in finding_type or check in finding.get('description', '').lower():
                        matching.append({
                            'title': finding.get('title'),
                            'severity': finding.get('severity')
                        })
                        break

            if matching:
                result[benchmark_key] = {
                    'name': benchmark['description'],
                    'count': len(matching),
                    'status': 'FAILED',
                    'findings': matching
                }
            else:
                result[benchmark_key] = {
                    'name': benchmark['description'],
                    'count': 0,
                    'status': 'PASSED',
                    'findings': []
                }

        return result

    def generate_compliance_report(self, findings: List[Dict]) -> str:
        """Generate compliance report text.

        Args:
            findings: List of finding dictionaries

        Returns:
            Formatted compliance report string
        """
        if not findings:
            return "No findings detected. Compliance status: EXCELLENT\n"

        report = []
        report.append("=" * 70)
        report.append("GuardX COMPLIANCE REPORT")
        report.append("=" * 70)
        report.append("")

        # Summary statistics
        total_findings = len(findings)
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        report.append("SUMMARY")
        report.append("-" * 70)
        report.append(f"Total Findings: {total_findings}")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                report.append(f"  {severity.upper():12}: {count}")
        report.append("")

        # OWASP Top 10 Mapping
        report.append("OWASP TOP 10 MAPPING")
        report.append("-" * 70)
        owasp_result = self.check_owasp(findings)

        if owasp_result:
            for category_id in sorted(owasp_result.keys()):
                category = owasp_result[category_id]
                report.append(f"{category_id}: {category['name']} ({category['count']} findings)")
                for finding in category['findings']:
                    severity = finding.get('severity', 'unknown').upper()
                    report.append(f"    - {finding['title']} [{severity}]")
        else:
            report.append("No OWASP Top 10 vulnerabilities detected.")

        report.append("")

        # CIS Benchmarks
        report.append("CIS BENCHMARKS")
        report.append("-" * 70)
        cis_result = self.check_basic_cis(findings)

        for benchmark_key in cis_result.keys():
            benchmark = cis_result[benchmark_key]
            status = benchmark['status']
            status_symbol = "✓ PASS" if status == "PASSED" else "✗ FAIL"
            report.append(f"{status_symbol} {benchmark['name']}")

            if benchmark['findings']:
                for finding in benchmark['findings']:
                    report.append(f"    - {finding['title']}")

        report.append("")

        # Risk Assessment
        report.append("RISK ASSESSMENT")
        report.append("-" * 70)

        critical_count = severity_counts.get('critical', 0)
        high_count = severity_counts.get('high', 0)

        if critical_count > 0:
            risk_level = "CRITICAL"
            recommendation = "IMMEDIATE ACTION REQUIRED. Stop production systems and remediate."
        elif high_count > 0:
            risk_level = "HIGH"
            recommendation = "Urgent remediation needed. Address within 24 hours."
        elif severity_counts.get('medium', 0) > 0:
            risk_level = "MEDIUM"
            recommendation = "Schedule remediation. Address within 1 week."
        else:
            risk_level = "LOW"
            recommendation = "Monitor and plan remediation. Address within 1 month."

        report.append(f"Overall Risk Level: {risk_level}")
        report.append(f"Recommendation: {recommendation}")
        report.append("")

        # Compliance Status
        report.append("COMPLIANCE STATUS")
        report.append("-" * 70)

        passed_benchmarks = sum(1 for b in cis_result.values() if b['status'] == 'PASSED')
        total_benchmarks = len(cis_result)

        if passed_benchmarks == total_benchmarks:
            compliance = "COMPLIANT"
        elif passed_benchmarks >= total_benchmarks * 0.8:
            compliance = "MOSTLY COMPLIANT"
        elif passed_benchmarks >= total_benchmarks * 0.5:
            compliance = "PARTIALLY COMPLIANT"
        else:
            compliance = "NON-COMPLIANT"

        report.append(f"Overall Status: {compliance}")
        report.append(f"Benchmarks Passed: {passed_benchmarks}/{total_benchmarks}")
        report.append("")

        report.append("=" * 70)

        return "\n".join(report)

    @staticmethod
    def get_severity_weight(severity: str) -> int:
        """Get numeric weight for severity level.

        Args:
            severity: Severity level string

        Returns:
            Numeric weight
        """
        weights = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25,
            'info': 10
        }
        return weights.get(severity.lower(), 0)

    @staticmethod
    def calculate_risk_score(findings: List[Dict]) -> float:
        """Calculate overall risk score from findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            Risk score between 0 and 100
        """
        if not findings:
            return 0.0

        total_weight = 0
        max_possible = len(findings) * ComplianceChecker.get_severity_weight('critical')

        for finding in findings:
            severity = finding.get('severity', 'info')
            weight = ComplianceChecker.get_severity_weight(severity)
            total_weight += weight

        risk_score = (total_weight / max_possible) * 100 if max_possible > 0 else 0
        return min(100.0, risk_score)


def check_compliance(findings: List[Dict]) -> str:
    """Generate compliance report for findings.

    Args:
        findings: List of finding dictionaries

    Returns:
        Formatted compliance report string
    """
    return ComplianceChecker().generate_compliance_report(findings)


def calculate_risk_score(findings: List[Dict]) -> float:
    """Calculate risk score for findings.

    Args:
        findings: List of finding dictionaries

    Returns:
        Risk score between 0 and 100
    """
    return ComplianceChecker.calculate_risk_score(findings)
