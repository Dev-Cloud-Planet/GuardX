"""GuardX Report Generator - Creates HTML and JSON security assessment reports."""
import os
import json
import datetime
from jinja2 import Template


class ReportGenerator:
    """Generates professional security assessment reports from scan data."""

    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), "templates")

    def generate_html(self, scan_data: dict) -> str:
        """Generate HTML report from scan data.

        Args:
            scan_data: Dictionary containing:
                - target: str - The target URL/host
                - date: str - Scan date
                - recon_result: str - Reconnaissance phase output
                - exploit_result: str - Exploitation phase output
                - remediate_result: str - Remediation phase output
                - findings: list[dict] - Vulnerabilities found (severity, title, description, evidence, status)
                - fixes: list[dict] - Applied fixes (finding_title, command, result, verified)
                - score_before: int - Security score before remediation (0-100)
                - score_after: int - Security score after remediation (0-100)

        Returns:
            str: Rendered HTML report
        """
        template_path = os.path.join(self.template_dir, "report.html.j2")
        with open(template_path, "r", encoding="utf-8") as f:
            tmpl = Template(f.read())

        return tmpl.render(
            **scan_data,
            generated_at=datetime.datetime.now().isoformat()
        )

    def generate_json(self, scan_data: dict) -> str:
        """Generate JSON report.

        Args:
            scan_data: Dictionary with scan results

        Returns:
            str: JSON formatted report
        """
        data = {
            **scan_data,
            "generated_at": datetime.datetime.now().isoformat()
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def save_report(
        self,
        content: str,
        filename: str,
        output_dir: str = None
    ) -> str:
        """Save report to file.

        Args:
            content: Report content to save
            filename: Output filename
            output_dir: Output directory (defaults to ~/.guardx/reports)

        Returns:
            str: Full path to saved report
        """
        if output_dir is None:
            output_dir = os.path.expanduser("~/.guardx/reports")

        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, filename)

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        return path


def generate_report(scan_data: dict, fmt: str = "html") -> str:
    """Convenience function to generate a report.

    Args:
        scan_data: Dictionary with scan results
        fmt: Report format - "html" or "json" (default: "html")

    Returns:
        str: Rendered report content
    """
    gen = ReportGenerator()
    if fmt == "json":
        return gen.generate_json(scan_data)
    return gen.generate_html(scan_data)
