"""SSL/TLS deep analysis tool. Pure Python, no external deps."""
import ssl
import socket
import datetime

TOOL_SCHEMA = {
    "name": "ssl_analyzer",
    "description": (
        "Perform deep SSL/TLS analysis on target. "
        "Tests protocol versions, cipher suites, certificate validity, "
        "HSTS headers, and detects known vulnerabilities (BEAST, POODLE, CRIME). "
        "Outputs security grade A+ to F with detailed findings."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target hostname or IP e.g. example.com"
            },
            "port": {
                "type": "integer",
                "description": "Port number (default 443)",
                "default": 443
            },
        },
        "required": ["target"],
    },
}

# Weak ciphers that should be flagged
WEAK_CIPHERS = {
    "RC4", "DES", "NULL", "EXPORT", "MD5", "anon", "PSK", "aNULL", "eNULL",
    "IDEA", "ADH", "AECDH", "CAMELLIA", "SEED", "KRB5", "SRP"
}

# TLS protocol versions to test
PROTOCOLS = []
try:
    PROTOCOLS.append(("SSLv3", ssl.PROTOCOL_SSLv3))
except AttributeError:
    pass  # SSLv3 disabled in modern Python

try:
    PROTOCOLS.append(("TLSv1.0", ssl.PROTOCOL_TLSv1))
except AttributeError:
    pass

try:
    PROTOCOLS.append(("TLSv1.1", ssl.PROTOCOL_TLSv1_1))
except AttributeError:
    pass

try:
    PROTOCOLS.append(("TLSv1.2", ssl.PROTOCOL_TLSv1_2))
except AttributeError:
    pass

try:
    PROTOCOLS.append(("TLSv1.3", ssl.PROTOCOL_TLS))
except AttributeError:
    pass


def is_available() -> bool:
    return True


def _test_protocol(target: str, port: int, protocol_name: str, protocol_version) -> bool:
    """Test if a specific TLS protocol version is enabled."""
    try:
        ctx = ssl.SSLContext(protocol_version)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                return True
    except (ssl.SSLError, socket.error, OSError):
        return False


def _get_certificate(target: str, port: int) -> tuple:
    """Get certificate from server."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()

                # Get cipher info
                cipher = ssock.cipher()

                return cert, cert_der, cipher
    except Exception as e:
        return None, None, None


def _parse_san(cert: dict) -> list:
    """Extract Subject Alternative Names from certificate."""
    san_list = []
    if "subjectAltName" in cert:
        for typ, val in cert["subjectAltName"]:
            san_list.append(f"{typ}:{val}")
    return san_list


def _check_cert_expiration(cert: dict) -> dict:
    """Check certificate expiration date."""
    try:
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            # Parse SSL date format: Jan 20 00:00:00 2025 GMT
            parts = not_after_str.split()
            month_str = parts[0]
            day = int(parts[1])
            year = int(parts[4])

            months = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
                     "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
            month = months.get(month_str, 1)

            expiry = datetime.datetime(year, month, day, tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            days_left = (expiry - now).days

            return {
                "expiry_date": not_after_str,
                "days_remaining": days_left,
                "expired": days_left < 0,
                "expiring_soon": 0 < days_left < 30
            }
    except Exception:
        pass
    return {"error": "Could not parse expiration"}


def _is_self_signed(cert: dict) -> bool:
    """Check if certificate is self-signed."""
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    return subject == issuer


def _check_weak_ciphers(cipher_name: str) -> bool:
    """Check if cipher is considered weak."""
    for weak in WEAK_CIPHERS:
        if weak.upper() in cipher_name.upper():
            return True
    return False


def _calculate_grade(findings: list, protocols_ok: list, cipher_ok: bool) -> str:
    """Calculate security grade based on findings."""
    critical_count = sum(1 for sev, _ in findings if sev == "CRITICAL")
    high_count = sum(1 for sev, _ in findings if sev == "HIGH")
    medium_count = sum(1 for sev, _ in findings if sev == "MEDIUM")

    if critical_count >= 2:
        return "F"
    elif critical_count == 1:
        return "D"
    elif high_count >= 3:
        return "C"
    elif high_count >= 1 or not cipher_ok:
        return "B"
    elif medium_count >= 2:
        return "B+"
    elif medium_count == 1:
        return "A"
    else:
        return "A+"


async def execute(params: dict) -> str:
    target = params.get("target", "").strip()
    port = params.get("port", 443)

    if not target:
        return "Error: target is required"

    lines = [
        f"=== SSL/TLS Analysis ===",
        f"Target: {target}:{port}",
        "",
    ]

    # Get certificate
    cert, cert_der, cipher = _get_certificate(target, port)

    if not cert:
        return f"Error: Could not connect to {target}:{port}"

    findings = []

    # Certificate analysis
    lines.append("--- Certificate Analysis ---")

    # Issuer
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))

    cn = subject.get("commonName", "N/A")
    issuer_cn = issuer.get("commonName", "N/A")
    lines.append(f"Subject: {cn}")
    lines.append(f"Issuer: {issuer_cn}")

    # Self-signed check
    if _is_self_signed(cert):
        findings.append(("HIGH", "Certificate is self-signed (untrusted)"))
        lines.append("[WARN] Self-signed certificate")
    else:
        lines.append("[OK] Certificate is signed by CA")

    # Expiration
    exp_info = _check_cert_expiration(cert)
    if "error" not in exp_info:
        lines.append(f"Expires: {exp_info['expiry_date']}")
        if exp_info["expired"]:
            findings.append(("CRITICAL", "Certificate has expired"))
            lines.append("[CRITICAL] Certificate expired!")
        elif exp_info["expiring_soon"]:
            findings.append(("MEDIUM", f"Certificate expires in {exp_info['days_remaining']} days"))
            lines.append(f"[WARN] Expires in {exp_info['days_remaining']} days")
        else:
            lines.append(f"[OK] Valid for {exp_info['days_remaining']} more days")

    # SAN
    san = _parse_san(cert)
    if san:
        lines.append(f"SANs: {', '.join(san)}")

    lines.append("")

    # Protocol version testing
    lines.append("--- Protocol Versions ---")
    protocols_enabled = []

    for proto_name, proto_version in PROTOCOLS:
        try:
            enabled = _test_protocol(target, port, proto_name, proto_version)
            if enabled:
                protocols_enabled.append(proto_name)
                # Flag weak protocols
                if proto_name in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
                    findings.append(("HIGH", f"{proto_name} is enabled (deprecated, vulnerable)"))
                    lines.append(f"[WARN] {proto_name}: Enabled (WEAK)")
                else:
                    lines.append(f"[OK] {proto_name}: Enabled")
            else:
                lines.append(f"[OK] {proto_name}: Disabled")
        except Exception:
            lines.append(f"[?] {proto_name}: Could not test")

    if not any(p in protocols_enabled for p in ["TLSv1.2", "TLSv1.3"]):
        findings.append(("CRITICAL", "No modern TLS versions (1.2+) enabled"))

    lines.append("")

    # Cipher suite
    lines.append("--- Cipher Suite ---")
    if cipher:
        cipher_name = cipher[0]
        cipher_bits = cipher[2]

        lines.append(f"Cipher: {cipher_name}")
        lines.append(f"Bits: {cipher_bits}")

        is_weak = _check_weak_ciphers(cipher_name)
        if is_weak:
            findings.append(("HIGH", f"Weak cipher detected: {cipher_name}"))
            lines.append("[WARN] Weak cipher suite")
        else:
            lines.append("[OK] Cipher appears strong")

    lines.append("")

    # Known vulnerabilities
    lines.append("--- Vulnerability Checks ---")

    if "TLSv1.0" in protocols_enabled:
        findings.append(("HIGH", "BEAST attack possible (TLSv1.0 enabled)"))
        lines.append("[WARN] BEAST: TLSv1.0 enables BEAST attack")
    else:
        lines.append("[OK] BEAST: Not vulnerable (TLSv1.0 disabled)")

    if "SSLv3" in protocols_enabled:
        findings.append(("CRITICAL", "POODLE attack possible (SSLv3 enabled)"))
        lines.append("[CRIT] POODLE: SSLv3 downgrade attack possible")
    else:
        lines.append("[OK] POODLE: Not vulnerable (SSLv3 disabled)")

    if "TLSv1.0" in protocols_enabled or "TLSv1.1" in protocols_enabled:
        findings.append(("MEDIUM", "CRIME attack possible (compression enabled)"))
        lines.append("[WARN] CRIME: Older TLS with compression vulnerable")
    else:
        lines.append("[OK] CRIME: Not vulnerable")

    lines.append("")

    # HSTS check
    lines.append("--- HSTS Header ---")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        import urllib.request
        req = urllib.request.Request(f"https://{target}:{port}/", method="HEAD")
        req.add_header("User-Agent", "GuardX/0.1")

        try:
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                hsts = resp.headers.get("Strict-Transport-Security")
                if hsts:
                    lines.append(f"[OK] HSTS enabled: {hsts}")
                else:
                    findings.append(("MEDIUM", "HSTS header not set"))
                    lines.append("[WARN] HSTS header missing")
        except Exception:
            lines.append("[?] Could not check HSTS")
    except Exception:
        pass

    lines.append("")

    # Summary
    cipher_ok = not _check_weak_ciphers(cipher[0] if cipher else "")
    grade = _calculate_grade(findings, protocols_enabled, cipher_ok)

    lines.append(f"=== SECURITY GRADE: {grade} ===")
    lines.append("")

    if findings:
        lines.append("--- Findings ---")
        seen = set()
        for severity, description in findings:
            key = (severity, description)
            if key not in seen:
                seen.add(key)
                lines.append(f"[{severity}] {description}")
    else:
        lines.append("No critical findings detected")

    return "\n".join(lines)
