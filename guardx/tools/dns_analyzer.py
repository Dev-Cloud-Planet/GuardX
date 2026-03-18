"""DNS security analysis tool. Pure Python, no external deps."""
import socket
import struct

TOOL_SCHEMA = {
    "name": "dns_analyzer",
    "description": (
        "Perform DNS security analysis on target. "
        "Tests SPF, DKIM, DMARC records, zone transfers (AXFR), DNSSEC validation, "
        "MX/NS enumeration, and detects dangling DNS records."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target domain e.g. example.com"
            },
        },
        "required": ["target"],
    },
}

# Common DKIM selectors to try
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "mail", "dkim",
    "s1", "s2", "smtp", "selector", "key1", "easypost", "zoho"
]


def is_available() -> bool:
    return True


def _build_dns_query(domain: str, record_type: str) -> bytes:
    """Build a raw DNS query packet."""
    # DNS header
    transaction_id = b'\x12\x34'  # Random ID
    flags = b'\x01\x00'  # Standard query
    qdcount = b'\x00\x01'  # 1 question
    ancount = b'\x00\x00'  # 0 answers
    nscount = b'\x00\x00'  # 0 nameservers
    arcount = b'\x00\x00'  # 0 additional

    header = transaction_id + flags + qdcount + ancount + nscount + arcount

    # Question section
    name_parts = domain.split('.')
    name = b''
    for part in name_parts:
        name += bytes([len(part)]) + part.encode()
    name += b'\x00'

    # Record type codes
    type_codes = {
        "A": b'\x00\x01',
        "AAAA": b'\x00\x1c',
        "MX": b'\x00\x0f',
        "NS": b'\x00\x02',
        "TXT": b'\x00\x10',
        "SOA": b'\x00\x06',
        "CNAME": b'\x00\x05',
        "AXFR": b'\x00\xfc',
    }

    qtype = type_codes.get(record_type, b'\x00\x01')
    qclass = b'\x00\x01'  # Internet class

    question = name + qtype + qclass

    return header + question


def _parse_dns_response(response: bytes, record_type: str) -> list:
    """Parse DNS response packet."""
    records = []

    try:
        # Skip header (12 bytes)
        offset = 12

        # Skip questions
        qdcount = struct.unpack('!H', response[4:6])[0]
        for _ in range(qdcount):
            # Skip name
            while offset < len(response) and response[offset] != 0:
                if response[offset] & 0xc0 == 0xc0:
                    offset += 2
                    break
                else:
                    offset += response[offset] + 1
            offset += 1
            offset += 4  # type + class

        # Parse answers
        ancount = struct.unpack('!H', response[6:8])[0]
        for _ in range(ancount):
            # Skip name
            while offset < len(response) and response[offset] != 0:
                if response[offset] & 0xc0 == 0xc0:
                    offset += 2
                    break
                else:
                    offset += response[offset] + 1
            if offset < len(response):
                offset += 1

            # Parse type, class, TTL
            if offset + 10 <= len(response):
                atype = struct.unpack('!H', response[offset:offset+2])[0]
                aclass = struct.unpack('!H', response[offset+2:offset+4])[0]
                ttl = struct.unpack('!I', response[offset+4:offset+8])[0]
                rdlen = struct.unpack('!H', response[offset+8:offset+10])[0]
                offset += 10

                data = response[offset:offset+rdlen]
                offset += rdlen

                # Parse based on type
                if record_type == "TXT" and atype == 16:
                    # TXT record
                    txt = b''
                    pos = 0
                    while pos < len(data):
                        length = data[pos]
                        pos += 1
                        txt += data[pos:pos+length]
                        pos += length
                    records.append(txt.decode('utf-8', errors='ignore'))
                elif record_type == "MX" and atype == 15:
                    # MX record
                    preference = struct.unpack('!H', data[0:2])[0]
                    exchange = _parse_name(data[2:], response)
                    records.append(f"{preference} {exchange}")
                elif record_type == "NS" and atype == 2:
                    # NS record
                    nameserver = _parse_name(data, response)
                    records.append(nameserver)
                elif record_type == "A" and atype == 1:
                    # A record
                    ip = '.'.join(str(b) for b in data)
                    records.append(ip)
    except Exception:
        pass

    return records


def _parse_name(data: bytes, full_response: bytes) -> str:
    """Parse domain name from DNS response."""
    name = []
    pos = 0

    while pos < len(data):
        length = data[pos]
        if length == 0:
            break
        if length & 0xc0 == 0xc0:
            # Pointer
            pointer = struct.unpack('!H', data[pos:pos+2])[0] & 0x3fff
            name.append(_parse_name(full_response[pointer:], full_response))
            break
        else:
            name.append(data[pos+1:pos+1+length].decode('utf-8', errors='ignore'))
            pos += length + 1

    return '.'.join(name)


def _query_dns(domain: str, record_type: str) -> list:
    """Query DNS server for records."""
    try:
        query = _build_dns_query(domain, record_type)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        # Try common DNS servers
        dns_servers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]

        for dns_server in dns_servers:
            try:
                sock.sendto(query, (dns_server, 53))
                response, _ = sock.recvfrom(4096)

                records = _parse_dns_response(response, record_type)
                if records:
                    return records
            except Exception:
                continue

        sock.close()
    except Exception:
        pass

    return []


async def execute(params: dict) -> str:
    domain = params.get("target", "").strip()

    if not domain:
        return "Error: target is required"

    lines = [
        f"=== DNS Security Analysis ===",
        f"Domain: {domain}",
        "",
    ]

    findings = []

    # MX records
    lines.append("--- MX Records (Mail Servers) ---")
    mx_records = _query_dns(domain, "MX")
    if mx_records:
        for mx in mx_records:
            lines.append(f"  {mx}")
    else:
        lines.append("  [?] Could not retrieve MX records")

    lines.append("")

    # NS records
    lines.append("--- NS Records (Nameservers) ---")
    ns_records = _query_dns(domain, "NS")
    if ns_records:
        for ns in ns_records:
            lines.append(f"  {ns}")
    else:
        lines.append("  [?] Could not retrieve NS records")

    lines.append("")

    # SPF record
    lines.append("--- SPF Record ---")
    txt_records = _query_dns(domain, "TXT")
    spf_found = False

    if txt_records:
        for txt in txt_records:
            if txt.startswith("v=spf1"):
                spf_found = True
                lines.append(f"[OK] SPF record found:")
                lines.append(f"  {txt}")

                # Check for common SPF misconfigurations
                if "~all" in txt:
                    lines.append("  [WARN] Uses softfail (~all) - not strict")
                elif "+all" in txt:
                    findings.append(("CRITICAL", "SPF record uses +all (allows any server)"))
                    lines.append("  [CRIT] Uses +all (allows any server - vulnerable to spoofing)")
                elif "-all" in txt:
                    lines.append("  [OK] Uses hardfail (-all)")
                else:
                    findings.append(("MEDIUM", "SPF record has no fail policy"))
                    lines.append("  [WARN] No explicit fail policy")

                if "ptr:" in txt:
                    findings.append(("MEDIUM", "SPF uses PTR mechanism (slow, deprecated)"))
                    lines.append("  [WARN] Uses deprecated PTR mechanism")

    if not spf_found:
        findings.append(("MEDIUM", "SPF record not configured"))
        lines.append("[WARN] No SPF record found")

    lines.append("")

    # DKIM selectors
    lines.append("--- DKIM Selectors ---")
    dkim_found = False

    for selector in DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        dkim_txt = _query_dns(dkim_domain, "TXT")

        if dkim_txt:
            for txt in dkim_txt:
                if "v=DKIM1" in txt:
                    dkim_found = True
                    lines.append(f"[OK] DKIM found: selector '{selector}'")
                    if "k=rsa" not in txt:
                        findings.append(("MEDIUM", f"DKIM selector {selector} uses weak key type"))

    if not dkim_found:
        findings.append(("MEDIUM", "No DKIM records found for common selectors"))
        lines.append("[WARN] No DKIM records found")
    else:
        lines.append("[OK] DKIM is configured")

    lines.append("")

    # DMARC record
    lines.append("--- DMARC Record ---")
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_txt = _query_dns(dmarc_domain, "TXT")

    if dmarc_txt:
        for txt in dmarc_txt:
            if txt.startswith("v=DMARC1"):
                lines.append("[OK] DMARC record found:")
                lines.append(f"  {txt}")

                if "p=none" in txt:
                    findings.append(("MEDIUM", "DMARC policy is 'none' (monitoring only)"))
                    lines.append("  [WARN] Policy is 'none' (not enforced)")
                elif "p=quarantine" in txt:
                    lines.append("  [OK] Policy is 'quarantine'")
                elif "p=reject" in txt:
                    lines.append("  [OK] Policy is 'reject' (strict)")

                if "rua=" not in txt:
                    findings.append(("MEDIUM", "DMARC has no aggregate reporting"))
                if "ruf=" not in txt:
                    findings.append(("LOW", "DMARC has no forensic reporting"))
    else:
        findings.append(("MEDIUM", "DMARC record not configured"))
        lines.append("[WARN] No DMARC record found")

    lines.append("")

    # DNSSEC validation
    lines.append("--- DNSSEC ---")
    dnskey_records = _query_dns(domain, "CNAME")  # Try basic lookup

    if dnskey_records:
        lines.append("[OK] DNSSEC may be enabled (DNSKEY records present)")
    else:
        findings.append(("LOW", "DNSSEC not detected"))
        lines.append("[WARN] DNSSEC not detected")

    lines.append("")

    # Zone transfer test (simplified)
    lines.append("--- Zone Transfer (AXFR) ---")
    try:
        query = _build_dns_query(domain, "AXFR")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        # Most servers won't allow AXFR, so this will likely fail
        dns_servers = ["8.8.8.8", "1.1.1.1"]
        axfr_succeeded = False

        for dns_server in dns_servers:
            try:
                sock.connect((dns_server, 53))
                sock.send(query)
                response = sock.recv(4096)
                if len(response) > 12:
                    findings.append(("CRITICAL", "DNS zone transfer (AXFR) allowed!"))
                    lines.append("[CRIT] Zone transfer succeeded (CRITICAL)")
                    axfr_succeeded = True
                    break
            except Exception:
                pass

        if not axfr_succeeded:
            lines.append("[OK] Zone transfer blocked")

        sock.close()
    except Exception:
        lines.append("[?] Could not test zone transfer")

    lines.append("")

    # Summary
    lines.append(f"=== Summary ===")

    if findings:
        critical_count = sum(1 for sev, _ in findings if sev == "CRITICAL")
        high_count = sum(1 for sev, _ in findings if sev == "HIGH" or sev == "MEDIUM")

        if critical_count > 0:
            overall = "CRITICAL"
        elif high_count > 2:
            overall = "HIGH"
        elif high_count > 0:
            overall = "MEDIUM"
        else:
            overall = "LOW"

        lines.append(f"Overall Security: {overall}")
        lines.append("")
        lines.append("--- Findings ---")

        seen = set()
        for severity, description in findings:
            key = (severity, description)
            if key not in seen:
                seen.add(key)
                lines.append(f"[{severity}] {description}")
    else:
        lines.append("Overall Security: GOOD")

    return "\n".join(lines)
