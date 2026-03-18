"""Unrestricted File Upload - Leading to RCE, XSS, or DoS."""

SKILL = {
    "id": "file_upload",
    "name": "Unrestricted File Upload",
    "category": "web",
    "severity": "critical",

    "detection": """
- Look for file upload functionality: profile pictures, document uploads, import features
- Use web_spider to discover forms with enctype="multipart/form-data" or input type="file"
- Test uploading files with dangerous extensions: .php, .php5, .phtml, .jsp, .aspx, .py, .pl
- Test double extensions: shell.php.jpg, shell.jpg.php
- Test null byte in filename: shell.php%00.jpg (older systems)
- Test case variations: shell.PHP, shell.pHp, shell.PhP
- Test alternative extensions: .phar, .inc, .phps, .php3, .php7
- Check if uploaded files are accessible via web (can you browse to them?)
- Check if Content-Type validation can be bypassed: Upload .php with Content-Type: image/jpeg
- Check if file content is validated (magic bytes): Prepend GIF89a; to PHP file
- Test SVG upload for stored XSS
- Check if filename is sanitized (try path traversal in filename)
- Check file size limits (DoS via large file upload)
- Test .htaccess upload: can override server config to execute arbitrary extensions
""",

    "exploitation": """
- Upload PHP webshell and access via http://target.com/uploads/shell.php?cmd=id
- Upload JSP webshell for Java/Tomcat environments
- Upload ASPX webshell for .NET environments
- Bypass extension filter with double extension: shell.php.jpg
- Bypass Content-Type check: set Content-Type: image/png while uploading .php
- Bypass magic bytes check: prepend GIF89a; or PNG header to PHP file
- Upload .htaccess to make .jpg executable as PHP
- SVG for stored XSS with onload event handler
- Polyglot file: valid image that is also valid PHP
- Chain with LFI: upload file anywhere, include via directory traversal
- Document: show uploaded file URL and RCE/XSS execution as proof
""",

    "remediation": """
- Validate file type server-side using magic bytes (not just extension or Content-Type):
  Python: import magic; mime = magic.from_buffer(file.read(2048), mime=True)
  Only allow: image/jpeg, image/png, image/gif, application/pdf
- Use allowlist for extensions (NOT blocklist):
  ALLOWED = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}
  ext = os.path.splitext(filename)[1].lower()
  if ext not in ALLOWED: reject
- Rename uploaded files to random names: uuid4().hex + allowed_ext
  NEVER use original filename in storage path
- Store uploads OUTSIDE web root:
  /var/uploads/ instead of /var/www/html/uploads/
  Serve via application with Content-Disposition: attachment
- Set proper Content-Type when serving: never let browser guess
- Remove execute permissions on upload directory:
  chmod -R 644 /var/www/uploads/
  nginx: disable PHP execution in uploads location block
- Limit file size: MAX_CONTENT_LENGTH = 5 * 1024 * 1024
- Scan uploads with antivirus (ClamAV)
- Use CDN/object storage (S3) for uploaded files instead of local disk
- SSH fix: add extension whitelist, disable PHP in upload dir, rename files
- SSH fix: move uploads outside webroot, set correct permissions
- Verify: try uploading .php file, confirm rejected or not executable
""",

    "tools": ["web_spider", "dir_bruteforce", "tech_fingerprint", "waf_detect"],

    "payloads": [
        "shell.php", "shell.php.jpg", "shell.jpg.php",
        "shell.php%00.jpg", "shell.PHP", "shell.pHp",
        ".htaccess", "shell.phar", "shell.php5",
    ],

    "references": [
        "OWASP A04:2021 - Insecure Design",
        "CWE-434: Unrestricted Upload of File with Dangerous Type",
        "CWE-436: Interpretation Conflict",
        "CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs",
    ],
}
