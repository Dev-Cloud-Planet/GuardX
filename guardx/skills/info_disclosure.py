"""Information Disclosure - Sensitive data exposure."""

SKILL = {
    "id": "info_disclosure",
    "name": "Information Disclosure",
    "category": "exposure",
    "severity": "medium",

    "detection": """
- Check for exposed files:
  /.env (environment variables, API keys, DB credentials)
  /.git/config (git repository, source code leak)
  /robots.txt (reveals hidden paths)
  /sitemap.xml (full site structure)
  /.DS_Store (macOS directory listing)
  /backup.zip, /db.sql, /dump.sql (database dumps)
  /phpinfo.php (full server configuration)
  /server-status, /server-info (Apache status)
  /elmah.axd (.NET error logs)
  /wp-config.php.bak (WordPress config backup)
- Check error pages for stack traces and debug info
- Check HTTP headers for version disclosure (Server, X-Powered-By)
- Check for directory listing enabled (browse folders)
- Check for exposed API documentation: /swagger, /api-docs, /graphql
- Check for exposed admin panels: /admin, /administrator, /wp-admin
- Check for source maps in production: /*.js.map
- Check for exposed debug endpoints: /debug, /trace, /metrics, /health
- Test 404/500 pages for information leakage
""",

    "exploitation": """
- .env file: extract DB credentials, API keys, secret keys
- .git exposure: reconstruct full source code with git-dumper
- phpinfo: reveals file paths, PHP version, loaded modules, environment vars
- Stack traces: reveal code structure, libraries, file paths, query structure
- Directory listing: browse all files, find backups, configs
- Exposed database dumps: download full database with all user data
- API docs: understand all endpoints, find auth bypass opportunities
- Source maps: deobfuscate JavaScript, find hardcoded secrets
- Document: list all sensitive files/info found with contents
""",

    "remediation": """
- Block access to sensitive files in nginx:
  location ~ /\\.(?!well-known) { deny all; }
  location ~ \\.(env|git|bak|sql|log|ini|conf)$ { deny all; }
  location ~ /(phpinfo|server-status|server-info) { deny all; }

- Disable directory listing:
  nginx: autoindex off;
  Apache: Options -Indexes

- Remove debug mode in production:
  Django: DEBUG = False
  Flask: app.run(debug=False)
  Node: NODE_ENV=production
  Laravel: APP_DEBUG=false

- Hide server versions:
  nginx: server_tokens off;
  Apache: ServerTokens Prod, ServerSignature Off
  PHP: expose_php = Off in php.ini
  Remove X-Powered-By header

- Delete backup files, database dumps, .git from production
- Remove source maps from production builds
- Custom error pages that don't reveal internals
- SSH fix: add deny rules in nginx, remove exposed files
- SSH fix: set debug=false, hide versions, add custom error pages
- Verify: re-check all paths, confirm 403/404 with no info leakage
""",

    "tools": ["http_headers_check", "nmap_scan", "dir_bruteforce", "web_spider", "tech_fingerprint"],

    "payloads": [],

    "references": [
        "OWASP A01:2021 - Broken Access Control",
        "OWASP A05:2021 - Security Misconfiguration",
        "CWE-200: Exposure of Sensitive Information",
        "CWE-548: Exposure of Information Through Directory Listing",
    ],
}
