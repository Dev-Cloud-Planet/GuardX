"""Insecure Direct Object Reference (IDOR)."""

SKILL = {
    "id": "idor",
    "name": "Insecure Direct Object Reference (IDOR)",
    "category": "auth",
    "severity": "high",

    "detection": """
- Look for numeric IDs in URLs: /api/user/123, /invoice/456, /order/789
- Look for IDs in API requests: POST /api/profile {"user_id": 123}
- Test by changing the ID to another value (123 -> 124)
- Check if you can access other users' data without authorization
- Test in: profile pages, order history, file downloads, API endpoints
- Check for predictable IDs (sequential integers vs UUIDs)
- Test both GET and POST/PUT/DELETE methods
- Check bulk endpoints: /api/users (might return all users)
- Test parameter pollution: /api/user?id=123&id=124
- Check GraphQL queries for unauthorized data access
""",

    "exploitation": """
- Access other users' profiles, orders, invoices, personal data
- Modify other users' data via PUT/PATCH endpoints
- Delete other users' resources
- Download other users' files
- Enumerate all users by incrementing IDs: 1, 2, 3, ... N
- Chain with other vulns: get admin user data, reset their password
- Document: show request/response for own ID vs other user's ID as proof
- Show that no authorization check prevents access to other users' data
""",

    "remediation": """
- Implement authorization checks on EVERY endpoint:
  def get_order(order_id):
      order = Order.get(order_id)
      if order.user_id != current_user.id:
          return 403 Forbidden
- Use UUIDs instead of sequential integers for resource IDs
- Implement row-level security in database
- Add middleware that validates resource ownership before processing
- Never trust client-side IDs: always verify server-side
- For APIs: validate JWT/session user matches the requested resource owner
- Log and alert on patterns of sequential ID access (enumeration detection)
- SSH fix: review API code, add authorization middleware
- Verify: test accessing other user's resources, confirm 403 response
""",

    "tools": ["http_headers_check", "web_spider", "dir_bruteforce"],

    "payloads": [],

    "references": [
        "OWASP A01:2021 - Broken Access Control",
        "CWE-639: Authorization Bypass Through User-Controlled Key",
        "CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs",
    ],
}
