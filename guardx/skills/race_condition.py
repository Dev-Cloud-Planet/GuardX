"""Race Condition / TOCTOU - Time-of-check to time-of-use vulnerabilities."""

SKILL = {
    "id": "race_condition",
    "name": "Race Condition (TOCTOU)",
    "category": "web",
    "severity": "high",

    "detection": """
- Look for operations that check-then-act: balance checks, coupon redemption, voting
- Identify stateful operations: transfer money, apply discount, redeem code, register
- Look for endpoints without proper locking/transaction isolation
- Test: send same request multiple times simultaneously
- Common targets:
  - Financial: transfer, withdraw, payment, purchase
  - Coupons: redeem, apply-code, activate
  - Voting/rating: vote, like, upvote
  - Registration: claim username, email verification
  - File operations: upload, rename, delete
- Check for race windows in multi-step processes (add to cart → checkout)
""",

    "exploitation": """
- Send 10-50 parallel requests to the same endpoint simultaneously
- Use tools: Burp Intruder (Pitchfork), curl parallel, Python threading
- Example: send 20 requests to /api/redeem-coupon with same code
  If coupon redeemed more than once = race condition confirmed
- Example: send 10 parallel /api/transfer with same amount
  If balance goes negative = race condition in transaction
- Single-packet attack: send multiple HTTP/2 requests in single TCP packet
  Eliminates network jitter for tighter race window
- Document: show that operation executed multiple times when it should be once
""",

    "remediation": """
- Use database transactions with proper isolation level (SERIALIZABLE)
- Implement optimistic locking (version numbers on records)
- Use distributed locks (Redis SETNX) for critical operations
- Use unique constraint + INSERT instead of SELECT-then-INSERT
- Implement idempotency keys for payment/financial operations
- Add rate limiting on sensitive endpoints
- Use atomic operations: UPDATE ... SET balance = balance - amount WHERE balance >= amount
- For file operations: use atomic rename instead of write-then-move
- SSH fix: Wrap critical DB operations in transactions
- SSH fix: Add UNIQUE constraints to prevent duplicate redemptions
- Verify: Run parallel requests again, confirm only one succeeds
""",

    "tools": ["http_request", "api_fuzzer", "web_spider"],

    "payloads": [
        "# Python parallel test:\nimport concurrent.futures, requests\ndef send(): requests.post(url, json=data)\nwith concurrent.futures.ThreadPoolExecutor(max_workers=20) as e: [e.submit(send) for _ in range(20)]",
    ],

    "references": [
        "OWASP A04:2021 - Insecure Design",
        "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization",
        "CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition",
    ],
}
