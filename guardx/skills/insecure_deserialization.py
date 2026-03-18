"""Insecure Deserialization - Object injection, RCE via serialized objects."""

SKILL = {
    "id": "insecure_deserialization",
    "name": "Insecure Deserialization",
    "category": "injection",
    "severity": "critical",

    "detection": """
- Look for serialized objects in cookies, POST body, hidden fields, API params
- Common formats:
  PHP: O:4:"User":2:{s:4:"name";... (starts with O: or a:)
  Java: rO0AB (base64) or AC ED 00 05 (hex) serialized objects
  Python: pickle data (starts with cos, c__builtin__)
  .NET: viewstate parameter in ASP.NET pages, AAEAAAD/// in base64
  Node.js: JSON with __proto__ or constructor.prototype
- Check Content-Type headers for application/x-java-serialized-object
- Look for base64-encoded data in cookies or parameters
- Check if modifying serialized data causes different errors (deserialization errors)
""",

    "exploitation": """
- PHP Object Injection: Modify serialized class to trigger __wakeup, __destruct, __toString
  Replace class properties to change behavior (role, isAdmin, etc.)
- Java deserialization: Use ysoserial to generate gadget chains
  java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin
  Target libraries: Apache Commons Collections, Spring, etc.
- Python pickle: Craft pickle payload with __reduce__ for command execution
  import pickle, os; pickle.loads(payload) → RCE
- Node.js prototype pollution: {"__proto__":{"isAdmin":true}}
  Pollute Object.prototype to affect all objects in the application
- .NET: Exploit ViewState deserialization with known machineKey
- Document: show modified object accepted by server, changed behavior
""",

    "remediation": """
- NEVER deserialize untrusted data without validation
- Use safe serialization formats: JSON instead of native serialization
- If native serialization required: implement integrity checks (HMAC signatures)
- PHP: avoid unserialize() on user input, use json_decode() instead
- Java: use look-ahead deserialization (SerialKiller, NotSoSerial)
- Python: NEVER use pickle.loads() on untrusted data, use json.loads()
- Node.js: Freeze Object.prototype, validate JSON schema before parsing
- .NET: Set TypeNameHandling.None in JSON.NET, encrypt ViewState
- Implement Content-Type validation (reject unexpected serialization formats)
- SSH fix: Replace unsafe deserialization with JSON in application code
- SSH fix: Update libraries with known deserialization CVEs
- Verify: Send modified serialized objects, confirm rejection
""",

    "tools": ["http_request", "web_spider", "tech_fingerprint", "js_analyzer"],

    "payloads": [
        'O:8:"stdClass":1:{s:4:"role";s:5:"admin";}',
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        'rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==',
    ],

    "references": [
        "OWASP A08:2021 - Software and Data Integrity Failures",
        "CWE-502: Deserialization of Untrusted Data",
    ],
}
