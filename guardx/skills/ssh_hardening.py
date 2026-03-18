"""SSH Server Hardening."""

SKILL = {
    "id": "ssh_hardening",
    "name": "SSH Server Hardening",
    "category": "config",
    "severity": "high",

    "detection": """
- Check if SSH allows root login: PermitRootLogin yes is dangerous
- Check if password authentication is enabled (should be key-only)
- Check SSH port: default 22 is targeted by bots
- Check for weak algorithms: hmac-sha1, diffie-hellman-group1, ssh-rsa (SHA-1)
- Check if fail2ban or similar is installed and active
- Check SSH banner for version disclosure
- Check MaxAuthTries setting (should be 3 or less)
- Check if empty passwords are allowed
- Check LoginGraceTime (should be 60 or less)
- Check AllowUsers/AllowGroups restrictions
- Verify authorized_keys file permissions (600)
- Check if X11 forwarding is enabled unnecessarily
- Check if TCP forwarding is restricted
""",

    "exploitation": """
- Root login enabled: brute force root password directly
- Password auth enabled: automated brute force with hydra, medusa
- Default port 22: constant bot attacks, credential stuffing
- Weak algorithms: potential downgrade attacks
- No fail2ban: unlimited brute force attempts
- High MaxAuthTries: more guesses per connection
- Empty passwords: trivial access
- Document: show SSH config weaknesses, brute force feasibility
""",

    "remediation": """
- Edit /etc/ssh/sshd_config:
  PermitRootLogin no
  PasswordAuthentication no
  PubkeyAuthentication yes
  MaxAuthTries 3
  LoginGraceTime 60
  PermitEmptyPasswords no
  X11Forwarding no
  AllowTcpForwarding no
  Protocol 2

- Remove weak algorithms. Add to sshd_config:
  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

- Install and configure fail2ban:
  sudo apt install fail2ban -y
  sudo systemctl enable fail2ban
  Create /etc/fail2ban/jail.local:
    [sshd]
    enabled = true
    port = 22
    maxretry = 3
    bantime = 3600
    findtime = 600

- Optional: change SSH port (add to sshd_config: Port 2222)
- Restart: sudo systemctl restart sshd
- IMPORTANT: test new SSH connection BEFORE closing current session
- Verify: nmap scan confirms changes, try password login (should fail)
""",

    "tools": ["nmap_scan", "port_check", "ssh_exec"],

    "payloads": [],

    "references": [
        "OWASP A05:2021 - Security Misconfiguration",
        "CWE-250: Execution with Unnecessary Privileges",
        "CWE-307: Improper Restriction of Excessive Authentication Attempts",
    ],
}
