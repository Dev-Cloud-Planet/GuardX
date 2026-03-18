"""Exposed Services - Databases, admin panels, APIs not meant to be public."""

SKILL = {
    "id": "exposed_services",
    "name": "Exposed Services & Ports",
    "category": "network",
    "severity": "critical",

    "detection": """
- Scan all common ports: 21(FTP), 22(SSH), 25(SMTP), 53(DNS), 80(HTTP), 443(HTTPS)
- Scan database ports: 3306(MySQL), 5432(PostgreSQL), 27017(MongoDB), 6379(Redis), 1433(MSSQL)
- Scan admin/dev ports: 8080, 8443, 9090, 9200(Elasticsearch), 5601(Kibana)
- Scan message queues: 5672(RabbitMQ), 9092(Kafka), 11211(Memcached)
- Check if databases accept connections from external IPs
- Check if admin panels (phpMyAdmin, Adminer, pgAdmin) are publicly accessible
- Check for Docker API exposed: port 2375/2376
- Check for Kubernetes API: port 6443, 10250
- Verify each open port: is it intentional or misconfigured?
""",

    "exploitation": """
- PostgreSQL: attempt connection with common credentials (postgres/postgres, admin/admin)
- MySQL: attempt anonymous login or common creds
- MongoDB: check if auth is disabled (default in older versions)
- Redis: send PING, if PONG returned = no auth. Then INFO to get server details
- Elasticsearch: curl http://target:9200/_cat/indices to list all data
- Memcached: echo "stats" | nc target 11211
- Docker API: curl http://target:2375/containers/json to list containers
- FTP: try anonymous login
- Document all services reachable and data accessible without credentials
""",

    "remediation": """
- IMMEDIATE: Configure firewall to block non-essential ports from public access
  sudo ufw default deny incoming
  sudo ufw allow 22/tcp    # SSH
  sudo ufw allow 80/tcp    # HTTP
  sudo ufw allow 443/tcp   # HTTPS
  sudo ufw enable
- Bind databases to localhost only:
  PostgreSQL: listen_addresses = 'localhost' in postgresql.conf
  MySQL: bind-address = 127.0.0.1 in my.cnf
  MongoDB: bindIp: 127.0.0.1 in mongod.conf
  Redis: bind 127.0.0.1 in redis.conf
- Use SSH tunnels or VPN for remote database access
- Enable authentication on ALL services (Redis, MongoDB, Elasticsearch)
- Remove or restrict admin panels to internal network only
- Block Docker API from external: never expose port 2375 publicly
- SSH fix: ufw deny {port} for each unnecessary exposed port
- SSH fix: Edit service config to bind to 127.0.0.1
- Verify: re-scan ports after firewall changes
""",

    "tools": ["port_check", "nmap_scan", "tech_fingerprint"],

    "payloads": [],

    "references": [
        "OWASP A05:2021 - Security Misconfiguration",
        "CWE-200: Exposure of Sensitive Information",
        "CWE-284: Improper Access Control",
    ],
}
