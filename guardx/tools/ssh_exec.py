"""SSH remote execution tool for remediation."""
import paramiko

TOOL_SCHEMA = {
    "name": "ssh_exec",
    "description": (
        "Execute a command on the remote server via SSH. "
        "Used for remediation: applying fixes, installing packages, "
        "changing configs. REQUIRES user confirmation before execution."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "Shell command to execute"},
            "description": {"type": "string", "description": "What this command does and why"},
        },
        "required": ["command", "description"],
    },
}


def is_available() -> bool:
    return True


class SSHConnection:
    def __init__(self):
        self.client = None

    def connect(self, host: str, user: str, password: str = None, key_path: str = None, port: int = 22):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {"hostname": host, "port": port, "username": user}
        if key_path:
            kwargs["key_filename"] = key_path
        if password:
            kwargs["password"] = password
        self.client.connect(**kwargs)

    def run(self, command: str, timeout: int = 60) -> str:
        if not self.client:
            return "ERROR: Not connected via SSH"
        _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return out if out else err if err else "(no output)"

    def close(self):
        if self.client:
            self.client.close()


_connection = SSHConnection()


def get_connection() -> SSHConnection:
    return _connection


async def execute(params: dict) -> str:
    command = params["command"]
    conn = get_connection()
    if not conn.client:
        return "ERROR: SSH not connected. Connect first."
    return conn.run(command)
