"""Safe subprocess execution with timeout and output limits."""
import asyncio
import shlex
from dataclasses import dataclass


@dataclass
class RunResult:
    command: str
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False


async def run(cmd: list[str], timeout: int = 300, max_output: int = 50000) -> RunResult:
    """Run a command safely. No shell=True, always a list."""
    command_str = " ".join(cmd)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return RunResult(
            command=command_str,
            stdout=stdout.decode("utf-8", errors="replace")[:max_output],
            stderr=stderr.decode("utf-8", errors="replace")[:max_output],
            returncode=proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        proc.kill()
        return RunResult(
            command=command_str,
            stdout="",
            stderr="TIMEOUT after {}s".format(timeout),
            returncode=-1,
            timed_out=True,
        )
    except FileNotFoundError:
        return RunResult(
            command=command_str,
            stdout="",
            stderr="Command not found: {}".format(cmd[0]),
            returncode=-1,
        )
