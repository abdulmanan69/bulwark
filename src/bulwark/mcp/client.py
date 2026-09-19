"""A minimal MCP client, used only to ask a server what it offers.

Static configuration almost never lists tools, so an offline scan cannot see
the descriptions that actually reach the model.  This module performs the one
exchange that reveals them: initialize, then ``tools/list``, ``prompts/list``
and ``resources/list``.

Three deliberate constraints:

* **No tool is ever called.**  We list, we never invoke.
* **No third-party dependency.**  JSON-RPC over a pipe is a hundred lines; a
  security scanner should not pull in a transitive tree to do it.
* **Everything is bounded.**  A hostile or broken server gets a timeout, a
  response-size cap and a forced kill, because "the scanner hung" is the
  failure mode that gets scanners removed from CI.

Starting a server is a real side effect -- it runs third-party code -- which is
why this only happens under an explicit ``--online`` flag.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..core.models import Artifact, ArtifactKind, ScanError, SourceRef
from ..discovery.mcp_config import build_tool_artifact

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "bulwark-scanner", "version": "0.1.0"}

#: Refuse to buffer more than this from a single server.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class McpError(Exception):
    """Any failure talking to a server.  Always caught by the caller."""


class StdioClient:
    """One short-lived JSON-RPC session over a child process's stdio."""

    def __init__(
        self,
        command: str,
        args: Sequence[str],
        env: Optional[Dict[str, str]] = None,
        *,
        timeout: float = 20.0,
        cwd: Optional[str] = None,
    ) -> None:
        self.command = command
        self.args = list(args)
        self.env = dict(env or {})
        self.timeout = timeout
        self.cwd = cwd
        self.process: Optional[subprocess.Popen] = None
        self._next_id = 0
        self._stderr: List[str] = []
        self._bytes_read = 0

    # ---- lifecycle -------------------------------------------------------

    def __enter__(self) -> "StdioClient":
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    def start(self) -> None:
        environment = os.environ.copy()
        environment.update({str(k): str(v) for k, v in self.env.items()})
        # A server that asks for a terminal, a pager or colour will hang or
        # emit escape codes into the protocol stream.  Tell it not to.
        environment.setdefault("NO_COLOR", "1")
        environment.setdefault("TERM", "dumb")
        environment.setdefault("CI", "1")

        try:
            self.process = subprocess.Popen(
                [self.command, *self.args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=self.cwd,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except (OSError, ValueError) as exc:
            raise McpError("could not start server: %s" % exc) from exc

        # Drain stderr on a daemon thread.  A server that logs heavily will
        # otherwise fill the pipe buffer and deadlock waiting for us to read.
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _drain_stderr(self) -> None:
        process = self.process
        if process is None or process.stderr is None:
            return
        try:
            for line in process.stderr:
                if len(self._stderr) < 200:
                    self._stderr.append(line.rstrip())
        except (ValueError, OSError):
            pass

    def close(self) -> None:
        process = self.process
        if process is None:
            return
        with contextlib.suppress(OSError, ValueError):
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=3)
        self.process = None

    # ---- protocol --------------------------------------------------------

    def _send(self, payload: Dict[str, Any]) -> None:
        process = self.process
        if process is None or process.stdin is None:
            raise McpError("server is not running")
        try:
            process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
            process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise McpError("server closed its input: %s" % exc) from exc

    def _read_response(self, request_id: int, deadline: float) -> Dict[str, Any]:
        """Read until the matching response arrives, the deadline passes, or
        the server exits.

        Servers interleave notifications and log lines with responses, so
        anything that is not the response we asked for is skipped rather than
        treated as an error.
        """
        process = self.process
        if process is None or process.stdout is None:
            raise McpError("server is not running")

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise McpError("timed out waiting for response")

            line = _readline_with_timeout(process.stdout, remaining)
            if line is _TIMEOUT:
                raise McpError("timed out waiting for response")
            if line is _EOF:
                # The stream closed. Give the process a moment to be reaped
                # before reporting: without the wait, poll() often still
                # returns None and a crashed server looks like a hang, which
                # sends the user looking in entirely the wrong place.
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=3)
                raise McpError(
                    "server closed its output without replying (exit code %s)%s"
                    % (process.returncode, self._stderr_tail())
                )
            assert isinstance(line, str)

            self._bytes_read += len(line)
            if self._bytes_read > MAX_RESPONSE_BYTES:
                raise McpError("server sent more than the response size limit")

            stripped = line.strip()
            if not stripped or not stripped.startswith("{"):
                continue  # a log line on stdout; not fatal, just not ours
            try:
                message = json.loads(stripped)
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("id") == request_id:
                return message

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        self._next_id += 1
        request_id = self._next_id
        self._send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params or {},
            }
        )
        message = self._read_response(request_id, time.monotonic() + self.timeout)
        if "error" in message:
            error = message.get("error") or {}
            raise McpError(
                "%s failed: %s (%s)"
                % (method, error.get("message", "unknown"), error.get("code", "?"))
            )
        return message.get("result")

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def initialize(self) -> Dict[str, Any]:
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                # Declare no capabilities: we are inspecting, not participating.
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        self.notify("notifications/initialized")
        return result if isinstance(result, dict) else {}

    def list_all(self, method: str, key: str) -> List[Dict[str, Any]]:
        """Page through a ``*/list`` method until the cursor runs out."""
        items: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        for _ in range(20):  # bound the paging; no honest server needs more
            params = {"cursor": cursor} if cursor else {}
            result = self.request(method, params)
            if not isinstance(result, dict):
                break
            page = result.get(key)
            if isinstance(page, list):
                items.extend(item for item in page if isinstance(item, dict))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return items

    def _stderr_tail(self) -> str:
        if not self._stderr:
            return ""
        return ": " + " / ".join(self._stderr[-3:])[:300]


class _Sentinel:
    """A distinct, readable marker for the two non-line outcomes."""

    def __init__(self, label: str) -> None:
        self.label = label

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<%s>" % self.label


#: The stream closed: the server is gone, or has stopped talking for good.
_EOF = _Sentinel("eof")
#: The deadline passed with the stream still open: the server is just slow.
_TIMEOUT = _Sentinel("timeout")


def _readline_with_timeout(stream: Any, timeout: float) -> Any:
    """Read one line, giving up after ``timeout`` seconds.

    Returns the line, :data:`_EOF`, or :data:`_TIMEOUT`.  Distinguishing the
    last two matters: "your server crashed, here is its stderr" and "your
    server is slow" send a user to completely different places.

    ``stream.readline()`` has no timeout on any platform, so the read happens
    on a throwaway thread.  The thread is a daemon: if the server never writes
    anything the interpreter still exits cleanly.
    """
    box: List[Any] = [_EOF]

    def read() -> None:
        try:
            line = stream.readline()
        except (ValueError, OSError):
            line = ""
        box[0] = line if line else _EOF

    thread = threading.Thread(target=read, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return _TIMEOUT
    return box[0]


# --------------------------------------------------------------------------
# Introspection
# --------------------------------------------------------------------------


def introspect_servers(
    artifacts: Sequence[Artifact], *, timeout: float = 20.0
) -> Tuple[List[Artifact], List[ScanError]]:
    """Connect to every enabled stdio server and record what it advertises.

    Remote (HTTP/SSE) servers are skipped: reaching them would send this
    machine's credentials to a third party as a side effect of running a
    security scan, which is not a trade a scanner gets to make on the user's
    behalf.
    """
    produced: List[Artifact] = []
    errors: List[ScanError] = []

    for server in artifacts:
        if server.kind is not ArtifactKind.MCP_SERVER or server.data.get("disabled"):
            continue
        command = str(server.data.get("command") or "")
        if not command:
            errors.append(
                ScanError(
                    where="introspect:" + server.identity,
                    message="skipped: remote transports are not contacted during a scan",
                    kind="skipped",
                )
            )
            continue

        try:
            produced.extend(_introspect_one(server, command, timeout))
        except McpError as exc:
            errors.append(
                ScanError(
                    where="introspect:" + server.identity,
                    message=str(exc),
                    kind="introspection_error",
                )
            )
        except Exception as exc:
            errors.append(
                ScanError(
                    where="introspect:" + server.identity,
                    message="%s: %s" % (type(exc).__name__, exc),
                    kind="introspection_error",
                )
            )

    return produced, errors


def _introspect_one(server: Artifact, command: str, timeout: float) -> List[Artifact]:
    args = [str(a) for a in server.data.get("args", [])]
    env = {str(k): str(v) for k, v in (server.data.get("env") or {}).items()}
    config_path = str(server.data.get("config_path") or server.source.path)

    out: List[Artifact] = []
    with StdioClient(command, args, env, timeout=timeout) as client:
        info = client.initialize()
        capabilities = info.get("capabilities") or {}
        server.data["live"] = {
            "server_info": info.get("serverInfo", {}),
            "protocol_version": info.get("protocolVersion", ""),
            "capabilities": sorted(capabilities.keys()),
        }

        # An empty capabilities block is not conclusive -- several servers omit
        # it and still serve tools -- so try tools/list regardless.
        if "tools" in capabilities or not capabilities:
            for tool in client.list_all("tools/list", "tools"):
                name = str(tool.get("name") or "")
                if not name:
                    continue
                schema = tool.get("inputSchema") or tool.get("input_schema") or {}
                annotations = tool.get("annotations") or {}
                out.append(
                    build_tool_artifact(
                        server=server,
                        name=name,
                        description=str(tool.get("description") or ""),
                        schema=schema if isinstance(schema, dict) else {},
                        annotations=annotations if isinstance(annotations, dict) else {},
                        path=config_path,
                        origin="live",
                    )
                )

        if "prompts" in capabilities:
            for prompt in client.list_all("prompts/list", "prompts"):
                name = str(prompt.get("name") or "")
                if name:
                    out.append(
                        _simple_artifact(
                            server,
                            ArtifactKind.MCP_PROMPT,
                            name,
                            str(prompt.get("description") or ""),
                            config_path,
                            {"arguments": prompt.get("arguments") or []},
                        )
                    )

        if "resources" in capabilities:
            for resource in client.list_all("resources/list", "resources"):
                uri = str(resource.get("uri") or resource.get("name") or "")
                if uri:
                    out.append(
                        _simple_artifact(
                            server,
                            ArtifactKind.MCP_RESOURCE,
                            uri,
                            str(resource.get("description") or ""),
                            config_path,
                            {
                                "mime_type": resource.get("mimeType", ""),
                                "name": resource.get("name", ""),
                            },
                        )
                    )

    return out


def _simple_artifact(
    server: Artifact,
    kind: ArtifactKind,
    name: str,
    description: str,
    path: str,
    extra: Dict[str, Any],
) -> Artifact:
    data: Dict[str, Any] = {"origin": "live", "server": server.identity}
    data.update(extra)
    return Artifact(
        kind=kind,
        identity="%s:%s" % (server.identity, name),
        name=name,
        platform=server.platform,
        parent=server.identity,
        source=SourceRef(path=path),
        text=description,
        trust=server.trust,
        data=data,
        tags=[kind.value.replace("_", "-"), "live"],
    )
