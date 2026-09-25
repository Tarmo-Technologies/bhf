# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
import queue
import re
import signal
import subprocess
import threading
from typing import Any, BinaryIO, Iterable


JsonObject = dict[str, Any]
MAX_FRAME_BYTES = 64 * 1024 * 1024
MAX_HEADER_BYTES = 8192
DEFAULT_DAEMON_TIMEOUT_SECS = 30.0


@dataclass(frozen=True)
class BhfConfig:
    daemon_path: str = "bhf-daemon"
    cli_path: str = "bhf"
    findings_dir: str = "findings"
    harness_path: str = ""
    minimize_strategy: str = "bytes"
    workspace_root: str = "."
    daemon_timeout_secs: float = DEFAULT_DAEMON_TIMEOUT_SECS

    @property
    def resolved_findings_dir(self) -> str:
        if os.path.isabs(self.findings_dir):
            return os.path.normpath(self.findings_dir)
        return os.path.normpath(os.path.join(self.workspace_root, self.findings_dir))


@dataclass(frozen=True)
class DiagnosticRecord:
    finding_id: str
    file: str
    line: int
    column: int
    text: str
    importance: str
    finding: JsonObject


@dataclass(frozen=True)
class FindingActionSpec:
    action: str
    menu_label: str
    description: str


class JsonRpcError(RuntimeError):
    def __init__(self, message: str, code: int | None = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


class StdioJsonRpcClient:
    def __init__(
        self,
        daemon_path: str,
        cwd: str | None = None,
        timeout_secs: float = DEFAULT_DAEMON_TIMEOUT_SECS,
        args: list[str] | None = None,
    ):
        if not math.isfinite(timeout_secs) or timeout_secs <= 0:
            raise ValueError("daemon timeout must be a positive finite number")
        process_options = (
            {"start_new_session": True}
            if os.name == "posix"
            else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        )
        self.process = subprocess.Popen(
            [daemon_path, *(args or [])],
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            **process_options,
        )
        self.next_id = 1
        self.timeout_secs = timeout_secs
        self._closed = False
        self._reader: threading.Thread | None = None

    def request(self, method: str, params: JsonObject | None = None) -> Any:
        if self._closed:
            raise JsonRpcError("daemon client is closed")
        if self._reader is not None and self._reader.is_alive():
            raise JsonRpcError("daemon request already in progress")
        if self.process.stdin is None or self.process.stdout is None:
            raise JsonRpcError("daemon stdio is unavailable")

        request_id = self.next_id
        self.next_id += 1
        request: JsonObject = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            request["params"] = params

        results: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

        def exchange() -> None:
            try:
                assert self.process.stdin is not None
                assert self.process.stdout is not None
                self.process.stdin.write(encode_frame(request))
                self.process.stdin.flush()
                results.put((True, read_frame(self.process.stdout)))
            except Exception as error:
                results.put((False, error))

        self._reader = threading.Thread(target=exchange, name="bhf-daemon-response", daemon=True)
        self._reader.start()
        try:
            ok, result = results.get(timeout=self.timeout_secs)
        except queue.Empty as error:
            self.close()
            raise TimeoutError(f"BHF daemon request exceeded {self.timeout_secs:g} seconds") from error
        if not ok:
            self.close()
            raise result
        response = result
        if response.get("id") != request_id:
            raise JsonRpcError("daemon returned a response with an unexpected id")
        if "error" in response:
            error = response["error"]
            if isinstance(error, dict):
                raise JsonRpcError(
                    str(error.get("message", "JSON-RPC request failed")),
                    error.get("code") if isinstance(error.get("code"), int) else None,
                    error.get("data"),
                )
            raise JsonRpcError("JSON-RPC request failed")
        return response.get("result")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if os.name == "posix":
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif self.process.poll() is None:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        if self.process.poll() is None:
            try:
                self.process.kill()
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        if self._reader is not None:
            self._reader.join(timeout=1)
        if self._reader is None or not self._reader.is_alive():
            for stream in (self.process.stdin, self.process.stdout):
                if stream is not None:
                    stream.close()


def encode_frame(message: JsonObject) -> bytes:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    return header + body


def read_frame(stream: BinaryIO) -> JsonObject:
    headers: list[bytes] = []
    header_bytes = 0
    while True:
        line = stream.readline(MAX_HEADER_BYTES - header_bytes + 1)
        if line == b"":
            raise EOFError("unexpected EOF while reading JSON-RPC headers")
        header_bytes += len(line)
        if header_bytes > MAX_HEADER_BYTES:
            raise ValueError("JSON-RPC header exceeds the maximum size")
        if not line.endswith(b"\n"):
            raise ValueError("JSON-RPC header line is incomplete")
        if line in (b"\r\n", b"\n"):
            break
        headers.append(line)

    content_length = None
    for header in headers:
        name, _, value = header.decode("ascii").partition(":")
        if name.lower() == "content-length":
            content_length = int(value.strip())
            break
    if content_length is None:
        raise ValueError("JSON-RPC frame is missing Content-Length")
    if content_length < 0 or content_length > MAX_FRAME_BYTES:
        raise ValueError("JSON-RPC body exceeds the maximum size")

    body = stream.read(content_length)
    if len(body) != content_length:
        raise EOFError("unexpected EOF while reading JSON-RPC body")
    value = json.loads(body.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON-RPC body must be an object")
    return value


def load_findings(config: BhfConfig) -> list[JsonObject]:
    client = StdioJsonRpcClient(
        config.daemon_path,
        cwd=config.workspace_root,
        timeout_secs=config.daemon_timeout_secs,
    )
    try:
        result = client.request("findings", {"findings": config.resolved_findings_dir})
    finally:
        client.close()
    findings = result.get("findings", []) if isinstance(result, dict) else []
    return [finding for finding in findings if isinstance(finding, dict)]


def diagnostic_records(
    findings: Iterable[JsonObject],
    workspace_root: str,
) -> list[DiagnosticRecord]:
    records = []
    for finding in findings:
        location = primary_location(finding)
        file_name = location.get("file") if location else None
        if not isinstance(file_name, str) or not file_name:
            continue
        records.append(
            DiagnosticRecord(
                finding_id=finding_id(finding),
                file=resolve_workspace_path(file_name, workspace_root),
                line=max(int(location.get("line", 1) or 1), 1),
                column=max(int(location.get("col", 1) or 1), 1),
                text=message_text(finding),
                importance=importance_for_severity(finding.get("severity")),
                finding=finding,
            )
        )
    return records


def primary_location(finding: JsonObject) -> JsonObject | None:
    actionability = finding.get("actionability")
    if isinstance(actionability, dict):
        fix = actionability.get("fix_location")
        if isinstance(fix, dict):
            path = fix.get("file") or fix.get("path")
            if isinstance(path, str) and path:
                return {"file": path, "line": fix.get("line"), "col": fix.get("col")}
    exception = finding.get("exception")
    if not isinstance(exception, dict):
        return None
    for key in ("handler", "last_breadcrumb", "explicit_raise"):
        location = exception.get(key)
        if isinstance(location, dict) and isinstance(location.get("file"), str):
            return location
    return None


def resolve_workspace_path(file_name: str, workspace_root: str) -> str:
    if os.path.isabs(file_name):
        return os.path.normpath(file_name)
    return os.path.normpath(os.path.join(workspace_root, file_name))


def message_text(finding: JsonObject) -> str:
    parts = [
        "BHF",
        str(finding.get("classification") or "finding"),
        finding_id(finding),
    ]
    actionability = finding.get("actionability")
    if isinstance(actionability, dict):
        if actionability.get("verdict"):
            parts.append(str(actionability["verdict"]))
        if actionability.get("confidence"):
            parts.append(str(actionability["confidence"]))
    signature = finding.get("signature")
    if signature:
        parts.append(str(signature))
    exception = finding.get("exception")
    if isinstance(exception, dict) and exception.get("name"):
        parts.append(str(exception["name"]))
    return " ".join(parts)


def importance_for_severity(severity: Any) -> str:
    normalized = str(severity or "unknown").lower()
    if normalized in ("critical", "high"):
        return "HIGH"
    if normalized in ("low",):
        return "LOW"
    if normalized in ("info", "informational"):
        return "INFORMATIONAL"
    return "MEDIUM"


def build_replay_args(finding: JsonObject, config: BhfConfig) -> list[str]:
    args = [config.cli_path, "replay", "--finding", finding_path(finding, config)]
    if config.harness_path.strip():
        args.extend(["--harness", config.harness_path])
    return args


def build_minimize_args(finding: JsonObject, config: BhfConfig) -> list[str]:
    strategy = config.minimize_strategy if config.minimize_strategy in ("bytes", "typed") else "bytes"
    args = [config.cli_path, "minimize", "--finding", finding_path(finding, config)]
    if config.harness_path.strip():
        args.extend(["--harness", config.harness_path])
    args.extend(["--strategy", strategy])
    return args


def resolve_reproducer_path(finding: JsonObject, config: BhfConfig) -> str | None:
    artifact = finding.get("generated_repro_ada")
    if not isinstance(artifact, str) or not artifact:
        return None
    if os.path.isabs(artifact):
        return os.path.normpath(artifact)
    return os.path.normpath(os.path.join(config.resolved_findings_dir, artifact))


def finding_path(finding: JsonObject, config: BhfConfig) -> str:
    identifier = finding_id(finding)
    if (
        identifier in (".", "..")
        or "\\" in identifier
        or ":" in identifier
        or os.path.basename(identifier) != identifier
    ):
        raise ValueError("BHF finding has an invalid ID")
    return os.path.normpath(os.path.join(config.resolved_findings_dir, identifier))


def action_name(action: str, finding: str) -> str:
    return f"BHF {safe_label(action)} {safe_label(finding)}"


def finding_action_specs(finding: JsonObject) -> list[FindingActionSpec]:
    actions = [
        FindingActionSpec("replay", "Replay this finding", "Replay this finding"),
        FindingActionSpec("minimize", "Minimize", "Minimize this finding"),
    ]
    if isinstance(finding.get("generated_repro_ada"), str) and finding["generated_repro_ada"]:
        actions.append(
            FindingActionSpec("open-repro", "Open repro.adb", "Open generated repro.adb")
        )
    return actions


def safe_label(value: str) -> str:
    label = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    label = label.strip("_")
    return label or "item"


def finding_id(finding: JsonObject) -> str:
    value = finding.get("id")
    return str(value) if value else "unknown-finding"
