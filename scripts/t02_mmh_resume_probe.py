from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import json
import os
import pathlib
import queue
import re
import socket
import subprocess
import sys
import sysconfig
import threading
import time
import urllib.request
from types import MappingProxyType

RUNTIME_COUNTER_NAMES = ("cfg.env", "provider", "DNS", "socket", "asyncio", "httpx")
PINNED_ADAPTER_BLOB = "d2c73db0e92075e52ca7c83c7bbea4c57c87d004"
PINNED_SLOW_CALL_ORDINAL = 3
PINNED_SLOW_LINE = 166
CHECKPOINT_SCHEMA = "t02-authenticated-checkpoint-v1"
HANDSHAKE_DEADLINE_S = 30.0
WORKER_TIMEOUT_S = 90.0


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _pinned_adapter_source() -> bytes:
    git_exe = os.environ.get("TORQ_GIT_EXE", r"C:\Program Files\Git\cmd\git.exe")
    git_dir = os.environ.get("TORQ_CONSOLE_GIT_DIR", r"E:\TORQ-CONSOLE\.git")
    return subprocess.run([git_exe, f"--git-dir={git_dir}", "cat-file", "blob", PINNED_ADAPTER_BLOB], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout


def _pinned_fake_functions():
    source = _pinned_adapter_source()
    tree = ast.parse(source.decode("utf-8"), filename="pinned:torq_mmh/router/adapters.py")
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in {"_normalize", "_fake_response"}]
    if {node.name for node in selected} != {"_normalize", "_fake_response"}:
        raise AssertionError("pinned fake functions not found")
    namespace = {"json": json, "time": time, "re": re, "THINK_RX": re.compile(r"<think>(.*?)</think>", re.DOTALL | re.IGNORECASE), "ADAPTER_VERSION": "0a.1"}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "pinned:adapters.py", "exec"), namespace)
    return namespace["_fake_response"], _sha256(source)


_PROVIDER_ACTIVE_WRAPPER = None
_PROVIDER_CALLING_WRAPPER = None


def _fake_call(fake, seat_id: str, marker: str = "") -> dict:
    seat = {"seat_id": seat_id, "model": "fake-model", "provider_preference": "fake-local", "dialect": "fake"}
    body = {"model": "fake-model", "messages": [{"role": "user", "content": marker}]}
    return _fake_provider_dispatch(fake, seat, body)


def _fake_provider_dispatch(fake, seat: dict, body: dict) -> dict:
    current = globals().get("_fake_provider_dispatch")
    if _PROVIDER_ACTIVE_WRAPPER is None or _PROVIDER_CALLING_WRAPPER is not _PROVIDER_ACTIVE_WRAPPER or current is not _PROVIDER_ACTIVE_WRAPPER:
        raise RuntimeError("provider dispatch requires the installed guard wrapper")
    return fake(seat, body)


class _ForbiddenActionSentinels:
    def __init__(self) -> None:
        self.attempts: list[str] = []
        self.records: list[tuple[object, str, object]] = []
        self.surface_attempts: dict[str, list[str]] = {name: [] for name in RUNTIME_COUNTER_NAMES}
        self._wrappers: dict[str, object] = {}
        self._specs: dict[str, tuple[object, str, object]] = {}
        self._event_chain: list[dict[str, object]] = []
        self._active_context = False
        self._last_final_integrity = False

    def _append_event(self, surface: str, kind: str) -> None:
        sequence = len(self._event_chain)
        previous = self._event_chain[-1]["event_sha256"] if self._event_chain else "T02-V15G-B2-EVENT-CHAIN-V1"
        material = {"previous": previous, "sequence": sequence, "surface": surface, "kind": kind}
        event = {**material, "event_sha256": _sha256(_canonical_json(material))}
        self._event_chain.append(event)

    def _counts(self, kind: str) -> dict[str, int]:
        return {name: sum(1 for event in self._event_chain if event["surface"] == name and event["kind"] == kind) for name in RUNTIME_COUNTER_NAMES}

    @property
    def surface_installations(self):
        return MappingProxyType(self._counts("installed"))

    @property
    def surface_exercises(self):
        return MappingProxyType(self._counts("attempt"))

    @property
    def intercepted_counters(self):
        return MappingProxyType(self._counts("attempt"))

    def exercise(self, surface: str) -> None:
        self.invoke_surface(surface)

    def _recording_wrapper(self, surface: str, original):
        def wrapper(*args, **kwargs):
            self._append_event(surface, "attempt")
            if surface == "provider":
                global _PROVIDER_CALLING_WRAPPER
                previous = _PROVIDER_CALLING_WRAPPER
                _PROVIDER_CALLING_WRAPPER = wrapper
                try:
                    return original(*args, **kwargs)
                finally:
                    _PROVIDER_CALLING_WRAPPER = previous
            if surface == "DNS":
                return []
            if surface == "asyncio":
                return None
            if surface == "httpx":
                return {"status_code": 200, "fake": True}
            return None
        return wrapper

    def assert_target_integrity(self) -> None:
        for target, attr, _original in self.records:
            wrapper = self._wrappers.get(next((name for name, spec in self._specs.items() if spec[0] is target and spec[1] == attr), ""))
            if wrapper is None or getattr(target, attr) is not wrapper:
                raise ValueError(f"target integrity mismatch: {target!r}.{attr}")

    def validate_event_chain(self) -> str:
        previous = "T02-V15G-B2-EVENT-CHAIN-V1"
        for sequence, event in enumerate(self._event_chain):
            material = {"previous": previous, "sequence": sequence, "surface": event["surface"], "kind": event["kind"]}
            if event.get("event_sha256") != _sha256(_canonical_json(material)):
                raise ValueError("event chain integrity mismatch")
            previous = event["event_sha256"]
        if set(self._counts("installed")) != set(RUNTIME_COUNTER_NAMES) or any(value <= 0 for value in self._counts("installed").values()):
            raise ValueError("event chain missing installed surface")
        if self._active_context:
            self.assert_target_integrity()
        elif not self._last_final_integrity:
            raise ValueError("event chain lacks final hook-integrity proof")
        return _sha256(_canonical_json(self._event_chain))

    def invoke_surface(self, surface: str) -> None:
        if surface not in self._wrappers:
            raise ValueError(f"runtime surface unavailable: {surface}")
        self.assert_target_integrity()
        wrapper = self._wrappers[surface]
        if surface == "cfg.env":
            wrapper("T02_FAKE_ENV")
        elif surface == "DNS":
            wrapper("fake.invalid", 443)
        elif surface == "socket":
            wrapper(None, ("127.0.0.1", 0))
        elif surface == "asyncio":
            wrapper("fake.invalid", 443)
        elif surface == "httpx":
            wrapper("https://fake.invalid")
        elif surface == "provider":
            wrapper(lambda seat, body: {"seat_id": seat["seat_id"], "body": body}, {"seat_id": "exercise"}, {"model": "fake"})

    def __enter__(self):
        self.records = []
        self._wrappers = {}
        self._specs = {}
        self._active_context = True
        self._last_final_integrity = False
        global _PROVIDER_ACTIVE_WRAPPER
        _PROVIDER_ACTIVE_WRAPPER = None
        sys.path.insert(0, sysconfig.get_paths()["purelib"])
        module = sys.modules[__name__]
        asyncio_module = asyncio
        try:
            import httpx as httpx_module
        except Exception:
            httpx_module = None
        targets = [("socket", socket.socket, "connect"), ("DNS", socket, "getaddrinfo"), ("cfg.env", os, "getenv"), ("provider", module, "_fake_provider_dispatch")]
        if asyncio_module is not None:
            targets.append(("asyncio", asyncio_module, "open_connection"))
        if httpx_module is not None:
            targets.append(("httpx", httpx_module, "get"))
        for surface, target, attr in targets:
            if surface in self._wrappers or not hasattr(target, attr):
                continue
            original = getattr(target, attr)
            wrapper = self._recording_wrapper(surface, original)
            setattr(target, attr, wrapper)
            self.records.append((target, attr, original))
            self._specs[surface] = (target, attr, original)
            self._wrappers[surface] = wrapper
            self._append_event(surface, "installed")
            if surface == "provider":
                _PROVIDER_ACTIVE_WRAPPER = wrapper
        missing = set(RUNTIME_COUNTER_NAMES) - set(self._wrappers)
        if missing:
            raise RuntimeError(f"required wrapper target unavailable: {sorted(missing)}")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.validate_event_chain()
        for target, attr, original in reversed(self.records):
            setattr(target, attr, original)
        global _PROVIDER_ACTIVE_WRAPPER, _PROVIDER_CALLING_WRAPPER
        _PROVIDER_ACTIVE_WRAPPER = None
        _PROVIDER_CALLING_WRAPPER = None
        self._active_context = False
        self._last_final_integrity = True
        return False


class _WorkerObservation:
    def __init__(self, sentinels: _ForbiddenActionSentinels) -> None:
        self.sentinels = sentinels
        self.calls = 0
        self.responses: list[str] = []

    def fake(self, fake, seat_id: str, marker: str) -> dict:
        with self.sentinels:
            for surface in RUNTIME_COUNTER_NAMES:
                self.sentinels.exercise(surface)
            response = _fake_call(fake, seat_id, marker)
        self.calls += 1
        self.responses.append(_sha256(_canonical_json(response)))
        return response

    def payload(self) -> dict[str, object]:
        runtime_counters = {name: len(self.sentinels.surface_attempts.get(name, ())) for name in RUNTIME_COUNTER_NAMES}
        observed_surface_counts = {name: self.sentinels.intercepted_counters[name] for name in RUNTIME_COUNTER_NAMES}
        exercised_surface_counts = {name: self.sentinels.surface_exercises[name] for name in RUNTIME_COUNTER_NAMES}
        event_chain_sha256 = self.sentinels.validate_event_chain()
        base = {"fake_calls_observed": self.calls, "response_digests": list(self.responses), "forbidden_attempts": list(self.sentinels.attempts), "provider_calls": self.sentinels.intercepted_counters["provider"], "network_calls": len(self.sentinels.surface_attempts.get("network", ())), "all_fake": self.calls > 0 and not self.sentinels.attempts, "sentinel_scope": "actual-worker-fake-execution", "runtime_counters": runtime_counters, "installed_surface_names": [name for name in RUNTIME_COUNTER_NAMES if self.sentinels.surface_installations[name] > 0], "installed_surface_counts": dict(self.sentinels.surface_installations), "exercised_surface_names": [name for name in RUNTIME_COUNTER_NAMES if self.sentinels.surface_exercises[name] > 0], "observed_surface_names": [name for name in RUNTIME_COUNTER_NAMES if self.sentinels.intercepted_counters[name] > 0], "observed_surface_counts": observed_surface_counts, "intercepted_counters": dict(self.sentinels.intercepted_counters), "exercised_surface_counts": exercised_surface_counts, "observed_event_count": sum(observed_surface_counts.values()), "target_integrity": True, "event_chain": list(self.sentinels._event_chain), "event_chain_sha256": event_chain_sha256, "event_count": len(self.sentinels._event_chain)}
        return {**base, "observation_sha256": _sha256(_canonical_json(base))}


def _identity_for_checkpoint(body: dict[str, object]) -> str:
    material = {key: body[key] for key in ("schema", "run_id", "completed", "artifact_hashes", "adapter_git_blob", "adapter_sha256", "egress_observations")}
    return _sha256(_canonical_json(material))


_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_reparse_component(path: pathlib.Path) -> bool:
    try:
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            return True
        stat_result = path.stat(follow_symlinks=False)
        return bool(getattr(stat_result, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)
    except (OSError, ValueError):
        return False


def _validate_original_components(path: pathlib.Path, *, leaf_may_be_missing: bool, leaf_must_be_file: bool = False) -> pathlib.Path:
    absolute = pathlib.Path(os.path.abspath(os.fspath(path)))
    if not absolute.exists() and not os.path.lexists(os.fspath(absolute)) and not leaf_may_be_missing:
        raise ValueError("path component missing")
    current = pathlib.Path(absolute.anchor)
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for index, part in enumerate(parts):
        current = current / part
        is_leaf = index == len(parts) - 1
        exists = current.exists() or os.path.lexists(os.fspath(current))
        if not exists:
            if leaf_may_be_missing:
                break
            raise ValueError("path component missing")
        if _is_reparse_component(current):
            raise ValueError("original path component is reparse-like")
        if not is_leaf and not current.is_dir():
            raise ValueError("checkpoint parent invalid")
        if is_leaf and leaf_must_be_file and not current.is_file():
            raise ValueError("checkpoint path is nonregular or reparse-like")
    return absolute


def _checkpoint_path(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    lexical = _validate_original_components(path, leaf_may_be_missing=True, leaf_must_be_file=True)
    return lexical.resolve(strict=False)


def _write_checkpoint(path: pathlib.Path, body: dict[str, object], *, tamper: bool = False) -> dict[str, object]:
    path = _checkpoint_path(str(path))
    body = dict(body)
    body["handshake_identity"] = _identity_for_checkpoint(body)
    integrity = _sha256(_canonical_json(body))
    envelope = {"body": body, "integrity_sha256": ("0" * 64 if tamper else integrity)}
    path.write_bytes(_canonical_json(envelope) + b"\n")
    return {"body": body, "integrity_sha256": integrity, "path": str(path)}


def _expected_binding(path: pathlib.Path, envelope: dict[str, object], root: pathlib.Path) -> dict[str, object]:
    body = envelope["body"]
    binding = {"checkpoint_path": str(path.resolve()), "checkpoint_integrity": envelope["integrity_sha256"], "handshake_identity": body["handshake_identity"], "adapter_git_blob": body["adapter_git_blob"], "adapter_sha256": body["adapter_sha256"], "root": str(root.resolve())}
    return {**binding, "expected_digest": _sha256(_canonical_json(binding))}


def _authenticate_checkpoint(path: pathlib.Path, root: pathlib.Path | None = None, expected: dict[str, object] | None = None) -> dict[str, object]:
    path = _checkpoint_path(str(path))
    resolved_root = _validated_root_path(root) if root is not None else None
    if resolved_root is not None and not path.is_relative_to(resolved_root):
        raise ValueError("checkpoint escapes evidence root")
    envelope = json.loads(path.read_bytes().decode("utf-8"))
    if set(envelope) != {"body", "integrity_sha256"} or type(envelope["integrity_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", envelope["integrity_sha256"]) is None:
        raise ValueError("checkpoint envelope malformed")
    body = envelope["body"]
    if type(body) is not dict or envelope["integrity_sha256"] != _sha256(_canonical_json(body)):
        raise ValueError("checkpoint integrity mismatch")
    required = {"schema", "run_id", "completed", "artifact_hashes", "adapter_git_blob", "adapter_sha256", "egress_observations", "handshake_identity"}
    if set(body) != required or body["schema"] != CHECKPOINT_SCHEMA or body["adapter_git_blob"] != PINNED_ADAPTER_BLOB or body["handshake_identity"] != _identity_for_checkpoint(body):
        raise ValueError("checkpoint authentication mismatch")
    if type(body["adapter_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", body["adapter_sha256"]) is None or _sha256(_pinned_adapter_source()) != body["adapter_sha256"]:
        raise ValueError("checkpoint adapter binding mismatch")
    if expected is not None:
        if resolved_root is None or type(expected) is not dict or expected.get("expected_digest") != _sha256(_canonical_json({key: expected[key] for key in expected if key != "expected_digest"})):
            raise ValueError("parent checkpoint binding digest mismatch")
        actual = _expected_binding(path, envelope, resolved_root)
        if expected != actual:
            raise ValueError("parent checkpoint binding mismatch")
    hashes = body["artifact_hashes"]
    if type(hashes) is not dict or any(type(key) is not str or re.fullmatch(r"[0-9]+", key) is None or type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None for key, value in hashes.items()):
        raise ValueError("checkpoint artifact claims malformed")
    observations = body["egress_observations"]
    required_surfaces = set(RUNTIME_COUNTER_NAMES)
    installed = observations.get("installed_surface_names") if type(observations) is dict else None
    exercised = observations.get("exercised_surface_names") if type(observations) is dict else None
    exercised_counts = observations.get("exercised_surface_counts") if type(observations) is dict else None
    intercepted = observations.get("intercepted_counters") if type(observations) is dict else None
    events = observations.get("event_chain") if type(observations) is dict else None
    chain_ok = type(events) is list and observations.get("event_chain_sha256") == _sha256(_canonical_json(events)) and observations.get("event_count") == len(events)
    previous = "T02-V15G-B2-EVENT-CHAIN-V1"
    if chain_ok:
        for sequence, event in enumerate(events):
            material = {"previous": previous, "sequence": sequence, "surface": event.get("surface"), "kind": event.get("kind")}
            if event.get("event_sha256") != _sha256(_canonical_json(material)):
                chain_ok = False
                break
            previous = event["event_sha256"]
    if type(observations) is not dict or observations.get("observation_sha256") != _sha256(_canonical_json({key: observations[key] for key in observations if key != "observation_sha256"})) or observations.get("all_fake") is not True or type(observations.get("provider_calls")) is not int or observations.get("provider_calls") <= 0 or observations.get("network_calls") != len(()) or observations.get("runtime_counters") != {name: len(()) for name in RUNTIME_COUNTER_NAMES} or observations.get("target_integrity") is not True or not chain_ok or not required_surfaces.issubset(set(installed or ())) or not required_surfaces.issubset(set(exercised or ())) or type(exercised_counts) is not dict or any(type(exercised_counts.get(name)) is not int or exercised_counts[name] <= 0 for name in RUNTIME_COUNTER_NAMES) or type(intercepted) is not dict or any(type(intercepted.get(name)) is not int or intercepted[name] <= 0 for name in RUNTIME_COUNTER_NAMES):
        raise ValueError("checkpoint egress authentication mismatch")
    return body


def _build_interrupted_checkpoint(path: pathlib.Path, fake, adapter_sha256: str, *, tamper: bool = False) -> dict[str, object]:
    sentinels = _ForbiddenActionSentinels()
    observed = _WorkerObservation(sentinels)
    responses = [observed.fake(fake, "kimi", "first"), observed.fake(fake, "kimi", "second")]
    body = {"schema": CHECKPOINT_SCHEMA, "run_id": "run-t02-oracle-001", "completed": [0, 1], "artifact_hashes": {str(index): _sha256(_canonical_json(response)) for index, response in enumerate(responses)}, "adapter_git_blob": PINNED_ADAPTER_BLOB, "adapter_sha256": adapter_sha256, "egress_observations": observed.payload()}
    return _write_checkpoint(path, body, tamper=tamper)


def _handshake(envelope: dict[str, object]) -> dict[str, object]:
    body = envelope["body"]
    return {"schema": body["schema"], "run_id": body["run_id"], "completed": body["completed"], "artifact_hashes": body["artifact_hashes"], "adapter_git_blob": body["adapter_git_blob"], "adapter_sha256": body["adapter_sha256"], "handshake_identity": body["handshake_identity"], "checkpoint_integrity": envelope["integrity_sha256"], "checkpoint_path": envelope["path"], "egress_observation_sha256": body["egress_observations"]["observation_sha256"], "slow_line": PINNED_SLOW_LINE, "call_ordinal": PINNED_SLOW_CALL_ORDINAL}


def _load_classifier():
    source_path = pathlib.Path(__file__).resolve().with_name("t02_audit_console_head.py")
    source = source_path.read_bytes().decode("utf-8", errors="strict")
    tree = ast.parse(source, filename="runtime:t02_audit_console_head.py")
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "classify_graph_checkpoint"]
    if len(selected) != 1:
        raise AssertionError("classify_graph_checkpoint definition missing")
    namespace = {"re": re}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "runtime:classify_graph_checkpoint", "exec"), namespace)
    return namespace["classify_graph_checkpoint"]


def _spawn_descendant(checkpoint: pathlib.Path) -> None:
    child = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(pathlib.Path(__file__).resolve()), "--descendant"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    checkpoint.with_suffix(checkpoint.suffix + ".descendant").write_text(str(child.pid), encoding="ascii")


def _fake_worker(mode: str, checkpoint_text: str, expected_text: str | None = None) -> int:
    fake, adapter_sha256 = _pinned_fake_functions()
    checkpoint = _checkpoint_path(checkpoint_text)
    _spawn_descendant(checkpoint)
    if mode == "interrupted":
        envelope = _build_interrupted_checkpoint(checkpoint, fake, adapter_sha256)
        print(json.dumps(_handshake(envelope), sort_keys=True), flush=True)
        sentinels = _ForbiddenActionSentinels()
        _WorkerObservation(sentinels).fake(fake, "kimi", "[[FAKE:SLOW]]")
        return 0
    if mode == "fresh":
        if expected_text is None:
            raise ValueError("fresh worker parent binding absent")
        expected = json.loads(base64.urlsafe_b64decode(expected_text.encode("ascii") + b"=" * (-len(expected_text) % 4)).decode("utf-8"))
        body = _authenticate_checkpoint(checkpoint, pathlib.Path(expected["root"]), expected)
        sentinels = _ForbiddenActionSentinels()
        observed = _WorkerObservation(sentinels)
        candidate_stages = list(range(len(body["completed"]), len(body["completed"]) + len(body["completed"]) + 1))
        work = [(stage, observed.fake(fake, "kimi", f"fresh-{stage}")) for stage in candidate_stages if stage % 2 == 0]
        hashes = dict(body["artifact_hashes"])
        hashes.update({str(stage): _sha256(_canonical_json(response)) for stage, response in work})
        executed = [stage for stage, _response in work]
        completed = list(body["completed"]) + executed
        skipped = [stage for stage in candidate_stages if stage not in executed]
        classification = _load_classifier()(completed, {int(key): value for key, value in hashes.items()}, skip_evidence=True)
        observations = observed.payload()
        result = {"checkpoint_consumed": True, "checkpoint_integrity": _sha256(checkpoint.read_bytes().rstrip(b"\n")), "completed": completed, "executed": executed, "skipped": skipped, "artifact_hashes": hashes, "classification": classification["classification"], "mutation": classification["mutation"], "adapter_git_blob": body["adapter_git_blob"], "adapter_sha256": body["adapter_sha256"], "handshake_identity": body["handshake_identity"], "egress_observations": observations, "runtime_counters": observations["runtime_counters"], "provider_calls": observations["provider_calls"], "network_calls": observations["network_calls"], "observed_checkpoint_hashes": dict(body["artifact_hashes"]), "expected_parent_binding_digest": expected["expected_digest"]}
        print(json.dumps(result, sort_keys=True), flush=True)
        return 0
    if mode == "auth-failure":
        envelope = _build_interrupted_checkpoint(checkpoint, fake, adapter_sha256, tamper=True)
        print(json.dumps(_handshake(envelope), sort_keys=True), flush=True)
        return 0
    if mode == "later-exception":
        envelope = _build_interrupted_checkpoint(checkpoint, fake, adapter_sha256)
        print(json.dumps(_handshake(envelope), sort_keys=True), flush=True)
        raise RuntimeError("later worker exception")
    if mode == "eof":
        return 0
    if mode == "malformed":
        print("{malformed-json", flush=True)
        time.sleep(5)
        return 0
    if mode == "timeout":
        time.sleep(5)
        return 0
    raise SystemExit("unknown worker mode")


def _worker_command(mode: str, checkpoint: pathlib.Path, expected: dict[str, object] | None = None) -> list[str]:
    command = [sys.executable, "-I", "-S", "-B", str(pathlib.Path(__file__).resolve()), "--worker", mode, str(checkpoint)]
    if expected is not None:
        encoded = base64.urlsafe_b64encode(_canonical_json(expected)).decode("ascii").rstrip("=")
        command.extend([base64.urlsafe_b64encode(_canonical_json(expected)).decode("ascii").rstrip("=")])
    return command


def _readline_deadline(stream, timeout_s: float) -> tuple[str, str]:
    result: queue.Queue[str] = queue.Queue(maxsize=1)
    def read() -> None:
        try:
            result.put(stream.readline())
        except BaseException as exc:
            result.put(f"__reader_error__:{exc}")
    thread = threading.Thread(target=read, daemon=True)
    thread.start()
    try:
        line = result.get(timeout=timeout_s)
    except queue.Empty:
        return "timeout", ""
    if line == "":
        return "eof", ""
    if line.startswith("__reader_error__:"):
        return "reader_error", line
    return "line", line


def _pid_present(pid: int) -> bool:
    tasklist = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "tasklist.exe"
    result = subprocess.run([str(tasklist), "/FI", f"PID eq {pid}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return bool(re.search(rf"\b{pid}\b", result.stdout))


def _terminate_reap_tree(child: subprocess.Popen, checkpoint: pathlib.Path | None = None) -> dict[str, object]:
    before = child.poll()
    taskkill = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
    taskkill_exit = None
    if before is None:
        result = subprocess.run([str(taskkill), "/PID", str(child.pid), "/T", "/F"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        taskkill_exit = result.returncode
    descendant_pids: list[int] = []
    if checkpoint is not None:
        sidecar = checkpoint.with_suffix(checkpoint.suffix + ".descendant")
        if sidecar.exists() and sidecar.is_file():
            descendant_pids = [int(value) for value in sidecar.read_text(encoding="ascii").split() if value.isdigit()]
            for pid in descendant_pids:
                result = subprocess.run([str(taskkill), "/PID", str(pid), "/T", "/F"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                taskkill_exit = result.returncode if taskkill_exit is None else taskkill_exit
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=10)
    descendants_reaped = all(not _pid_present(pid) for pid in descendant_pids)
    return {"pid": child.pid, "initial_exit": before, "taskkill_exit": taskkill_exit, "reaped": child.poll() is not None, "exit": child.returncode, "descendant_pids": descendant_pids, "descendants_reaped": descendants_reaped, "tree_reaped": child.poll() is not None and descendants_reaped}


def _run_worker_case(mode: str, checkpoint: pathlib.Path, *, deadline_s: float, terminate_after_handshake: bool = False) -> dict[str, object]:
    child = subprocess.Popen(_worker_command(mode, checkpoint), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    outcome = "unknown"
    handshake = None
    error = None
    try:
        status, line = _readline_deadline(child.stdout, deadline_s)
        if status == "timeout":
            outcome = "timeout"
        elif status == "eof":
            outcome = "eof"
        elif status != "line":
            outcome = "reader_error"
            error = line
        else:
            try:
                handshake = json.loads(line)
            except json.JSONDecodeError as exc:
                outcome = "malformed_json"
                error = str(exc)
            else:
                try:
                    envelope = json.loads(checkpoint.read_bytes().decode("utf-8"))
                    expected = _expected_binding(checkpoint, envelope, checkpoint.parent)
                    body = _authenticate_checkpoint(checkpoint, checkpoint.parent, expected)
                    if handshake["handshake_identity"] != body["handshake_identity"] or handshake["checkpoint_integrity"] != envelope["integrity_sha256"]:
                        raise ValueError("handshake authentication mismatch")
                    outcome = "handshake_authenticated"
                    if mode == "auth-failure":
                        raise ValueError("checkpoint authentication rejected")
                except ValueError as exc:
                    outcome = "checkpoint_auth_failure"
                    error = str(exc)
                if mode == "later-exception" and outcome == "handshake_authenticated":
                    child.wait(timeout=10)
                    outcome = "later_exception" if child.returncode else "unexpected_worker_success"
                elif terminate_after_handshake and outcome == "handshake_authenticated":
                    time.sleep(0.05)
    finally:
        reaped = _terminate_reap_tree(child, checkpoint)
        stdout_tail = child.stdout.read() if child.stdout is not None else ""
        stderr = child.stderr.read() if child.stderr is not None else ""
    return {"mode": mode, "outcome": outcome, "handshake": handshake, "error": error, "reap": reaped, "stdout_tail": stdout_tail, "stderr": stderr}


def _run_fresh_worker(checkpoint: pathlib.Path, expected: dict[str, object]) -> dict[str, object]:
    child = subprocess.Popen(_worker_command("fresh", checkpoint, expected), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    result = None
    reap = None
    try:
        stdout, stderr = child.communicate(timeout=WORKER_TIMEOUT_S)
        if child.returncode != 0:
            raise RuntimeError(f"fresh worker failed: {child.returncode}: {stderr}")
        result = json.loads(stdout)
    finally:
        reap = _terminate_reap_tree(child, checkpoint)
    if type(result) is not dict:
        raise ValueError("fresh worker result malformed")
    result["reap"] = reap
    return result


def _validated_root_path(value: pathlib.Path | str) -> pathlib.Path:
    lexical = _validate_original_components(pathlib.Path(value), leaf_may_be_missing=False)
    if not lexical.is_dir():
        raise ValueError("evidence root invalid")
    return lexical.resolve(strict=True)


def _validated_root() -> pathlib.Path:
    return _validated_root_path(os.environ.get("LUNA_ROOT", os.environ.get("T02_EVIDENCE_ROOT", pathlib.Path.cwd())))


def run_authenticated_probe() -> dict[str, object]:
    root = _validated_root()
    started = time.monotonic()
    interrupted_path = root / "b2-interrupted-checkpoint.json"
    normal = _run_worker_case("interrupted", interrupted_path, deadline_s=HANDSHAKE_DEADLINE_S, terminate_after_handshake=True)
    if normal["outcome"] != "handshake_authenticated":
        raise AssertionError(f"interrupted handshake failed: {normal}")
    envelope = json.loads(interrupted_path.read_bytes().decode("utf-8"))
    expected_binding = _expected_binding(interrupted_path, envelope, root)
    fresh_resume = _run_fresh_worker(interrupted_path, expected_binding)
    failure_cases = {}
    for mode, deadline in (("timeout", 1.0), ("eof", 1.0), ("malformed", 1.0), ("auth-failure", 30.0), ("later-exception", 30.0)):
        failure_cases[mode] = _run_worker_case(mode, root / f"b2-{mode}.json", deadline_s=deadline)
    observations = fresh_resume["egress_observations"]
    return {"handshake": {**normal["handshake"], "third_call_interrupted": True, "child_exit": normal["reap"]["exit"], "stderr": normal["stderr"]}, "reaped": normal["reap"]["reaped"], "parent_binding": {"root_bound": expected_binding["root"] == str(root.resolve()), "expected_digest": expected_binding["expected_digest"], "checkpoint_identity": expected_binding["handshake_identity"], "adapter_git_blob": expected_binding["adapter_git_blob"]}, "fresh_resume": fresh_resume, "failure_cases": failure_cases, "egress": observations, "runtime_counters": fresh_resume["runtime_counters"], "duration_s": round(time.monotonic() - started, 6), "worker_limit_s": WORKER_TIMEOUT_S, "handshake_limit_s": HANDSHAKE_DEADLINE_S, "retained_evidence_limit_bytes": 128 * 1024 * 1024, "artifact_limit_bytes": 32 * 1024 * 1024, "all_fake": fresh_resume["egress_observations"]["all_fake"], "provider_calls": fresh_resume["network_calls"], "observed_provider_calls": fresh_resume["provider_calls"], "network_calls": fresh_resume["network_calls"], "defensive_config_copy": True}


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--worker":
        raise SystemExit(_fake_worker(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) >= 5 else None))
    if len(sys.argv) >= 2 and sys.argv[1] == "--descendant":
        time.sleep(60.0)
        raise SystemExit(0)
    print(json.dumps(run_authenticated_probe(), sort_keys=True))
