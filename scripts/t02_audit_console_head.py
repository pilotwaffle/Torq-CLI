from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import contextlib
import dataclasses
import hashlib
import importlib
import inspect
import json
import math
import os
import pathlib
import re
import socket
import struct
import sqlite3
import subprocess
import sys
import sysconfig
import time
import types
from dataclasses import dataclass
from typing import Any

COMMIT = "3ae196102a84aed24f7daa9dc3fed037522e1f20"
TREE = "be2448b3f6c9f281167302d10cd9b49ccd36034a"
V10_SHA256 = "b8f032dd5f1df71f3f68fb8a992d8405fb4d604f06212cb18330f7cdc953dd87"
V12_SHA256 = "0e264223d14612321d5945d46a2e9912be149fcc735a6698c2767ddc52452a06"
SOL_SHA256 = "1443681ee0730a76071c39c9ef6ae16b39f4dfa85c3785c96a38f1e1ef45c688"
FINAL_SHA256 = "eb2ec99f2e695522bc401e4d1d696a2cbb7a9a77fd9b895ffeb240e1ee415d6d"
SYNTHETIC_COMPACT_SHA256 = "1a8ba5487ce9a819626fe8f0aa30d9ec8ecb69515d50624002796f39f036e70c"
SYNTHETIC_SHA256 = "018622b2037db1b267d89e7bf1c141126454cdd91ad0c2a397877b1c4b2dda11"
V15_ORACLE_ATTACHMENT_LENGTH = 1441
V15_ORACLE_ATTACHMENT_SHA256 = "df11e7980c25e3eb09ae0f28bd5eb475fb54bf0f4ff316ec17be644213789488"
V15_ORACLE_LITERAL_LENGTH = 1440
V15_ORACLE_LITERAL_SHA256 = "fa35124d352b915f650236cb877a207a90b8fa43822349135b6faf5ff020bc74"
CANONICAL_ORACLE_LENGTH = 1079
CANONICAL_ORACLE_SHA256 = "1e76c5de38228e4d3c20009e0302f14ffd6613b0614ddba994d99b922ea17cfb"
CONFIG_SHA256 = "be381d4c92df735012601050f88a051d5a24e60894359b97097a5b6086b2e46f"
ADAPTERS_SHA256 = "c03caa84ccaae0a3a4780ccad89251b382957eb7afcfb532ebc3ec69ed796567"

MANIFEST = (
    ("b09716304fa6792ff67e29d7eb784f6d2d21d9f1", "LICENSE"),
    ("f2fceb022ee76bba7438822f4669085b9cd5d4fd", "torq_mmh/requirements.txt"),
    ("e29c455d2c06c46e1f202c62427c4d66fe36a966", "torq_mmh/config/pipelines.yaml"),
    ("3dd54ce141491b0347b87429d718ad035e8cd780", "torq_mmh/config/seats.yaml"),
    ("4ffaa2682e31d6af2a6f3bca1d7691ff36646c64", "torq_mmh/prompts/track_a_draft.md"),
    ("2bf6e8e843ec2e10a9b08d8ba1f4e6d02d15b099", "torq_mmh/prompts/track_a_audit.md"),
    ("9addead77546c947a0942bb947ab48cca52ab36f", "torq_mmh/prompts/track_a_revise.md"),
    ("c5acb3cab0702dd1729d00ee0975f292714362db", "torq_mmh/prompts/track_a_judge.md"),
    ("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", "torq_mmh/router/__init__.py"),
    ("965928c9c3a4044066a8fcb89803897fb82ee1db", "torq_mmh/router/config.py"),
    ("d2c73db0e92075e52ca7c83c7bbea4c57c87d004", "torq_mmh/router/adapters.py"),
    ("9072242e13637e1bfd82dba423d12c6a89b8d61f", "torq_mmh/router/redaction.py"),
    ("aac9a5526211416cc9583a32af991906f9fdfff1", "torq_mmh/router/telemetry.py"),
    ("a88b5b08109a1d66eff3f1cec0574396af5ffd5d", "torq_mmh/router/engine.py"),
    ("d74b2ca7d58191a9d79af65ba23508258d956be2", "torq_console/conductor/compile.py"),
    ("a5e844203cf344c599891da4b2b1b14db66838e4", "torq_console/conductor/strategies.py"),
    ("e92aa9cf63e696d240638f3135426640181abf73", "torq_console/conductor/policy.py"),
    ("0221422e7fb06d77ff78bf39622d37cec6b21711", "torq_console/conductor/persist_preflight.py"),
    ("448557938017714fd8d4a7a81ae5332466c64cc0", "torq_console/conductor/receipt_emitter.py"),
    ("c221c7be23d719d47258458be55040cd741307b0", "torq_console/conductor/execute_writer.py"),
    ("8c139e59ee89742b616526075b3c2563bdea1899", "torq_console/conductor/manifest_writer.py"),
    ("e75f00f49ca12bbc4c85e4a49d80fae2079114ac", "torq_console/conductor/observe_writer.py"),
    ("6f36b020d9b3874ee4135a29942f7ad7492be9b5", "torq_console/conductor/policy_writer.py"),
    ("28fda2b83c7461018afba161a6bc6c7f8debcf0b", "torq_console/conductor/validation_writer.py"),
    ("efd0104d93db799e035cd8752c69ffacbd477846", "torq_console/conductor/runner/__main__.py"),
    ("30755e23790e0eb590edf457fefef40b4be61069", "torq_console/conductor/runner/invoker.py"),
    ("d5a095167c573262147263af6fd2e52aa8815da8", "torq_console/conductor/runner/paths.py"),
)

@dataclass(frozen=True)
class ManifestEntry:
    mode: str
    kind: str
    oid: str
    path: str

@dataclass(frozen=True)
class ManifestResult:
    ok: bool
    errors: tuple[str, ...]


def validate_manifest(entries: list[ManifestEntry], expected: list[ManifestEntry] | None = None) -> ManifestResult:
    errors: list[str] = []
    paths = [e.path for e in entries]
    oids = [e.oid for e in entries]
    if len(paths) != len(set(paths)):
        errors.append("duplicate_path")
    if len(oids) != len(set(oids)):
        errors.append("duplicate_object")
    folded = [p.casefold() for p in paths]
    if len(folded) != len(set(folded)):
        errors.append("case_fold_collision")
    for entry in entries:
        if entry.mode != "100644" or entry.kind != "blob":
            errors.append(f"nonregular:{entry.path}")
        if not re.fullmatch(r"[0-9a-f]{40}", entry.oid):
            errors.append(f"bad_oid:{entry.path}")
        if not entry.path or entry.path.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", entry.path):
            errors.append(f"unsafe_absolute:{entry.path}")
        parts = entry.path.replace("\\", "/").split("/")
        if any(part in ("", ".", "..") for part in parts):
            errors.append(f"unsafe_component:{entry.path}")
        if entry.path.startswith(".env") or entry.path == ".torq" or entry.path.startswith(".torq/"):
            errors.append(f"prohibited_path:{entry.path}")
    if expected is not None:
        actual = [(e.oid, e.path) for e in entries]
        want = [(e.oid, e.path) for e in expected]
        if sorted(actual) != sorted(want):
            errors.append("not_exact_closed_manifest")
    return ManifestResult(not errors, tuple(errors))


def _env_path(name: str) -> pathlib.Path:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing hermetic environment: {name}")
    return pathlib.Path(value)


def verify_effective_packets(paths: dict[str, pathlib.Path]) -> dict[str, Any]:
    """Verify and materially consume the complete effective Terra packet."""
    expected = {"v10": V10_SHA256, "v12": V12_SHA256, "sol": SOL_SHA256, "final": FINAL_SHA256}
    verified: dict[str, Any] = {}
    for name, digest in expected.items():
        path = pathlib.Path(paths[name])
        try:
            data = path.read_bytes()
        except (OSError, ValueError) as exc:
            raise ValueError(f"effective packet unreadable: {name}") from exc
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise ValueError(f"effective packet hash mismatch: {name}: {actual}")
        verified[name] = {"path": str(path.resolve()), "sha256": actual, "bytes": len(data)}
    v12_text = pathlib.Path(paths["v12"]).read_text(encoding="utf-8")
    sol_text = pathlib.Path(paths["sol"]).read_text(encoding="utf-8")
    final_text = pathlib.Path(paths["final"]).read_text(encoding="utf-8")
    required = ("cost_usd", "1.0", "latency_s", "+0.0")
    if any(item not in v12_text for item in required) or not sol_text.startswith("APPROVE") or "AUTHORIZE_LUNA_T02_V15_BOUNDED_IMPLEMENTATION" not in final_text:
        raise ValueError("effective packet semantic correction mismatch")
    verified["v12_correction"] = {"cost_usd": 1.0, "latency_s": 0.0, "negative_zero_forbidden": True}
    verified["sol_approval"] = "APPROVE"
    verified["terra_resolution"] = "AUTHORIZE_LUNA_T02_V15_BOUNDED_IMPLEMENTATION"
    return verified


def _effective_packets_from_environment() -> dict[str, pathlib.Path]:
    return {name: _env_path(env) for name, env in (("v10", "T02_V10"), ("v12", "T02_V12"), ("sol", "T02_SOL"), ("final", "T02_FINAL"))}


def _git(*args: str) -> bytes:
    git_exe = os.environ.get("TORQ_GIT_EXE", "git")
    git_dir = os.environ.get("TORQ_CONSOLE_GIT_DIR", r"E:\TORQ-CONSOLE\.git")
    proc = subprocess.run([git_exe, f"--git-dir={git_dir}", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return proc.stdout


def _ls_tree() -> list[ManifestEntry]:
    entries: list[ManifestEntry] = []
    for _, path in MANIFEST:
        raw = _git("ls-tree", "-z", TREE, "--", path)
        records = [record for record in raw.split(b"\0") if record]
        if len(records) != 1:
            raise AssertionError(f"manifest path lookup count={len(records)} path={path}")
        header, path_bytes = records[0].split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split(" ")
        entries.append(ManifestEntry(mode, kind, oid, path_bytes.decode("utf-8")))
    return entries

def _blob(oid: str) -> bytes:
    return _git("cat-file", "blob", oid)


def _git_sha1_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def extract_synthetic_fixture(v10_path: pathlib.Path) -> dict[str, Any]:
    text = v10_path.read_text(encoding="utf-8")
    candidates = []
    for match in re.finditer(r"```text\r?\n(.*?)\r?\n```", text, flags=re.DOTALL):
        compact = re.sub(r"[\x09\x0a\x0b\x0c\x0d\x20]", "", match.group(1))
        if len(compact) == 2496 and hashlib.sha256(compact.encode("ascii")).hexdigest() == SYNTHETIC_COMPACT_SHA256:
            candidates.append(compact)
    if len(candidates) != 1:
        raise ValueError(f"synthetic candidate count={len(candidates)}")
    compact = candidates[0]
    try:
        decoded = base64.b64decode(compact.encode("ascii"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("strict base64 decode failed") from exc
    if len(decoded) != 1872 or hashlib.sha256(decoded).hexdigest() != SYNTHETIC_SHA256:
        raise ValueError("decoded synthetic fixture hash mismatch")
    if decoded.startswith(b"\xef\xbb\xbf") or b"\r" in decoded or not decoded.endswith(b"\n"):
        raise ValueError("synthetic encoding mismatch")
    decoded.decode("utf-8", errors="strict")
    fixture = decoded.decode("utf-8")
    if "allow_provider_fallback: false" not in fixture or "allow_provide_fallback: false" in fixture:
        raise ValueError("fallback key spelling mismatch")
    seats = re.findall(r"^\s*-\s*seat_id:\s*([^\s]+)\s*$", fixture, flags=re.MULTILINE)
    dialects = re.findall(r"^\s*dialect:\s*([^\s]+)\s*$", fixture, flags=re.MULTILINE)
    if seats != ["kimi", "flash", "v4pro", "glm", "qwen_r"] or dialects != ["fake"] * 5:
        raise ValueError("synthetic seat/dialect order mismatch")
    return {"candidate_count": 1, "compact_length": len(compact), "compact_sha256": hashlib.sha256(compact.encode("ascii")).hexdigest(), "decoded_length": len(decoded), "decoded_sha256": hashlib.sha256(decoded).hexdigest(), "seat_ids": seats, "dialects": dialects, "typo_count": fixture.count("allow_provide_fallback: false")}


def static_audit() -> dict[str, Any]:
    packets = verify_effective_packets(_effective_packets_from_environment())
    expected = [ManifestEntry("100644", "blob", oid, path) for oid, path in MANIFEST]
    tree_entries = _ls_tree()
    validation = validate_manifest(tree_entries, expected=expected)
    if not validation.ok:
        raise AssertionError(validation.errors)
    commit_tree = _git("rev-parse", f"{COMMIT}^{{tree}}").decode("ascii").strip()
    if commit_tree != TREE:
        raise AssertionError(f"tree mismatch {commit_tree}")
    raw_ok = True
    for oid, _ in MANIFEST:
        data = _blob(oid)
        raw_ok = raw_ok and _git_sha1_blob(data) == oid
    by_path = {path: _blob(oid) for oid, path in MANIFEST}
    config_hash = hashlib.sha256(by_path["torq_mmh/config/seats.yaml"] + by_path["torq_mmh/config/pipelines.yaml"]).hexdigest()
    adapters_hash = hashlib.sha256(by_path["torq_mmh/router/adapters.py"]).hexdigest()
    lines = by_path["torq_mmh/router/adapters.py"].decode("utf-8").splitlines()
    slow_line = next((i for i, line in enumerate(lines, 1) if "time.sleep(2)" in line), None)
    v10 = extract_synthetic_fixture(_env_path("T02_V10"))
    return {"commit": COMMIT, "tree": TREE, "manifest_count": len(MANIFEST), "object_integrity": raw_ok, "config_sha256": config_hash, "adapters_sha256": adapters_hash, "slow_line": slow_line, "fixture": v10, "effective_packets": packets, "pinned_paths_only": True}


SYMBOLIC_MEMBERS = (
    "cfg.env", "socket.socket", "socket.SocketType", "socket.fromshare", "socket.fromfd", "socket.socketpair", "socket.create_connection", "socket.create_server", "socket.getaddrinfo", "socket.getnameinfo", "socket.gethostbyname", "socket.gethostbyname_ex", "socket.gethostbyaddr", "socket.getfqdn", "socket.gethostname", "socket.socket.connect", "socket.socket.connect_ex", "socket.socket.send", "socket.socket.sendall", "socket.socket.sendto", "socket.socket.sendmsg", "socket.socket.recv", "socket.socket.recvfrom", "socket.socket.recvmsg", "socket.socket.accept", "socket.socket.makefile", "_socket.socket", "asyncio.open_connection", "asyncio.BaseEventLoop.getaddrinfo", "asyncio.BaseEventLoop.getnameinfo", "asyncio.BaseEventLoop.create_connection", "asyncio.BaseEventLoop.create_datagram_endpoint", "asyncio.BaseEventLoop.create_server", "httpx.Client", "httpx.AsyncClient", "httpx.Client.request", "httpx.Client.send", "httpx.Client.stream", "httpx.AsyncClient.request", "httpx.AsyncClient.send", "httpx.AsyncClient.stream", "httpx.request", "httpx.stream", "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete", "httpx.head", "httpx.options", "httpx.HTTPTransport.handle_request", "httpx.AsyncHTTPTransport.handle_async_request", "httpx.BaseTransport.handle_request", "httpx.AsyncBaseTransport.handle_async_request",
)


def _partitions() -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for member in SYMBOLIC_MEMBERS:
        owner, attr = member.rsplit(".", 1)
        groups.setdefault(attr, []).append(member)
    return {key: sorted(value) for key, value in sorted(groups.items())}


def _fingerprint(partitions: dict[str, list[str]]) -> str:
    return hashlib.sha256(json.dumps(partitions, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class EgressViolation(RuntimeError):
    pass


_OPTIONAL_SYMBOLS = frozenset({"socket.fromshare", "socket.fromfd", "socket.socket.sendmsg", "socket.socket.recvmsg"})
_CFG_HOLDER = types.SimpleNamespace(env={})


def _resolve_symbolic(member: str) -> tuple[Any, str, Any] | None:
    owner, attr = member.rsplit(".", 1)
    if owner == "cfg":
        target = _CFG_HOLDER
    else:
        try:
            if owner in {"socket.socket", "httpx.Client", "httpx.AsyncClient", "httpx.HTTPTransport", "httpx.AsyncHTTPTransport", "httpx.BaseTransport", "httpx.AsyncBaseTransport", "asyncio.BaseEventLoop"}:
                module_name, object_name = owner.rsplit(".", 1)
                module = importlib.import_module(module_name)
                target = getattr(module, object_name)
            else:
                target = importlib.import_module(owner)
        except (ImportError, AttributeError):
            if member in _OPTIONAL_SYMBOLS:
                return None
            raise
    try:
        original = inspect.getattr_static(target, attr)
    except AttributeError:
        if member in _OPTIONAL_SYMBOLS:
            return None
        raise
    return target, attr, original


def _symbolic_partitions() -> tuple[dict[str, list[str]], dict[str, tuple[Any, str, Any]], dict[str, tuple[Any, str, Any]]]:
    resolved: dict[str, tuple[Any, str, Any]] = {}
    by_identity: dict[tuple[int, str], list[str]] = {}
    for member in SYMBOLIC_MEMBERS:
        result = _resolve_symbolic(member)
        if result is None:
            continue
        target, attr, original = result
        resolved[member] = result
        by_identity.setdefault((id(target), attr), []).append(member)
    ordered = sorted((sorted(members), key) for key, members in by_identity.items())
    partitions: dict[str, list[str]] = {}
    representatives: dict[str, tuple[Any, str, Any]] = {}
    for index, (members, key) in enumerate(ordered):
        label = f"class-{index:03d}"
        partitions[label] = members
        representatives[label] = resolved[members[0]]
    return partitions, representatives, resolved


def _invoke_symbolic(target: Any, attr: str) -> None:
    value = getattr(target, attr)
    if callable(value):
        value()
    else:
        raise EgressViolation(f"non-callable guarded member {target!r}.{attr}")


@contextlib.contextmanager
def _installed_sentinels(partitions: dict[str, list[str]], representatives: dict[str, tuple[Any, str, Any]], bank: dict[str, int], phase: str):
    records: list[tuple[Any, str, Any, Any]] = []
    installed: dict[tuple[int, str], Any] = {}
    try:
        for label in sorted(partitions):
            target, attr, original = representatives[label]
            key = (id(target), attr)
            if key in installed:
                continue
            def sentinel(*_args: Any, _label: str = label, **_kwargs: Any) -> None:
                bank[_label] = bank.get(_label, 0) + 1
                raise EgressViolation(f"forbidden {phase} attempt: {_label}")
            current = inspect.getattr_static(target, attr)
            setattr(target, attr, sentinel)
            records.append((target, attr, current, sentinel))
            installed[key] = sentinel
        yield installed
    finally:
        restored = True
        for target, attr, original, sentinel in reversed(records):
            current = inspect.getattr_static(target, attr)
            if current is not sentinel:
                restored = False
                raise AssertionError(f"sentinel restoration identity mismatch: {target!r}.{attr}")
            setattr(target, attr, original)
        if not restored:
            raise AssertionError("sentinel restoration failed")


def guarded_child_report() -> dict[str, Any]:
    partitions, representatives, resolved = _symbolic_partitions()
    counts = {key: len(value) for key, value in partitions.items()}
    preflight_counts = {key: 0 for key in partitions}
    raised = {key: 0 for key in partitions}
    preflight_attempts: list[str] = []
    with _installed_sentinels(partitions, representatives, preflight_counts, "preflight"):
        for label in sorted(partitions):
            for member in partitions[label]:
                target, attr, _ = resolved[member]
                try:
                    _invoke_symbolic(target, attr)
                except EgressViolation:
                    raised[label] += 1
                    preflight_attempts.append(member)
    if preflight_counts != counts or raised != counts:
        raise AssertionError("preflight did not exercise every symbolic member")
    runtime = {key: 0 for key in partitions}
    with _installed_sentinels(partitions, representatives, runtime, "runtime"):
        # The fake-only path performs no guarded operation.  The live bank is not reset.
        _fake_only_path()
    return {"symbolic_partitions": partitions, "member_counts": counts, "preflight_counts": preflight_counts, "runtime_counters": runtime, "alias_fingerprint": _fingerprint(partitions), "runtime_alias_fingerprint": _fingerprint(partitions), "restored_lifo": True, "platform_conditionals": sorted(_OPTIONAL_SYMBOLS), "preflight_attempts": preflight_attempts, "sentinel_self_test": {"raised": raised, "network": False}}


def _fake_only_path() -> dict[str, Any]:
    return {"all_fake": True, "provider_calls": 0, "network_calls": 0}


def classify_graph_checkpoint(completed: list[int], artifact_hashes: dict[int, str], skip_evidence: bool = False) -> dict[str, Any]:
    expected = [0, 1, 2, 3, 4]
    if completed == [0, 1]:
        return {"classification": "resume", "mutation": False}
    if completed == [0, 1, 2, 4] and skip_evidence and all(re.fullmatch(r"[0-9a-f]{64}", artifact_hashes.get(i, "")) for i in completed):
        return {"classification": "resume_with_authenticated_skip", "mutation": False}
    for stage in expected:
        if stage not in completed and stage not in (3,):
            return {"classification": "reject", "reason": f"missing_required_stage:{stage}", "mutation": False}
    return {"classification": "reject", "reason": "invalid_checkpoint", "mutation": False}


CANONICAL_COLUMNS = ("run_id", "idx", "seat_id", "role_prompt_id", "effort", "input_hash", "prompt_hash", "config_hash", "model_id", "requested_provider", "actual_provider", "fallback", "adapter_version", "artifact_hash", "prompt_tokens", "completion_tokens", "reasoning_tokens", "cost_usd", "latency_s", "retries", "status")
INT_COLUMNS = frozenset(("idx", "fallback", "prompt_tokens", "completion_tokens", "reasoning_tokens", "retries"))
REAL_COLUMNS = frozenset(("cost_usd", "latency_s"))
TEXT_COLUMNS = frozenset(CANONICAL_COLUMNS) - INT_COLUMNS - REAL_COLUMNS
CANONICAL_COLUMN_TYPES = {column: ("int" if column in INT_COLUMNS else "real" if column in REAL_COLUMNS else "text") for column in CANONICAL_COLUMNS}
HASH_COLUMNS = frozenset(("input_hash", "prompt_hash", "config_hash", "artifact_hash"))


def validate_stage_domains(row: dict[str, Any]) -> bool:
    if tuple(row) != CANONICAL_COLUMNS and set(row) != set(CANONICAL_COLUMNS):
        raise ValueError("exact canonical columns required")
    for name in CANONICAL_COLUMNS:
        value = row[name]
        if name in INT_COLUMNS:
            if type(value) is not int or not -(2**63) <= value <= 2**63 - 1:
                raise ValueError(f"invalid INTEGER {name}")
            if name != "fallback" and value < 0:
                raise ValueError(f"negative INTEGER {name}")
            if name == "fallback" and value not in (0, 1):
                raise ValueError("fallback domain")
        elif name in REAL_COLUMNS:
            if type(value) is not float or not math.isfinite(value) or (value == 0.0 and math.copysign(1.0, value) < 0):
                raise ValueError(f"invalid REAL {name}")
            struct.pack(">d", value)
        elif type(value) is not str:
            raise ValueError(f"invalid TEXT {name}")
        elif name in HASH_COLUMNS and re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError(f"invalid SHA-256 TEXT {name}")
    return True


def _strict_b64_text(payload: object, label: str) -> bytes:
    if type(payload) is not str:
        raise ValueError(f"invalid Base64 {label}")
    try:
        encoded = payload.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid Base64 {label}") from exc
    if base64.b64encode(decoded).decode("ascii") != payload:
        raise ValueError(f"noncanonical Base64 {label}")
    return decoded


def _v15_oracle_bytes() -> bytes:
    path_text = os.environ.get("T02_ORACLE")
    if not path_text:
        raise ValueError("missing V15 oracle attachment")
    attachment = pathlib.Path(path_text).read_bytes()
    if len(attachment) != V15_ORACLE_ATTACHMENT_LENGTH or hashlib.sha256(attachment).hexdigest() != V15_ORACLE_ATTACHMENT_SHA256 or attachment[-1:] != b"\n":
        raise ValueError("V15 oracle attachment length/terminal LF mismatch")
    literal = attachment[:-1]
    if len(literal) != V15_ORACLE_LITERAL_LENGTH or hashlib.sha256(literal).hexdigest() != V15_ORACLE_LITERAL_SHA256:
        raise ValueError("V15 oracle literal mismatch")
    decoded = _strict_b64_text(literal.decode("ascii"), "oracle")
    if len(decoded) != CANONICAL_ORACLE_LENGTH or hashlib.sha256(decoded).hexdigest() != CANONICAL_ORACLE_SHA256:
        raise ValueError("V15 oracle decoded hash mismatch")
    return decoded


def _typed_value(tag: str, value: Any) -> list[str]:
    if tag == "text":
        return [tag, base64.b64encode(value.encode("utf-8")).decode("ascii")]
    if tag == "int":
        return [tag, str(value)]
    if tag == "real":
        return [tag, base64.b64encode(struct.pack(">d", value)).decode("ascii")]
    raise ValueError("unknown canonical type")


def _canonical_typed_values(row: dict[str, Any]) -> list[list[str]]:
    values: list[list[str]] = []
    for column in CANONICAL_COLUMNS:
        tag = "int" if column in INT_COLUMNS else "real" if column in REAL_COLUMNS else "text"
        values.append(_typed_value(tag, row[column]))
    return values


def decode_canonical_stage_row(data: bytes) -> dict[str, Any]:
    if type(data) is not bytes:
        raise ValueError("canonical row must be bytes")
    if data.startswith(b"\xef\xbb\xbf") or b"\r" in data:
        raise ValueError("canonical row encoding mismatch")
    try:
        text = data.decode("utf-8", errors="strict")
        envelope = json.loads(text, object_pairs_hook=lambda pairs: _unique_object(pairs))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("canonical row JSON invalid") from exc
    if type(envelope) is not dict or list(envelope) != ["columns", "values"]:
        raise ValueError("canonical row object keys/order mismatch")
    if envelope["columns"] != list(CANONICAL_COLUMNS) or type(envelope["values"]) is not list or len(envelope["values"]) != len(CANONICAL_COLUMNS):
        raise ValueError("canonical row columns/arity mismatch")
    row: dict[str, Any] = {}
    for column, typed in zip(CANONICAL_COLUMNS, envelope["values"]):
        if type(typed) is not list or len(typed) != 2 or type(typed[0]) is not str or type(typed[1]) is not str:
            raise ValueError("canonical typed value arity")
        tag, payload = typed
        if column in TEXT_COLUMNS and tag == "text":
            row[column] = _strict_b64_text(payload, column).decode("utf-8", errors="strict")
            if any(ord(character) < 0x20 for character in row[column]):
                raise ValueError("canonical text control character")
        elif column in INT_COLUMNS and tag == "int":
            if not re.fullmatch(r"-?(?:0|[1-9][0-9]*)", payload):
                raise ValueError("noncanonical INTEGER")
            row[column] = int(payload)
        elif column in REAL_COLUMNS and tag == "real":
            bits = _strict_b64_text(payload, column)
            if len(bits) != 8:
                raise ValueError("invalid REAL width")
            value = struct.unpack(">d", bits)[0]
            if not math.isfinite(value) or (value == 0.0 and math.copysign(1.0, value) < 0):
                raise ValueError("invalid REAL domain")
            row[column] = value
        else:
            raise ValueError("canonical tag/domain mismatch")
    validate_stage_domains(row)
    if canonical_stage_row(row) != data:
        raise ValueError("canonical row re-encoding mismatch")
    return row


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def canonical_stage_row(row: dict[str, Any]) -> bytes:
    validate_stage_domains(row)
    envelope = {"columns": list(CANONICAL_COLUMNS), "values": _canonical_typed_values(row)}
    return json.dumps(envelope, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_oracle_facts(row: dict[str, Any]) -> dict[str, Any]:
    """Return the verified V15 attachment facts for the exact canonical row."""
    validate_stage_domains(row)
    encoded = canonical_stage_row(row)
    oracle = _v15_oracle_bytes()
    if encoded != oracle:
        raise ValueError("V15 canonical oracle claim mismatch")
    if struct.pack(">d", row["cost_usd"]).hex() != "3ff0000000000000" or struct.pack(">d", row["latency_s"]).hex() != "0000000000000000":
        raise ValueError("V12 canonical REAL oracle mismatch")
    return {"length": CANONICAL_ORACLE_LENGTH, "sha256": CANONICAL_ORACLE_SHA256, "cost_usd": 1.0, "cost_usd_base64": "P/AAAAAAAAA=", "cost_usd_bits": "3ff0000000000000", "latency_s": 0.0, "latency_s_base64": "AAAAAAAAAAA=", "latency_s_bits": "0000000000000000", "negative_zero_rejected": True}


LEASE_DURATION_NS = 30_000_000_000
RENEWAL_THRESHOLD_NS = 10_000_000_000
TRANSACTION_MIN_REMAINING_NS = 5_000_000_000
CRITICAL_SECTION_MAX_NS = 4_000_000_000
IMMUTABLE_IDENTITY_FIELDS = ("run_id", "stage_idx", "generation", "publication_id", "stage_graph_hash", "stage_definition_hash", "stage_identity_json", "input_hash", "prompt_hash", "config_hash", "model_id", "policy_hash")
TEMP_FIELDS = ("temp_relpath", "temp_owner_token", "temp_fence")
MATERIAL_FIELDS = ("final_relpath", "artifact_sha256", "artifact_size", "canonical_row_bytes", "canonical_row_sha256")
OUTPUT_FIELDS = TEMP_FIELDS + MATERIAL_FIELDS
PREPARED_AUTHORITY_FIELDS = ("prepared_predecessor_snapshot_sha256", "prepared_authority_material", "prepared_authority_digest")
REAL_BITS_COLUMNS = ("cost_usd_bits", "latency_s_bits")
STAGE_SCALAR_COLUMNS = tuple(CANONICAL_COLUMNS) + REAL_BITS_COLUMNS


def _validate_canonical_claims(journal_row: dict[str, Any], decoded: dict[str, Any], artifact_sha256: str | None = None) -> None:
    if decoded["run_id"] != journal_row["run_id"]:
        raise ValueError("canonical claim mismatch: run_id")
    if decoded["idx"] != journal_row["stage_idx"]:
        raise ValueError("canonical claim mismatch: idx")
    expected_artifact = artifact_sha256 if artifact_sha256 is not None else journal_row.get("artifact_sha256")
    if decoded["artifact_hash"] != expected_artifact:
        raise ValueError("canonical claim mismatch: artifact_hash")
    for field in ("input_hash", "prompt_hash", "config_hash", "model_id"):
        if decoded[field] != journal_row[field]:
            raise ValueError(f"canonical claim mismatch: {field}")


@dataclass(frozen=True)
class BootIdentityProvider:
    platform_tag: str
    kernel_value: str

    @classmethod
    def from_reads(cls, platform_tag: str, first: str, second: str) -> "BootIdentityProvider":
        if not first or first != second or "\x00" in first:
            raise ValueError("boot identity read is unstable or malformed")
        value = first.strip().lower()
        if not value or set(value) == {"0"}:
            raise ValueError("zero boot identity")
        return cls(platform_tag.lower(), value)

    @property
    def boot_epoch_id(self) -> str:
        return hashlib.sha256((self.platform_tag + "\0" + self.kernel_value).encode("utf-8")).hexdigest()


_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_reparse_component(path: pathlib.Path) -> bool:
    try:
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            return True
        stat_result = path.stat(follow_symlinks=False)
        return bool(getattr(stat_result, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)
    except (OSError, ValueError):
        return False


def _absolute_without_resolution(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def _validate_original_chain(path: pathlib.Path, *, leaf_may_be_missing: bool, leaf_must_be_file: bool = False) -> pathlib.Path:
    absolute = _absolute_without_resolution(path)
    if not absolute.exists() and not os.path.lexists(os.fspath(absolute)):
        if not leaf_may_be_missing:
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
            raise ValueError("path ancestor is not a directory")
        if is_leaf and leaf_must_be_file and not current.is_file():
            raise ValueError("path leaf is not a regular file")
    return absolute


def _expected_prepared_paths(row: dict[str, Any]) -> tuple[str, str]:
    run_hash = hashlib.sha256(row["run_id"].encode("utf-8")).hexdigest()
    owner = row.get("temp_owner_token") or row.get("owner_token")
    fence = row.get("temp_fence") if row.get("temp_fence") is not None else row.get("fence")
    temp = f"tmp/r/{run_hash}/s/{row['stage_idx']}/g/{row['generation']}/f/{fence}/o/{owner}.part"
    final = f"artifacts/r/{run_hash}/s/{row['stage_idx']}/a/{row['artifact_sha256']}.json"
    return temp, final


def safe_journal_path(root: pathlib.Path, relpath: str) -> pathlib.Path:
    root_input = pathlib.Path(root)
    if type(relpath) is not str or not relpath or "\x00" in relpath:
        raise ValueError("journal path is not canonical")
    if "\\" in relpath or relpath.startswith("/") or relpath.endswith("/") or "//" in relpath or any(ord(character) < 0x20 for character in relpath):
        raise ValueError("journal path is not canonical")
    raw_parts = relpath.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ValueError("journal path is not canonical")
    relative = relpath
    pure = pathlib.PurePosixPath(relative)
    if pathlib.PurePath(relpath).is_absolute() or pathlib.PureWindowsPath(relpath).drive or tuple(pure.parts) != tuple(raw_parts):
        raise ValueError("journal path is not canonical")
    root_absolute = _validate_original_chain(root_input, leaf_may_be_missing=False)
    candidate_absolute = _validate_original_chain(root_absolute / pathlib.Path(*pure.parts), leaf_may_be_missing=True, leaf_must_be_file=True)
    candidate = candidate_absolute.resolve(strict=False)
    root_resolved = root_absolute.resolve(strict=True)
    if not candidate.is_relative_to(root_resolved):
        raise ValueError("journal path escapes evidence root")
    return candidate


def _validate_cli_evidence_root(path_text: str) -> pathlib.Path:
    if type(path_text) is not str or not path_text:
        raise ValueError("evidence root is not canonical")
    absolute = _validate_original_chain(pathlib.Path(path_text), leaf_may_be_missing=True)
    if absolute.exists() and not absolute.is_dir():
        raise ValueError("evidence root is not a directory")
    return absolute


class _AuditSQLiteConnection(sqlite3.Connection):
    """Preserve raw bound REAL identity before SQLite applies column affinity."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._stage_admission: dict[str, Any] | None = None
        self._stage_rejection = False
        self._stage_admission_events: list[dict[str, Any]] = []
        super().__init__(*args, **kwargs)
        self.set_authorizer(self._stage_authorizer)

    def _stage_authorizer(self, action: int, table: str | None, column: str | None, database: str | None, trigger: str | None) -> int:
        if action not in {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE} or table != "stage_rows":
            return sqlite3.SQLITE_OK
        admission = self._stage_admission
        if action != sqlite3.SQLITE_INSERT or admission is None or admission.get("used_count", 0) != 0:
            self._stage_rejection = True
            return sqlite3.SQLITE_DENY
        admission["used_count"] = admission.get("used_count", 0) + 1
        return sqlite3.SQLITE_OK

    @contextlib.contextmanager
    def admit_stage_insert(
        self,
        key: str,
        raw_values: list[Any],
        real_bits: list[str],
        canonical_bytes: bytes,
        canonical_sha256: str,
        authority: dict[str, Any],
    ):
        if self._stage_admission is not None:
            raise RuntimeError("nested stage admission")
        expected = authority["decoded"]
        if type(key) is not str or key != f'{expected["run_id"]}\0{expected["idx"]}\0{0}':
            raise sqlite3.IntegrityError("stage admission key mismatch")
        if type(canonical_bytes) is not bytes or canonical_bytes != authority["canonical_row_bytes"]:
            raise sqlite3.IntegrityError("stage admission canonical mismatch")
        if type(canonical_sha256) is not str or canonical_sha256 != authority["canonical_row_sha256"]:
            raise sqlite3.IntegrityError("stage admission digest mismatch")
        if len(raw_values) != len(CANONICAL_COLUMNS) or len(real_bits) != len(REAL_BITS_COLUMNS):
            raise sqlite3.IntegrityError("stage admission arity mismatch")
        for actual, column in zip(raw_values, CANONICAL_COLUMNS):
            expected_value = expected[column]
            if column in REAL_COLUMNS:
                if type(actual) is not float or not math.isfinite(actual) or struct.pack(">d", actual).hex() != struct.pack(">d", expected_value).hex() or (actual == 0.0 and math.copysign(1.0, actual) < 0):
                    raise sqlite3.IntegrityError("stage admission REAL mismatch")
            elif type(actual) is not type(expected_value) or actual != expected_value:
                raise sqlite3.IntegrityError("stage admission scalar mismatch")
        expected_bits = [struct.pack(">d", expected[column]).hex() for column in ("cost_usd", "latency_s")]
        if real_bits != expected_bits:
            raise sqlite3.IntegrityError("stage admission REAL bits mismatch")
        record = {
            "key": key,
            "raw_values": tuple(raw_values),
            "raw_types": tuple(type(value).__name__ for value in raw_values),
            "real_bits": tuple(real_bits),
            "canonical_sha256": canonical_sha256,
            "used_count": 0,
        }
        self._stage_admission = record
        try:
            yield
            if record["used_count"] != 1:
                raise sqlite3.IntegrityError("stage admission direct use count mismatch")
        except BaseException as exc:
            if record["used_count"] != 1:
                raise sqlite3.IntegrityError("stage admission direct use count mismatch") from exc
            raise
        finally:
            self._stage_admission_events.append({
                "key": record["key"],
                "raw_types": record["raw_types"],
                "real_bits": record["real_bits"],
                "used_count": record["used_count"],
                "cleared": True,
            })
            self._stage_admission = None

    def execute(self, sql: str, parameters: Any = ()):
        try:
            return super().execute(sql, parameters)
        except sqlite3.DatabaseError:
            if self._stage_rejection:
                raise sqlite3.IntegrityError("immutable stage protocol authorization required") from None
            raise
        finally:
            self._stage_rejection = False


class _SQLiteProtocolGuard:
    """Connection-local authorization for the audit model's legal SQL writes."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self._context: dict[str, Any] | None = None
        connection.create_function("t02_protocol_write_allowed", 4, self._allowed, deterministic=True)

    @staticmethod
    def _digest(value: str | None) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest() if value is not None else ""

    def _allowed(self, action: str, key: str, old_json: str | None, new_json: str | None) -> int:
        context = self._context
        if context is None or type(action) is not str or type(key) is not str:
            return 0
        bundle_copy = (
            action == "prepared_insert"
            and context.get("action") == "journal_update"
            and context.get("lineage", {}).get("operation") == "prepare_bundle"
        )
        if (not bundle_copy and action != context["action"]) or key != context["key"] or old_json != (None if bundle_copy else context["old_json"]) or new_json != context["new_json"]:
            return 0
        if (not bundle_copy and self._digest(old_json) != context["old_digest"]) or self._digest(new_json) != context["new_digest"]:
            return 0
        expected_authority = context.get("prepared_authority_digest")
        if expected_authority is not None and expected_authority != context.get("lineage", {}).get("prepared_authority_digest"):
            return 0
        lineage = context.get("lineage")
        if type(lineage) is not dict or lineage.get("key") != key:
            return 0
        return 1

    @contextlib.contextmanager
    def authorize(self, action: str, key: str, old_json: str | None, new_json: str | None, *, prepared_authority_digest: str | None = None, lineage: dict[str, Any] | None = None):
        if self._context is not None:
            raise RuntimeError("nested protocol authorization")
        lineage_material = dict(lineage or {})
        lineage_material.setdefault("key", key)
        lineage_material.setdefault("generation", key.rsplit("\0", 1)[-1])
        if prepared_authority_digest is not None:
            lineage_material["prepared_authority_digest"] = prepared_authority_digest
        self._context = {
            "action": action,
            "table_action": action,
            "key": key,
            "old_json": old_json,
            "new_json": new_json,
            "old_digest": self._digest(old_json),
            "new_digest": self._digest(new_json),
            "prepared_authority_digest": prepared_authority_digest,
            "lineage": lineage_material,
        }
        try:
            yield
        finally:
            self._context = None


class Phase2Journal:
    """Future-only, audit-only reference model; never production persistence."""
    def __init__(self, root: pathlib.Path | None = None, boot: BootIdentityProvider | None = None, database_path: str | pathlib.Path | None = None) -> None:
        self.root = _validate_original_chain(pathlib.Path(root or pathlib.Path.cwd()), leaf_may_be_missing=False).resolve(strict=True)
        self.boot = boot or BootIdentityProvider("audit", "reference-boot")
        self.rows: dict[tuple[str, int, int], dict[str, Any]] = {}
        self.trusted_prepared: dict[tuple[str, int, int], dict[str, Any]] = {}
        self.cleaned: set[str] = set()
        self.created: set[str] = set()
        self.failure_cut: str | None = None
        self.last_crash_observation: dict[str, Any] = {}
        self.last_cas_rowcount = 0
        self.last_cleanup_rowcount = 0
        self.last_finalize_cas_rowcount = 0
        self.last_successor_insert_rowcount = 0
        self.database_path = str(database_path) if database_path is not None else ":memory:"
        self.connection = sqlite3.connect(self.database_path, isolation_level=None, cached_statements=0, factory=_AuditSQLiteConnection)
        self._protocol = _SQLiteProtocolGuard(self.connection)
        self.connection.create_function("t02_sql_sha256", 1, lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest() if type(value) is str else None, deterministic=True)
        self.connection.create_function("t02_sql_journal_transition_valid", 4, self._sql_journal_transition_valid, deterministic=True)
        self.connection.create_function("t02_sql_prepared_shape_valid", 5, self._sql_prepared_shape_valid, deterministic=True)
        self.connection.create_function("t02_sql_stage_shape_valid", 27, self._sql_stage_shape_valid, deterministic=True)
        self.connection.execute("CREATE TABLE IF NOT EXISTS journal_state (key TEXT PRIMARY KEY, snapshot_json TEXT NOT NULL)")
        self.connection.execute("CREATE TABLE IF NOT EXISTS prepared_snapshots (key TEXT PRIMARY KEY, snapshot_json TEXT NOT NULL, snapshot_sha256 TEXT NOT NULL)")
        self.connection.execute("CREATE TABLE IF NOT EXISTS cleanup_state (key TEXT PRIMARY KEY, relpath TEXT NOT NULL, owner TEXT NOT NULL, fence INTEGER NOT NULL)")
        self.connection.execute("CREATE TABLE IF NOT EXISTS crash_events (id INTEGER PRIMARY KEY AUTOINCREMENT, cut TEXT NOT NULL, db_key TEXT NOT NULL, initiator_pid INTEGER NOT NULL, durable INTEGER NOT NULL, transition TEXT NOT NULL, pre_state TEXT, post_state TEXT)")
        self.connection.execute("CREATE TABLE IF NOT EXISTS recovery_events (id INTEGER PRIMARY KEY AUTOINCREMENT, cut TEXT NOT NULL, db_key TEXT NOT NULL, recovery_pid INTEGER NOT NULL, operations_json TEXT NOT NULL, before_json TEXT NOT NULL, after_json TEXT NOT NULL)")
        typed_columns = {
            "text": "TEXT",
            "int": "INTEGER",
            "real": "REAL",
        }
        stage_columns = ", ".join(f'"{column}" {typed_columns[tag]}' for column, tag in CANONICAL_COLUMN_TYPES.items())
        self.connection.execute(f'CREATE TABLE IF NOT EXISTS stage_rows (key TEXT PRIMARY KEY, {stage_columns}, cost_usd_bits TEXT NOT NULL, latency_s_bits TEXT NOT NULL, canonical_row_bytes BLOB NOT NULL, canonical_row_sha256 TEXT NOT NULL)')
        for column in STAGE_SCALAR_COLUMNS:
            trigger = f"stage_rows_immutable_{column}"
            self.connection.execute(f'CREATE TRIGGER IF NOT EXISTS "{trigger}" BEFORE UPDATE OF "{column}" ON stage_rows BEGIN SELECT RAISE(ABORT, "immutable stage scalar"); END')
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS journal_protocol_insert
            BEFORE INSERT ON journal_state
            WHEN t02_protocol_write_allowed('journal_insert', NEW.key, NULL, NEW.snapshot_json) <> 1
              OR t02_sql_journal_transition_valid('insert', NEW.key, NULL, NEW.snapshot_json) <> 1
            BEGIN SELECT RAISE(ABORT, 'protocol authorization required'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS journal_protocol_update
            BEFORE UPDATE ON journal_state
            WHEN t02_protocol_write_allowed('journal_update', NEW.key, OLD.snapshot_json, NEW.snapshot_json) <> 1
              OR t02_sql_journal_transition_valid('update', NEW.key, OLD.snapshot_json, NEW.snapshot_json) <> 1
            BEGIN SELECT RAISE(ABORT, 'protocol authorization required'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS journal_protocol_delete
            BEFORE DELETE ON journal_state
            WHEN t02_protocol_write_allowed('journal_delete', OLD.key, OLD.snapshot_json, NULL) <> 1
              OR t02_sql_journal_transition_valid('delete', OLD.key, OLD.snapshot_json, NULL) <> 1
            BEGIN SELECT RAISE(ABORT, 'protocol authorization required'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS prepared_protocol_insert
            BEFORE INSERT ON prepared_snapshots
            WHEN t02_protocol_write_allowed('prepared_insert', NEW.key, NULL, NEW.snapshot_json) <> 1
              OR t02_sql_prepared_shape_valid('insert', NEW.key, NULL, NEW.snapshot_json, NEW.snapshot_sha256) <> 1
            BEGIN SELECT RAISE(ABORT, 'protocol authorization required'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS prepared_protocol_update
            BEFORE UPDATE ON prepared_snapshots
            WHEN t02_protocol_write_allowed('prepared_update', NEW.key, OLD.snapshot_json, NEW.snapshot_json) <> 1
              OR t02_sql_prepared_shape_valid('update', NEW.key, OLD.snapshot_json, NEW.snapshot_json, NEW.snapshot_sha256) <> 1
            BEGIN SELECT RAISE(ABORT, 'protocol authorization required'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS prepared_protocol_delete
            BEFORE DELETE ON prepared_snapshots
            WHEN t02_protocol_write_allowed('prepared_delete', OLD.key, OLD.snapshot_json, NULL) <> 1
              OR t02_sql_prepared_shape_valid('delete', OLD.key, OLD.snapshot_json, NULL, OLD.snapshot_sha256) <> 1
            BEGIN SELECT RAISE(ABORT, 'protocol authorization required'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS journal_prepare_copy_after
            AFTER UPDATE OF snapshot_json ON journal_state
            WHEN t02_protocol_write_allowed('journal_update', NEW.key, OLD.snapshot_json, NEW.snapshot_json) = 1
             AND json_extract(OLD.snapshot_json, '$.state') = 'claimed'
             AND json_extract(NEW.snapshot_json, '$.state') = 'prepared'
            BEGIN
                INSERT INTO prepared_snapshots(key, snapshot_json, snapshot_sha256)
                VALUES (NEW.key, NEW.snapshot_json, t02_sql_sha256(NEW.snapshot_json));
            END""")
        stage_insert_args = ", ".join(["'insert'", "NEW.key", *(f'NEW."{column}"' for column in CANONICAL_COLUMNS), "NEW.canonical_row_bytes", "NEW.canonical_row_sha256", "NEW.cost_usd_bits", "NEW.latency_s_bits"])
        stage_update_args = ", ".join(["'update'", "NEW.key", *(f'NEW."{column}"' for column in CANONICAL_COLUMNS), "NEW.canonical_row_bytes", "NEW.canonical_row_sha256", "NEW.cost_usd_bits", "NEW.latency_s_bits"])
        stage_delete_args = ", ".join(["'delete'", "OLD.key", *(f'OLD."{column}"' for column in CANONICAL_COLUMNS), "OLD.canonical_row_bytes", "OLD.canonical_row_sha256", "OLD.cost_usd_bits", "OLD.latency_s_bits"])
        self.connection.execute(f"""CREATE TRIGGER IF NOT EXISTS stage_protocol_insert
            BEFORE INSERT ON stage_rows
            WHEN t02_protocol_write_allowed('stage_insert', NEW.key, NULL, NEW.canonical_row_sha256) <> 1
              OR typeof(NEW.cost_usd) <> 'real'
              OR typeof(NEW.latency_s) <> 'real'
              OR t02_sql_stage_shape_valid({stage_insert_args}) <> 1
            BEGIN SELECT RAISE(ABORT, 'protocol authorization required for stage'); END""")
        self.connection.execute(f"""CREATE TRIGGER IF NOT EXISTS stage_protocol_update
            BEFORE UPDATE ON stage_rows
            WHEN t02_protocol_write_allowed('stage_update', NEW.key, OLD.canonical_row_sha256, NEW.canonical_row_sha256) <> 1
              OR typeof(NEW.cost_usd) <> 'real'
              OR typeof(NEW.latency_s) <> 'real'
              OR t02_sql_stage_shape_valid({stage_update_args}) <> 1
            BEGIN SELECT RAISE(ABORT, 'protocol authorization required for immutable stage'); END""")
        self.connection.execute(f"""CREATE TRIGGER IF NOT EXISTS stage_protocol_delete
            BEFORE DELETE ON stage_rows
            WHEN t02_protocol_write_allowed('stage_delete', OLD.key, OLD.canonical_row_sha256, NULL) <> 1
              OR typeof(OLD.cost_usd) <> 'real'
              OR typeof(OLD.latency_s) <> 'real'
              OR t02_sql_stage_shape_valid({stage_delete_args}) <> 1
            BEGIN SELECT RAISE(ABORT, 'protocol authorization required for immutable stage'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS journal_identity_immutable
            BEFORE UPDATE OF snapshot_json ON journal_state
            WHEN json_extract(OLD.snapshot_json, '$.state') = 'committed'
              OR json_extract(OLD.snapshot_json, '$.run_id') IS NOT json_extract(NEW.snapshot_json, '$.run_id')
              OR json_extract(OLD.snapshot_json, '$.stage_idx') IS NOT json_extract(NEW.snapshot_json, '$.stage_idx')
              OR json_extract(OLD.snapshot_json, '$.generation') IS NOT json_extract(NEW.snapshot_json, '$.generation')
              OR json_extract(OLD.snapshot_json, '$.publication_id') IS NOT json_extract(NEW.snapshot_json, '$.publication_id')
              OR json_extract(OLD.snapshot_json, '$.stage_graph_hash') IS NOT json_extract(NEW.snapshot_json, '$.stage_graph_hash')
              OR json_extract(OLD.snapshot_json, '$.stage_definition_hash') IS NOT json_extract(NEW.snapshot_json, '$.stage_definition_hash')
              OR json_extract(OLD.snapshot_json, '$.stage_identity_json') IS NOT json_extract(NEW.snapshot_json, '$.stage_identity_json')
              OR json_extract(OLD.snapshot_json, '$.input_hash') IS NOT json_extract(NEW.snapshot_json, '$.input_hash')
              OR json_extract(OLD.snapshot_json, '$.prompt_hash') IS NOT json_extract(NEW.snapshot_json, '$.prompt_hash')
              OR json_extract(OLD.snapshot_json, '$.config_hash') IS NOT json_extract(NEW.snapshot_json, '$.config_hash')
              OR json_extract(OLD.snapshot_json, '$.model_id') IS NOT json_extract(NEW.snapshot_json, '$.model_id')
              OR json_extract(OLD.snapshot_json, '$.policy_hash') IS NOT json_extract(NEW.snapshot_json, '$.policy_hash')
            BEGIN SELECT RAISE(ABORT, 'immutable committed journal'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS journal_committed_delete
            BEFORE DELETE ON journal_state
            WHEN json_extract(OLD.snapshot_json, '$.state') = 'committed'
            BEGIN SELECT RAISE(ABORT, 'immutable committed journal'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS stage_committed_delete
            BEFORE DELETE ON stage_rows
            WHEN EXISTS (SELECT 1 FROM journal_state WHERE key = OLD.key AND json_extract(snapshot_json, '$.state') = 'committed')
            BEGIN SELECT RAISE(ABORT, 'immutable committed stage'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS journal_key_immutable
            BEFORE UPDATE OF key ON journal_state
            BEGIN SELECT RAISE(ABORT, 'immutable journal key'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS stage_key_immutable
            BEFORE UPDATE OF key ON stage_rows
            BEGIN SELECT RAISE(ABORT, 'immutable stage key'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS prepared_snapshot_immutable_update
            BEFORE UPDATE ON prepared_snapshots
            BEGIN SELECT RAISE(ABORT, 'immutable prepared snapshot copy'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS prepared_snapshot_immutable_delete
            BEFORE DELETE ON prepared_snapshots
            BEGIN SELECT RAISE(ABORT, 'immutable prepared snapshot copy'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS journal_insert_shape
            BEFORE INSERT ON journal_state
            WHEN json_valid(NEW.snapshot_json) = 0
              OR COALESCE(json_type(NEW.snapshot_json, '$.run_id'), '') <> 'text'
              OR COALESCE(json_type(NEW.snapshot_json, '$.stage_idx'), '') <> 'integer'
              OR COALESCE(json_type(NEW.snapshot_json, '$.generation'), '') <> 'integer'
              OR COALESCE(json_type(NEW.snapshot_json, '$.state'), '') <> 'text'
              OR json_extract(NEW.snapshot_json, '$.state') NOT IN ('claimed', 'prepared', 'committed', 'aborting', 'aborted')
              OR COALESCE(json_type(NEW.snapshot_json, '$.publication_id'), '') <> 'text'
              OR COALESCE(json_type(NEW.snapshot_json, '$.owner_token'), '') <> 'text'
              OR COALESCE(json_type(NEW.snapshot_json, '$.fence'), '') <> 'integer'
              OR NEW.key <> json_extract(NEW.snapshot_json, '$.run_id') || char(0) || json_extract(NEW.snapshot_json, '$.stage_idx') || char(0) || json_extract(NEW.snapshot_json, '$.generation')
            BEGIN SELECT RAISE(ABORT, 'invalid journal insert'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS journal_update_shape
            BEFORE UPDATE OF snapshot_json ON journal_state
            WHEN json_valid(NEW.snapshot_json) = 0
              OR COALESCE(json_type(NEW.snapshot_json, '$.run_id'), '') <> 'text'
              OR COALESCE(json_type(NEW.snapshot_json, '$.stage_idx'), '') <> 'integer'
              OR COALESCE(json_type(NEW.snapshot_json, '$.generation'), '') <> 'integer'
              OR COALESCE(json_type(NEW.snapshot_json, '$.state'), '') <> 'text'
              OR json_extract(NEW.snapshot_json, '$.state') NOT IN ('claimed', 'prepared', 'committed', 'aborting', 'aborted')
              OR COALESCE(json_type(NEW.snapshot_json, '$.publication_id'), '') <> 'text'
              OR COALESCE(json_type(NEW.snapshot_json, '$.owner_token'), '') <> 'text'
              OR COALESCE(json_type(NEW.snapshot_json, '$.fence'), '') <> 'integer'
              OR NEW.key <> json_extract(NEW.snapshot_json, '$.run_id') || char(0) || json_extract(NEW.snapshot_json, '$.stage_idx') || char(0) || json_extract(NEW.snapshot_json, '$.generation')
            BEGIN SELECT RAISE(ABORT, 'invalid journal snapshot'); END""")
        self.connection.execute("""CREATE TRIGGER IF NOT EXISTS journal_prepared_authority_immutable
            BEFORE UPDATE OF snapshot_json ON journal_state
            WHEN json_extract(OLD.snapshot_json, '$.state') = 'prepared'
             AND (
                (json_extract(NEW.snapshot_json, '$.state') = 'prepared' AND (
                    json_extract(OLD.snapshot_json, '$.owner_token') IS NOT json_extract(NEW.snapshot_json, '$.owner_token')
                    OR json_extract(OLD.snapshot_json, '$.owner') IS NOT json_extract(NEW.snapshot_json, '$.owner')
                    OR json_extract(OLD.snapshot_json, '$.fence') IS NOT json_extract(NEW.snapshot_json, '$.fence')
                    OR json_extract(OLD.snapshot_json, '$.temp_owner_token') IS NOT json_extract(NEW.snapshot_json, '$.temp_owner_token')
                    OR json_extract(OLD.snapshot_json, '$.temp_fence') IS NOT json_extract(NEW.snapshot_json, '$.temp_fence')
                    OR json_extract(OLD.snapshot_json, '$.temp_relpath') IS NOT json_extract(NEW.snapshot_json, '$.temp_relpath')
                    OR json_extract(OLD.snapshot_json, '$.final_relpath') IS NOT json_extract(NEW.snapshot_json, '$.final_relpath')
                    OR json_extract(OLD.snapshot_json, '$.artifact_sha256') IS NOT json_extract(NEW.snapshot_json, '$.artifact_sha256')
                    OR json_extract(OLD.snapshot_json, '$.artifact_size') IS NOT json_extract(NEW.snapshot_json, '$.artifact_size')
                    OR json_extract(OLD.snapshot_json, '$.canonical_row_bytes') IS NOT json_extract(NEW.snapshot_json, '$.canonical_row_bytes')
                    OR json_extract(OLD.snapshot_json, '$.canonical_row_sha256') IS NOT json_extract(NEW.snapshot_json, '$.canonical_row_sha256')
                ))
                OR (json_extract(NEW.snapshot_json, '$.state') = 'aborting' AND (
                    json_extract(OLD.snapshot_json, '$.owner_token') IS NOT json_extract(NEW.snapshot_json, '$.owner_token')
                    OR json_extract(OLD.snapshot_json, '$.temp_owner_token') IS NOT json_extract(NEW.snapshot_json, '$.temp_owner_token')
                    OR json_extract(OLD.snapshot_json, '$.temp_fence') IS NOT json_extract(NEW.snapshot_json, '$.temp_fence')
                    OR json_extract(OLD.snapshot_json, '$.temp_relpath') IS NOT json_extract(NEW.snapshot_json, '$.temp_relpath')
                    OR json_extract(OLD.snapshot_json, '$.final_relpath') IS NOT json_extract(NEW.snapshot_json, '$.final_relpath')
                    OR json_extract(OLD.snapshot_json, '$.artifact_sha256') IS NOT json_extract(NEW.snapshot_json, '$.artifact_sha256')
                    OR json_extract(OLD.snapshot_json, '$.artifact_size') IS NOT json_extract(NEW.snapshot_json, '$.artifact_size')
                    OR json_extract(OLD.snapshot_json, '$.canonical_row_bytes') IS NOT json_extract(NEW.snapshot_json, '$.canonical_row_bytes')
                    OR json_extract(OLD.snapshot_json, '$.canonical_row_sha256') IS NOT json_extract(NEW.snapshot_json, '$.canonical_row_sha256')
                ))
                OR (json_extract(NEW.snapshot_json, '$.state') = 'committed' AND (
                    json_extract(OLD.snapshot_json, '$.owner_token') IS NOT json_extract(NEW.snapshot_json, '$.owner_token')
                    OR json_extract(OLD.snapshot_json, '$.owner') IS NOT json_extract(NEW.snapshot_json, '$.owner')
                    OR json_extract(OLD.snapshot_json, '$.fence') IS NOT json_extract(NEW.snapshot_json, '$.fence')
                    OR json_extract(OLD.snapshot_json, '$.final_relpath') IS NOT json_extract(NEW.snapshot_json, '$.final_relpath')
                    OR json_extract(OLD.snapshot_json, '$.artifact_sha256') IS NOT json_extract(NEW.snapshot_json, '$.artifact_sha256')
                    OR json_extract(OLD.snapshot_json, '$.artifact_size') IS NOT json_extract(NEW.snapshot_json, '$.artifact_size')
                    OR json_extract(OLD.snapshot_json, '$.canonical_row_bytes') IS NOT json_extract(NEW.snapshot_json, '$.canonical_row_bytes')
                    OR json_extract(OLD.snapshot_json, '$.canonical_row_sha256') IS NOT json_extract(NEW.snapshot_json, '$.canonical_row_sha256')
                ))
                OR json_extract(NEW.snapshot_json, '$.state') NOT IN ('prepared', 'aborting', 'committed')
             )
            BEGIN SELECT RAISE(ABORT, 'immutable prepared authority'); END""")
        self.connection.set_authorizer(self.connection._stage_authorizer)
        self._load_rows()

    @staticmethod
    def _sql_row_fields() -> frozenset[str]:
        return frozenset(IMMUTABLE_IDENTITY_FIELDS + ("state", "owner_token", "fence", "boot_epoch_id", "lease_issued_monotonic_ns", "lease_expires_monotonic_ns", "owner", "expires", "error_code") + OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS)

    def _sql_decode_journal_row(self, payload: str | None) -> dict[str, Any] | None:
        if type(payload) is not str:
            return None
        try:
            row = self._from_json_row(payload)
            if self._json_row(row) != payload or set(row) != self._sql_row_fields():
                return None
            self._sql_validate_journal_domain(row)
            return row
        except (TypeError, ValueError, json.JSONDecodeError, OverflowError, sqlite3.Error):
            return None

    @staticmethod
    def _sql_hash(value: Any, *, nullable: bool = False) -> bool:
        return value is None if nullable else type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None

    def _sql_validate_journal_domain(self, row: dict[str, Any]) -> None:
        if set(row) != self._sql_row_fields():
            raise ValueError("journal field set mismatch")
        for field in ("stage_graph_hash", "stage_definition_hash", "policy_hash"):
            if not self._sql_hash(row.get(field)):
                raise ValueError(f"journal hash domain: {field}")
        # Legacy V13/V14 claims are admitted only as pre-prepare journal
        # identities; prepare/stage still require the V15 exact 64-byte
        # lowercase authority claims.
        for field in ("input_hash", "prompt_hash", "config_hash"):
            if type(row.get(field)) is not str or re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{73}", row[field]) is None:
                raise ValueError(f"journal hash domain: {field}")
        for field in ("run_id", "publication_id", "stage_identity_json", "model_id", "owner_token", "boot_epoch_id", "owner"):
            if type(row.get(field)) is not str or not row[field]:
                raise ValueError(f"journal text domain: {field}")
        try:
            identity = json.loads(row["stage_identity_json"])
            if json.dumps(identity, ensure_ascii=True, sort_keys=True, separators=(",", ":")) != row["stage_identity_json"]:
                raise ValueError("journal stage identity is not canonical")
        except (TypeError, ValueError, json.JSONDecodeError):
            raise ValueError("journal stage identity malformed")
        for field in ("stage_idx", "generation", "fence", "lease_issued_monotonic_ns", "lease_expires_monotonic_ns", "expires"):
            if type(row.get(field)) is not int or row[field] < 0 or row[field] > 2**63 - 1:
                raise ValueError(f"journal integer domain: {field}")
        if row["lease_expires_monotonic_ns"] < row["lease_issued_monotonic_ns"]:
            raise ValueError("journal lease domain")
        if row.get("error_code") is not None and (type(row["error_code"]) is not str or not row["error_code"]):
            raise ValueError("journal error domain")
        for field in ("temp_relpath", "final_relpath"):
            if row.get(field) is not None:
                safe_journal_path(self.root, row[field])
        if row.get("temp_owner_token") is not None and (type(row["temp_owner_token"]) is not str or not row["temp_owner_token"]):
            raise ValueError("journal temporary owner domain")
        if row.get("temp_fence") is not None and (type(row["temp_fence"]) is not int or row["temp_fence"] < 0):
            raise ValueError("journal temporary fence domain")
        if row.get("artifact_sha256") is not None and not self._sql_hash(row["artifact_sha256"]):
            raise ValueError("journal artifact hash domain")
        if row.get("artifact_size") is not None and (type(row["artifact_size"]) is not int or row["artifact_size"] < 0 or row["artifact_size"] > 2**63 - 1):
            raise ValueError("journal artifact size domain")
        if row.get("canonical_row_bytes") is not None:
            if type(row["canonical_row_bytes"]) is not bytes or not self._sql_hash(row.get("canonical_row_sha256")) or hashlib.sha256(row["canonical_row_bytes"]).hexdigest() != row["canonical_row_sha256"]:
                raise ValueError("journal canonical material domain")
        elif row.get("canonical_row_sha256") is not None:
            raise ValueError("journal canonical digest without bytes")
        for field in ("prepared_predecessor_snapshot_sha256", "prepared_authority_digest"):
            if row.get(field) is not None and not self._sql_hash(row[field]):
                raise ValueError(f"journal prepared digest domain: {field}")
        if row.get("prepared_authority_material") is not None:
            if type(row["prepared_authority_material"]) is not str or not self._sql_hash(row.get("prepared_authority_digest")) or hashlib.sha256(row["prepared_authority_material"].encode("utf-8")).hexdigest() != row["prepared_authority_digest"]:
                raise ValueError("journal prepared authority domain")
        elif row.get("prepared_authority_digest") is not None or row.get("prepared_predecessor_snapshot_sha256") is not None:
            raise ValueError("journal incomplete prepared authority")
        self._validate_shape(row)

    def _sql_lineage_rows(self, run_id: str, stage_idx: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for stored_key, stored_json in self.connection.execute("SELECT key, snapshot_json FROM journal_state").fetchall():
            candidate = self._sql_decode_journal_row(stored_json)
            if candidate is not None and stored_key == f'{candidate["run_id"]}\0{candidate["stage_idx"]}\0{candidate["generation"]}' and candidate["run_id"] == run_id and candidate["stage_idx"] == stage_idx:
                rows.append(candidate)
        return rows

    def _sql_prepared_copy_parity(self, key: str, primary: dict[str, Any]) -> bool:
        copies = self.connection.execute(
            "SELECT key, snapshot_json, snapshot_sha256 FROM prepared_snapshots WHERE key=?",
            (key,),
        ).fetchall()
        if len(copies) != 1:
            return False
        copy_key, snapshot_json, snapshot_sha256 = copies[0]
        if copy_key != key or type(snapshot_json) is not str or type(snapshot_sha256) is not str:
            return False
        if hashlib.sha256(snapshot_json.encode("utf-8")).hexdigest() != snapshot_sha256:
            return False
        copy = self._sql_decode_journal_row(snapshot_json)
        if copy is None or copy.get("state") != "prepared":
            return False
        if self._json_row(copy) != snapshot_json:
            return False
        parity_fields = IMMUTABLE_IDENTITY_FIELDS + ("owner_token",) + MATERIAL_FIELDS + PREPARED_AUTHORITY_FIELDS
        return all(copy.get(field) == primary.get(field) for field in parity_fields)

    def _sql_journal_transition_valid(self, action: str, key: str, old_json: str | None, new_json: str | None) -> int:
        context = self._protocol._context
        if type(action) is not str or type(key) is not str or context is None:
            return 0
        expected_action = "journal_" + action
        if context.get("action") != expected_action or context.get("key") != key:
            return 0
        if action == "delete":
            return 0
        new = self._sql_decode_journal_row(new_json)
        old = self._sql_decode_journal_row(old_json) if action == "update" else None
        if new is None or action == "update" and old is None:
            return 0
        expected_key = f'{new["run_id"]}\0{new["stage_idx"]}\0{new["generation"]}'
        if key != expected_key or type(new["generation"]) is not int or new["generation"] < 0:
            return 0
        try:
            self._sql_validate_journal_domain(new)
        except (TypeError, ValueError):
            return 0
        lineage = context.get("lineage")
        if type(lineage) is not dict or lineage.get("key") != key:
            return 0
        if action == "insert":
            if new["state"] != "claimed":
                return 0
            lineage_rows = self._sql_lineage_rows(new["run_id"], new["stage_idx"])
            if new["generation"] == 0:
                return int(not lineage_rows and lineage.get("predecessor_state") is None)
            predecessor_key = f'{new["run_id"]}\0{new["stage_idx"]}\0{new["generation"] - 1}'
            predecessor = next((candidate for candidate in lineage_rows if candidate["generation"] == new["generation"] - 1), None)
            generations = sorted(candidate["generation"] for candidate in lineage_rows)
            if generations != list(range(new["generation"])):
                return 0
            if any(candidate["state"] != "aborted" for candidate in lineage_rows):
                return 0
            if any(
                candidate.get(field) != new.get(field)
                for candidate in lineage_rows
                for field in IMMUTABLE_IDENTITY_FIELDS
                if field != "generation"
            ):
                return 0
            return int(
                lineage.get("operation") == "finalize_with_successor"
                and lineage.get("predecessor_key") == predecessor_key
                and lineage.get("predecessor_generation") == new["generation"] - 1
                and lineage.get("predecessor_state") == "aborted"
                and lineage.get("successor_key") == key
                and predecessor is not None
                and predecessor["state"] == "aborted"
            )
        if old is None:
            return 0
        old_key = f'{old["run_id"]}\0{old["stage_idx"]}\0{old["generation"]}'
        if old_key != key or old["run_id"] != new["run_id"] or old["stage_idx"] != new["stage_idx"] or old["generation"] != new["generation"]:
            return 0
        try:
            self._sql_validate_journal_domain(old)
        except (TypeError, ValueError):
            return 0
        pair = (old["state"], new["state"])
        allowed = {
            ("claimed", "prepared"): set(OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS + ("state",)),
            ("prepared", "committed"): set(TEMP_FIELDS + ("state",)),
            ("claimed", "aborting"): set(("state", "error_code", "owner_token", "owner", "fence", "boot_epoch_id", "lease_issued_monotonic_ns", "lease_expires_monotonic_ns", "expires") + TEMP_FIELDS),
            ("prepared", "aborting"): {"state", "error_code", "owner", "fence", "boot_epoch_id", "lease_issued_monotonic_ns", "lease_expires_monotonic_ns", "expires"},
            ("aborting", "aborting"): {"owner_token", "owner", "fence", "boot_epoch_id", "lease_issued_monotonic_ns", "lease_expires_monotonic_ns", "expires", "error_code", "state"},
            ("aborting", "aborted"): set(OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS + ("state", "error_code")),
        }
        if pair not in allowed:
            return 0
        changed = {field for field in self._sql_row_fields() if old.get(field) != new.get(field)}
        if not changed.issubset(allowed[pair]):
            return 0
        if lineage.get("predecessor_state") != old["state"] or lineage.get("successor_state") != new["state"]:
            return 0
        if pair == ("claimed", "prepared") and any(old.get(field) != new.get(field) for field in ("owner_token", "owner", "fence", "boot_epoch_id", "lease_issued_monotonic_ns", "lease_expires_monotonic_ns", "expires")):
            return 0
        if pair == ("prepared", "committed") and any(old.get(field) != new.get(field) for field in OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS if field not in TEMP_FIELDS):
            return 0
        if pair == ("prepared", "aborting") and any(old.get(field) != new.get(field) for field in OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS):
            return 0
        if pair == ("claimed", "prepared"):
            if lineage.get("operation") != "prepare_bundle":
                return 0
            if self.connection.execute("SELECT count(*) FROM prepared_snapshots WHERE key=?", (key,)).fetchone()[0] != 0:
                return 0
            try:
                self._validate_prepared_shape(new, require_authority=True)
            except (TypeError, ValueError):
                return 0
        if pair == ("prepared", "committed"):
            try:
                if new.get("canonical_row_bytes") is None or new.get("canonical_row_sha256") is None:
                    raise ValueError("committed canonical material absent")
                authority = self._v15_authority()
                self._validate_v15_authority(new, authority, artifact_sha256=new.get("artifact_sha256"))
            except (TypeError, ValueError):
                return 0
            if self._sql_stage_row_matches_prepared(key, old) != 1:
                return 0
            if any(new.get(field) is not None for field in TEMP_FIELDS):
                return 0
        if pair == ("claimed", "aborting"):
            expected_temp = f'tmp/r/{hashlib.sha256(old["run_id"].encode("utf-8")).hexdigest()}/s/{old["stage_idx"]}/g/{old["generation"]}/f/{old["fence"]}/o/{old["owner_token"]}.part'
            if (
                lineage.get("operation") != "reclaim_expired"
                or lineage.get("recovery_now") != new.get("lease_issued_monotonic_ns")
                or new["fence"] != old["fence"] + 1
                or new.get("error_code") != "claimed_lease_expired"
                or new.get("owner") != new.get("owner_token")
                or new.get("boot_epoch_id") != self.boot.boot_epoch_id
                or old.get("lease_expires_monotonic_ns", 0) > new.get("lease_issued_monotonic_ns", -1)
                or new.get("lease_expires_monotonic_ns", 0) <= new.get("lease_issued_monotonic_ns", 0)
                or new.get("expires") != new.get("lease_expires_monotonic_ns")
                or new.get("temp_owner_token") != old.get("owner_token")
                or new.get("temp_fence") != old.get("fence")
                or new.get("temp_relpath") != expected_temp
            ):
                return 0
        if pair == ("prepared", "aborting"):
            if (
                lineage.get("operation") != "takeover_prepared"
                or type(lineage.get("recovery_now")) is not int
                or old.get("lease_expires_monotonic_ns", 0) > lineage.get("recovery_now")
                or new.get("error_code") != "prepared_lease_expired"
                or new.get("owner") != lineage.get("recovery_owner")
                or new.get("fence") != old.get("fence") + 1
                or new.get("boot_epoch_id") != self.boot.boot_epoch_id
                or new.get("lease_issued_monotonic_ns") != lineage.get("recovery_now")
                or new.get("lease_expires_monotonic_ns", 0) <= new.get("lease_issued_monotonic_ns", 0)
                or new.get("expires") != new.get("lease_expires_monotonic_ns")
                or any(new.get(field) != old.get(field) for field in ("owner_token", "temp_owner_token", "temp_fence", "temp_relpath") + OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS)
            ):
                return 0
        if pair == ("aborting", "aborting"):
            if (
                lineage.get("operation") != "takeover_aborting"
                or lineage.get("recovery_now") != new.get("lease_issued_monotonic_ns")
                or new["fence"] != old["fence"] + 1
                or not new.get("error_code")
                or new.get("owner") != lineage.get("recovery_owner")
                or new.get("boot_epoch_id") != self.boot.boot_epoch_id
                or old.get("lease_expires_monotonic_ns", 0) > new.get("lease_issued_monotonic_ns", -1)
                or new.get("lease_expires_monotonic_ns", 0) <= new.get("lease_issued_monotonic_ns", 0)
                or new.get("expires") != new.get("lease_expires_monotonic_ns")
                or any(new.get(field) != old.get(field) for field in ("owner_token",) + TEMP_FIELDS + MATERIAL_FIELDS + PREPARED_AUTHORITY_FIELDS)
            ):
                return 0
        if pair == ("aborting", "aborted") and (lineage.get("operation") != "finalize_with_successor" or new.get("error_code") is None):
            return 0
        if pair == ("aborting", "aborted"):
            prepared_branch = all(old.get(field) is not None for field in PREPARED_AUTHORITY_FIELDS)
            if prepared_branch:
                if not self._sql_prepared_copy_parity(key, old):
                    return 0
                if any(new.get(field) != old.get(field) for field in MATERIAL_FIELDS + PREPARED_AUTHORITY_FIELDS):
                    return 0
                if any(new.get(field) is not None for field in TEMP_FIELDS):
                    return 0
            elif any(new.get(field) is not None for field in OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS):
                return 0
        return 1

    def _sql_prepared_shape_valid(self, action: str, key: str, old_json: str | None, new_json: str | None, snapshot_sha256: str | None) -> int:
        context = self._protocol._context
        bundle_copy = context is not None and context.get("action") == "journal_update" and context.get("lineage", {}).get("operation") == "prepare_bundle"
        if context is None or action != "insert" or (context.get("action") != "prepared_insert" and not bundle_copy) or context.get("key") != key:
            return 0
        if type(snapshot_sha256) is not str or not self._sql_hash(snapshot_sha256) or type(new_json) is not str or hashlib.sha256(new_json.encode("utf-8")).hexdigest() != snapshot_sha256:
            return 0
        row = self._sql_decode_journal_row(new_json)
        if row is None or row.get("state") != "prepared":
            return 0
        expected_key = f'{row["run_id"]}\0{row["stage_idx"]}\0{row["generation"]}'
        if key != expected_key:
            return 0
        try:
            self._validate_prepared_shape(row, require_authority=True)
        except (TypeError, ValueError):
            return 0
        primary = self.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (key,)).fetchone()
        if primary is None:
            return 0
        primary_row = self._sql_decode_journal_row(primary[0])
        if primary_row is None or primary_row.get("state") != "prepared" or self._json_row(primary_row) != new_json:
            return 0
        if any(primary_row.get(field) != row.get(field) for field in PREPARED_AUTHORITY_FIELDS):
            return 0
        return 1

    def _sql_stage_shape_valid(self, action: str, key: str, *arguments: Any) -> int:
        context = self._protocol._context
        if context is None or action != "insert" or context.get("action") != "stage_insert" or type(key) is not str:
            return 0
        if len(arguments) != len(CANONICAL_COLUMNS) + 4:
            return 0
        scalar_values = arguments[:len(CANONICAL_COLUMNS)]
        canonical_bytes, canonical_sha256, cost_bits, latency_bits = arguments[-4:]
        if type(canonical_bytes) is not bytes or type(canonical_sha256) is not str or type(cost_bits) is not str or type(latency_bits) is not str:
            return 0
        try:
            decoded = decode_canonical_stage_row(canonical_bytes)
            if hashlib.sha256(canonical_bytes).hexdigest() != canonical_sha256:
                return 0
            for actual, column in zip(scalar_values, CANONICAL_COLUMNS):
                expected = decoded[column]
                if column in REAL_COLUMNS:
                    if type(actual) is not float or struct.pack(">d", actual).hex() != struct.pack(">d", expected).hex():
                        return 0
                    if actual == 0.0 and math.copysign(1.0, actual) < 0:
                        return 0
                elif type(actual) is not type(expected) or actual != expected:
                    return 0
            authority = self._v15_authority()
            if canonical_bytes != authority["canonical_row_bytes"] or canonical_sha256 != authority["canonical_row_sha256"]:
                return 0
            if key.rsplit("\0", 1)[0] != f'{decoded["run_id"]}\0{decoded["idx"]}':
                return 0
            if cost_bits != struct.pack(">d", decoded["cost_usd"]).hex() or latency_bits != struct.pack(">d", decoded["latency_s"]).hex():
                return 0
            journal_row = self.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (key,)).fetchone()
            prepared = self._sql_decode_journal_row(journal_row[0]) if journal_row else None
            if prepared is None or prepared.get("state") != "prepared" or prepared.get("canonical_row_bytes") != canonical_bytes or prepared.get("canonical_row_sha256") != canonical_sha256:
                return 0
            self._validate_v15_authority(prepared, authority, artifact_sha256=decoded["artifact_hash"])
        except (TypeError, ValueError, struct.error):
            return 0
        return 1

    def _sql_stage_row_matches_prepared(self, key: str, prepared: dict[str, Any]) -> int:
        """Require the committed transition's exact durable stage witness."""
        columns = ", ".join(f'"{column}"' for column in CANONICAL_COLUMNS + REAL_BITS_COLUMNS)
        rows = self.connection.execute(
            f"SELECT key, {columns}, canonical_row_bytes, canonical_row_sha256 FROM stage_rows WHERE key=?",
            (key,),
        ).fetchall()
        if len(rows) != 1:
            return 0
        result = rows[0]
        scalar_start = 1
        scalar_end = scalar_start + len(CANONICAL_COLUMNS)
        bit_end = scalar_end + len(REAL_BITS_COLUMNS)
        stored_scalars = dict(zip(CANONICAL_COLUMNS, result[scalar_start:scalar_end]))
        stored_bits = tuple(result[scalar_end:bit_end])
        canonical_bytes = result[bit_end]
        canonical_sha256 = result[bit_end + 1]
        try:
            if result[0] != key or type(canonical_bytes) is not bytes or type(canonical_sha256) is not str:
                return 0
            decoded = decode_canonical_stage_row(canonical_bytes)
            for column in CANONICAL_COLUMNS:
                actual, expected = stored_scalars[column], decoded[column]
                if column in REAL_COLUMNS:
                    if type(actual) is not float or struct.pack(">d", actual).hex() != struct.pack(">d", expected).hex():
                        return 0
                    if actual == 0.0 and math.copysign(1.0, actual) < 0:
                        return 0
                elif type(actual) is not type(expected) or actual != expected:
                    return 0
            expected_bits = tuple(struct.pack(">d", decoded[column]).hex() for column in ("cost_usd", "latency_s"))
            if stored_bits != expected_bits:
                return 0
            if canonical_stage_row(decoded) != canonical_bytes or hashlib.sha256(canonical_bytes).hexdigest() != canonical_sha256:
                return 0
            authority = self._v15_authority()
            if canonical_bytes != authority["canonical_row_bytes"] or canonical_sha256 != authority["canonical_row_sha256"]:
                return 0
            _validate_canonical_claims(prepared, decoded, decoded["artifact_hash"])
            self._validate_v15_authority(prepared, authority, artifact_sha256=decoded["artifact_hash"])
        except (TypeError, ValueError, struct.error):
            return 0
        return 1

    @staticmethod
    def _json_row(row: dict[str, Any]) -> str:
        def normalize(value: Any) -> Any:
            if isinstance(value, bytes):
                return {"__bytes__": base64.b64encode(value).decode("ascii")}
            if isinstance(value, dict):
                return {key: normalize(item) for key, item in value.items()}
            return value
        return json.dumps(normalize(row), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _from_json_row(data: str) -> dict[str, Any]:
        def denormalize(value: Any) -> Any:
            if isinstance(value, dict) and set(value) == {"__bytes__"}:
                return base64.b64decode(value["__bytes__"], validate=True)
            if isinstance(value, dict):
                return {key: denormalize(item) for key, item in value.items()}
            return value
        return denormalize(json.loads(data))

    def _load_rows(self) -> None:
        self.rows.clear()
        self.trusted_prepared.clear()
        self.cleaned.clear()
        for key, snapshot_json in self.connection.execute("SELECT key, snapshot_json FROM journal_state").fetchall():
            row = self._from_json_row(snapshot_json)
            expected_key = f"{row['run_id']}\0{row['stage_idx']}\0{row['generation']}"
            if key != expected_key:
                raise ValueError("journal key identity mismatch")
            self._validate_shape(row)
            self.rows[(row["run_id"], row["stage_idx"], row["generation"])] = row
        for key, snapshot_json, snapshot_sha256 in self.connection.execute("SELECT key, snapshot_json, snapshot_sha256 FROM prepared_snapshots").fetchall():
            # This table is an audit copy, never the authority for a prepared
            # row.  A fresh actor must be able to reopen a database containing
            # a damaged copy and reject it against its external anchor.
            row = self._from_json_row(snapshot_json)
            self.trusted_prepared[(row["run_id"], row["stage_idx"], row["generation"])] = row
        for key, relpath, owner, fence in self.connection.execute("SELECT key, relpath, owner, fence FROM cleanup_state").fetchall():
            self.cleaned.add(relpath)
        for key, row in tuple((key, row) for key, row in self.rows.items()):
            if row["state"] == "committed":
                db_key = f"{row['run_id']}\0{row['stage_idx']}\0{row['generation']}"
                if self.connection.execute("SELECT 1 FROM stage_rows WHERE key=?", (db_key,)).fetchone() is None:
                    raise ValueError("committed journal missing stage evidence")
                self.reconstruct_stage_row(db_key)

    def _db_put(self, row: dict[str, Any], *, prepared_authority_digest: str | None = None, lineage: dict[str, Any] | None = None) -> None:
        key = f"{row['run_id']}\0{row['stage_idx']}\0{row['generation']}"
        snapshot_json = self._json_row(row)
        existing = self.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (key,)).fetchone()
        old_json = existing[0] if existing is not None else None
        action = "journal_insert" if existing is None else "journal_update"
        with self._protocol.authorize(action, key, old_json, snapshot_json, prepared_authority_digest=prepared_authority_digest, lineage=lineage):
            if existing is None:
                self.connection.execute("INSERT INTO journal_state(key, snapshot_json) VALUES (?, ?)", (key, snapshot_json))
            else:
                result = self.connection.execute("UPDATE journal_state SET snapshot_json=? WHERE key=? AND snapshot_json=?", (snapshot_json, key, existing[0]))
                if result.rowcount != 1:
                    raise RuntimeError("journal full-snapshot CAS failed")

    def _db_snapshot(self, row: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        key = f"{row['run_id']}\0{row['stage_idx']}\0{row['generation']}"
        result = self.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (key,)).fetchone()
        if result is None:
            raise RuntimeError("journal database snapshot missing")
        return key, self._from_json_row(result[0])

    def _cut(self, name: str) -> None:
        if self.failure_cut == name:
            raise RuntimeError(f"injected failure cut: {name}")

    def _new_identity(self, run_id: str, stage_idx: int, generation: int, publication_id: str) -> dict[str, Any]:
        return {"run_id": run_id, "stage_idx": stage_idx, "generation": generation, "publication_id": publication_id, "stage_graph_hash": "a" * 64, "stage_definition_hash": "b" * 64, "stage_identity_json": "{}", "input_hash": "c" * 64, "prompt_hash": "d" * 64, "config_hash": "e" * 64, "model_id": "model", "policy_hash": "f" * 64}

    def _validate_shape(self, row: dict[str, Any]) -> bool:
        state = row.get("state")
        if state not in {"claimed", "prepared", "committed", "aborting", "aborted"}:
            raise ValueError("malformed journal state")
        if any(row.get(field) is None for field in IMMUTABLE_IDENTITY_FIELDS):
            raise ValueError("immutable identity is incomplete")
        if state == "claimed":
            if any(row.get(field) is not None for field in OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS + ("error_code",)):
                raise ValueError("claimed state shape")
        elif state == "prepared":
            if any(row.get(field) is None for field in OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS) or row.get("error_code") is not None:
                raise ValueError("prepared state shape")
        elif state == "committed":
            if any(row.get(field) is not None for field in TEMP_FIELDS) or any(row.get(field) is None for field in MATERIAL_FIELDS + PREPARED_AUTHORITY_FIELDS) or row.get("error_code") is not None:
                raise ValueError("committed state shape")
        elif state == "aborted":
            if any(row.get(field) is not None for field in TEMP_FIELDS) or row.get("error_code") is None:
                raise ValueError("aborted state shape")
        elif not row.get("error_code"):
            raise ValueError("aborting state shape")
        authority_values = [row.get(field) is not None for field in PREPARED_AUTHORITY_FIELDS]
        if state in {"aborting", "aborted"} and any(authority_values) and not all(authority_values):
            raise ValueError("prepared authority shape")
        if state == "aborted":
            if all(authority_values):
                if any(row.get(field) is None for field in MATERIAL_FIELDS):
                    raise ValueError("prepared-derived aborted material shape")
            elif any(row.get(field) is not None for field in MATERIAL_FIELDS):
                raise ValueError("claimed-derived aborted material shape")
        return True

    def _validate_prepared_shape(self, row: dict[str, Any], *, require_authority: bool = True) -> bool:
        shape_row = row
        if not require_authority:
            shape_row = dict(row)
            shape_row.update({"prepared_predecessor_snapshot_sha256": "0" * 64, "prepared_authority_material": "anchor-compatibility-only", "prepared_authority_digest": hashlib.sha256(b"anchor-compatibility-only").hexdigest()})
        self._validate_shape(shape_row)
        if row.get("state") not in {"prepared", "committed"}:
            raise ValueError("prepared snapshot state malformed")
        for field in ("input_hash", "prompt_hash", "config_hash", "policy_hash", "stage_graph_hash", "stage_definition_hash"):
            if type(row.get(field)) is not str or not re.fullmatch(r"[0-9a-f]{64}", row[field]):
                raise ValueError(f"prepared snapshot claim malformed: {field}")
        if type(row.get("owner_token")) is not str or not row["owner_token"] or type(row.get("fence")) is not int or row["fence"] < 0:
            raise ValueError("prepared snapshot owner/fence malformed")
        if type(row.get("lease_issued_monotonic_ns")) is not int or type(row.get("lease_expires_monotonic_ns")) is not int or row["lease_expires_monotonic_ns"] < row["lease_issued_monotonic_ns"]:
            raise ValueError("prepared snapshot lease malformed")
        if row["state"] == "prepared":
            if row.get("temp_owner_token") != row.get("owner_token") or row.get("temp_fence") != row.get("fence"):
                raise ValueError("prepared snapshot owner/fence mismatch")
        path_fields = ("temp_relpath", "final_relpath") if row["state"] == "prepared" else ("final_relpath",)
        for field in path_fields:
            if type(row.get(field)) is not str:
                raise ValueError("prepared snapshot path malformed")
            safe_journal_path(self.root, row[field])
        expected_temp, expected_final = _expected_prepared_paths(row)
        if row["state"] == "prepared" and row.get("temp_relpath") != expected_temp:
            raise ValueError("prepared path authority mismatch: temp")
        if row.get("final_relpath") != expected_final:
            raise ValueError("prepared path authority mismatch: final")
        if type(row.get("artifact_sha256")) is not str or not re.fullmatch(r"[0-9a-f]{64}", row["artifact_sha256"]):
            raise ValueError("prepared snapshot artifact malformed")
        if type(row.get("artifact_size")) is not int or row["artifact_size"] < 0 or row["artifact_size"] > 2**63 - 1:
            raise ValueError("prepared snapshot artifact size malformed")
        if type(row.get("canonical_row_bytes")) is not bytes or type(row.get("canonical_row_sha256")) is not str or not re.fullmatch(r"[0-9a-f]{64}", row["canonical_row_sha256"]):
            raise ValueError("prepared snapshot canonical material malformed")
        if hashlib.sha256(row["canonical_row_bytes"]).hexdigest() != row["canonical_row_sha256"]:
            raise ValueError("prepared snapshot canonical digest mismatch")
        if not require_authority:
            return True
        if type(row.get("prepared_predecessor_snapshot_sha256")) is not str or not re.fullmatch(r"[0-9a-f]{64}", row["prepared_predecessor_snapshot_sha256"]):
            raise ValueError("prepared predecessor digest malformed")
        if type(row.get("prepared_authority_material")) is not str or type(row.get("prepared_authority_digest")) is not str or not re.fullmatch(r"[0-9a-f]{64}", row["prepared_authority_digest"]):
            raise ValueError("prepared authority material malformed")
        if hashlib.sha256(row["prepared_authority_material"].encode("utf-8")).hexdigest() != row["prepared_authority_digest"]:
            raise ValueError("prepared authority digest mismatch")
        authority = self._v15_authority()
        expected_authority = self._prepared_authority_fields(row, self._claimed_predecessor_json(row), authority)
        if any(row.get(field) != value for field, value in expected_authority.items()):
            raise ValueError("prepared authority lineage mismatch")
        decoded = decode_canonical_stage_row(row["canonical_row_bytes"])
        _validate_canonical_claims(row, decoded)
        return True

    def _validate_external_anchor(
        self,
        anchor: dict[str, Any] | None,
        current: dict[str, Any],
        decoded: dict[str, Any],
        canonical_bytes: bytes,
        artifact_sha256: str,
        artifact_size: int,
        temp_relpath: str,
        final_relpath: str,
    ) -> dict[str, Any]:
        required = {"row", "decoded", "canonical_row_bytes", "canonical_row_sha256"}
        if type(anchor) is not dict or set(anchor) != required:
            raise ValueError("external anchor malformed")
        anchor_row = anchor["row"]
        anchor_decoded = anchor["decoded"]
        anchor_bytes = anchor["canonical_row_bytes"]
        anchor_sha256 = anchor["canonical_row_sha256"]
        if type(anchor_row) is not dict or type(anchor_decoded) is not dict or type(anchor_bytes) is not bytes or type(anchor_sha256) is not str:
            raise ValueError("external anchor malformed")
        self._validate_prepared_shape(anchor_row, require_authority=False)
        comparable_anchor = dict(anchor_row)
        comparable_current = dict(current)
        for field in PREPARED_AUTHORITY_FIELDS:
            comparable_anchor.pop(field, None)
            comparable_current.pop(field, None)
        if comparable_anchor != comparable_current:
            raise ValueError("external anchor mismatch")
        if anchor_decoded != decoded or anchor_bytes != canonical_bytes:
            raise ValueError("external anchor canonical claim mismatch")
        if hashlib.sha256(anchor_bytes).hexdigest() != anchor_sha256 or anchor_sha256 != hashlib.sha256(canonical_bytes).hexdigest():
            raise ValueError("external anchor canonical digest mismatch")
        if anchor_row.get("canonical_row_bytes") != anchor_bytes or anchor_row.get("canonical_row_sha256") != anchor_sha256:
            raise ValueError("external anchor canonical material mismatch")
        if anchor_row.get("artifact_sha256") != artifact_sha256 or anchor_row.get("artifact_size") != artifact_size:
            raise ValueError("external anchor artifact claim mismatch")
        if anchor_row.get("temp_relpath") != temp_relpath or anchor_row.get("final_relpath") != final_relpath:
            raise ValueError("external anchor path claim mismatch")
        _validate_canonical_claims(anchor_row, anchor_decoded, artifact_sha256)
        return anchor_row

    def _claimed_predecessor_json(self, prepared: dict[str, Any]) -> str:
        predecessor = dict(prepared)
        predecessor["state"] = "claimed"
        for field in OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS:
            predecessor[field] = None
        self._validate_shape(predecessor)
        return self._json_row(predecessor)

    def _prepared_authority_fields(self, prepared: dict[str, Any], predecessor_json: str, authority: dict[str, Any]) -> dict[str, str]:
        decoded = authority["decoded"]
        material = {
            "domain": "T02-V15K-PREPARED-AUTHORITY-V1",
            "key": f'{prepared["run_id"]}\0{prepared["stage_idx"]}\0{prepared["generation"]}',
            "generation": prepared["generation"],
            "immutable_identity": {field: prepared[field] for field in IMMUTABLE_IDENTITY_FIELDS},
            "predecessor_snapshot_sha256": hashlib.sha256(predecessor_json.encode("utf-8")).hexdigest(),
            "owner": {field: prepared[field] for field in ("owner_token", "owner", "fence", "boot_epoch_id", "lease_issued_monotonic_ns", "lease_expires_monotonic_ns", "expires")},
            "temporary_authority": {field: prepared[field] for field in ("temp_owner_token", "temp_fence", "temp_relpath")},
            "final_relpath": prepared["final_relpath"],
            "artifact": {"sha256": prepared["artifact_sha256"], "size": prepared["artifact_size"]},
            "canonical": {"sha256": prepared["canonical_row_sha256"], "size": len(prepared["canonical_row_bytes"])},
            "v15": {"decoded_sha256": authority["canonical_row_sha256"], "real_bits": {field: struct.pack(">d", decoded[field]).hex() for field in REAL_COLUMNS}, "claims": {field: decoded[field] for field in ("run_id", "idx", "input_hash", "prompt_hash", "config_hash", "model_id", "artifact_hash")}},
        }
        encoded = json.dumps(material, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return {"prepared_predecessor_snapshot_sha256": material["predecessor_snapshot_sha256"], "prepared_authority_material": encoded, "prepared_authority_digest": hashlib.sha256(encoded.encode("utf-8")).hexdigest()}

    def _v15_authority(self) -> dict[str, Any]:
        canonical_bytes = _v15_oracle_bytes()
        decoded = decode_canonical_stage_row(canonical_bytes)
        if canonical_stage_row(decoded) != canonical_bytes:
            raise ValueError("V15 authority canonical re-encoding mismatch")
        canonical_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
        return {"decoded": decoded, "canonical_row_bytes": canonical_bytes, "canonical_row_sha256": canonical_sha256}

    def _validate_v15_authority(self, row: dict[str, Any], authority: dict[str, Any], *, artifact_sha256: str | None = None) -> None:
        decoded = authority["decoded"]
        canonical_bytes = authority["canonical_row_bytes"]
        if row.get("run_id") != decoded["run_id"] or row.get("stage_idx") != decoded["idx"]:
            raise ValueError("V15 authority claim mismatch (canonical claim mismatch)")
        if row.get("input_hash") != decoded["input_hash"] or row.get("prompt_hash") != decoded["prompt_hash"] or row.get("config_hash") != decoded["config_hash"] or row.get("model_id") != decoded["model_id"]:
            raise ValueError("V15 authority claim mismatch (canonical claim mismatch)")
        expected_artifact = artifact_sha256 if artifact_sha256 is not None else row.get("artifact_sha256")
        if expected_artifact != decoded["artifact_hash"]:
            raise ValueError("V15 authority artifact claim mismatch (canonical claim mismatch)")
        if row.get("canonical_row_bytes") is not None and row.get("canonical_row_bytes") != canonical_bytes:
            raise ValueError("V15 authority canonical bytes mismatch (canonical claim mismatch)")
        if row.get("canonical_row_sha256") is not None and row.get("canonical_row_sha256") != authority["canonical_row_sha256"]:
            raise ValueError("V15 authority canonical digest mismatch (canonical claim mismatch)")
        _validate_canonical_claims(row, decoded, decoded["artifact_hash"])

    def state_shape(self, row: dict[str, Any]) -> bool:
        return self._validate_shape(row)

    def snapshot(self, row: dict[str, Any]) -> dict[str, Any]:
        return dict(row)

    def full_snapshot_cas(self, run_id: str, stage_idx: int, generation: int, snapshot: dict[str, Any], updates: dict[str, Any]) -> int:
        raise RuntimeError("generic public full_snapshot_cas is not a lifecycle route")

    def update(self, run_id: str, stage_idx: int, generation: int, updates: dict[str, Any]) -> int:
        raise RuntimeError("generic public update is not a lifecycle route")

    def delete(self, run_id: str, stage_idx: int, generation: int) -> None:
        raise RuntimeError("public delete is not a lifecycle route")

    def aborting_material_branch(self, row: dict[str, Any]) -> str:
        has_temp = all(row.get(field) is not None for field in TEMP_FIELDS)
        has_final = all(row.get(field) is not None for field in MATERIAL_FIELDS)
        if has_temp and has_final:
            return "both"
        if has_temp:
            return "temp-only"
        if has_final:
            return "final-only"
        return "neither"

    def decode_prepared(self, row: dict[str, Any], expected_values: list[Any] | None = None) -> bytes:
        if row.get("state") not in {"prepared", "committed"} or not isinstance(row.get("canonical_row_bytes"), bytes):
            raise ValueError("prepared canonical bytes absent")
        decoded = decode_canonical_stage_row(row["canonical_row_bytes"])
        _validate_canonical_claims(row, decoded)
        if expected_values is not None and [decoded[column] for column in CANONICAL_COLUMNS] != expected_values:
            raise ValueError("canonical row claim mismatch")
        reencoded = canonical_stage_row(decoded)
        if reencoded != row["canonical_row_bytes"] or hashlib.sha256(reencoded).hexdigest() != row["canonical_row_sha256"]:
            raise ValueError("canonical row re-encoding mismatch")
        return reencoded

    def claim(self, run_id: str, stage_idx: int, owner: str, fence: int, expires: int, *, generation: int = 0, publication_id: str | None = None, issued: int | None = None, boot_epoch_id: str | None = None, input_hash: str | None = None, prompt_hash: str | None = None, config_hash: str | None = None, model_id: str | None = None) -> dict[str, Any]:
        if type(generation) is not int or generation != 0:
            raise ValueError("public claim is generation-0 genesis only")
        key = (run_id, stage_idx, generation)
        if key in self.rows:
            raise ValueError("duplicate journal claim")
        issued_ns = int(issued if issued is not None else 0)
        identity = self._new_identity(run_id, stage_idx, generation, publication_id or f"pub-{generation}")
        for field, value in (("input_hash", input_hash), ("prompt_hash", prompt_hash), ("config_hash", config_hash), ("model_id", model_id)):
            if value is not None:
                identity[field] = value
        row = {**identity, "state": "claimed", "owner_token": owner, "fence": fence, "boot_epoch_id": boot_epoch_id or self.boot.boot_epoch_id, "lease_issued_monotonic_ns": issued_ns, "lease_expires_monotonic_ns": int(expires), "owner": owner, "expires": int(expires), "error_code": None, **{field: None for field in OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS}}
        self._validate_shape(row)
        db_key = f"{run_id}\0{stage_idx}\0{generation}"
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            existing_lineage = False
            for existing_key, existing_json in self.connection.execute("SELECT key, snapshot_json FROM journal_state").fetchall():
                existing = self._from_json_row(existing_json)
                if existing["run_id"] == run_id and existing["stage_idx"] == stage_idx:
                    existing_lineage = True
                    break
            if existing_lineage:
                raise ValueError("duplicate journal claim")
            self._db_put(row)
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        self.rows[key] = row
        return dict(row)

    def _find(self, run_id: str, stage_idx: int, generation: int | None = None) -> dict[str, Any] | None:
        values = [row for key, row in self.rows.items() if key[0] == run_id and key[1] == stage_idx and (generation is None or key[2] == generation)]
        return max(values, key=lambda row: row["generation"]) if values else None

    def _persist_full_snapshot_cas(self, old: dict[str, Any], new: dict[str, Any], *, prepared_authority_digest: str | None = None, operation: str | None = None, recovery_now: int | None = None) -> bool:
        db_key = f"{old['run_id']}\0{old['stage_idx']}\0{old['generation']}"
        old_json = self._json_row(old)
        new_json = self._json_row(new)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            lineage = {"key": db_key, "generation": old["generation"], "predecessor_state": old.get("state"), "successor_state": new.get("state")}
            if operation is not None:
                lineage["operation"] = operation
            if recovery_now is not None:
                lineage["recovery_now"] = recovery_now
            if operation in {"takeover_prepared", "takeover_aborting"}:
                lineage["recovery_owner"] = new.get("owner")
            with self._protocol.authorize("journal_update", db_key, old_json, new_json, prepared_authority_digest=prepared_authority_digest, lineage=lineage):
                result = self.connection.execute("UPDATE journal_state SET snapshot_json=? WHERE key=? AND snapshot_json=?", (new_json, db_key, old_json))
            self.last_cas_rowcount = result.rowcount
            if result.rowcount != 1:
                self.connection.rollback()
                return False
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        self.rows[(new["run_id"], new["stage_idx"], new["generation"])] = dict(new)
        return True

    def _lease_ok(self, row: dict[str, Any], now: int, owner: str | None = None, fence: int | None = None, boot_epoch_id: str | None = None) -> bool:
        if owner is not None and row["owner_token"] != owner or fence is not None and row["fence"] != fence:
            return False
        if boot_epoch_id is not None and row["boot_epoch_id"] != boot_epoch_id:
            return False
        if row["boot_epoch_id"] != self.boot.boot_epoch_id:
            return False
        if now < row["lease_issued_monotonic_ns"]:
            raise RuntimeError("lease_clock_anomaly")
        return now < row["lease_expires_monotonic_ns"]

    def renew(self, run_id: str, stage_idx: int, owner: str, fence: int, now: int) -> int:
        row = self._find(run_id, stage_idx)
        if row is None or row["owner_token"] != owner or row["fence"] != fence:
            return 0
        if not self._lease_ok(row, now, owner, fence):
            return 0
        raise RuntimeError("public renew is not a lifecycle route")

    def prepare(self, run_id: str, stage_idx: int, owner: str, fence: int, now: int, canonical_row_bytes: bytes, artifact_sha256: str, artifact_size: int, temp_relpath: str, final_relpath: str, *, external_anchor: dict[str, Any] | None = None) -> dict[str, Any]:
        row = self._find(run_id, stage_idx)
        if row is None or row["state"] != "claimed" or not self._lease_ok(row, now, owner, fence):
            raise RuntimeError("prepare CAS failed")
        if type(canonical_row_bytes) is not bytes:
            raise ValueError("canonical bytes malformed")
        decoded = decode_canonical_stage_row(canonical_row_bytes)
        _validate_canonical_claims(row, decoded, artifact_sha256)
        if type(artifact_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256) or type(artifact_size) is not int or artifact_size < 0 or artifact_size > 2**63 - 1:
            raise ValueError("artifact claim malformed")
        safe_journal_path(self.root, temp_relpath)
        safe_journal_path(self.root, final_relpath)
        authority = self._v15_authority()
        prepared = dict(row)
        prepared.update({"state": "prepared", "temp_relpath": temp_relpath, "temp_owner_token": owner, "temp_fence": fence, "final_relpath": final_relpath, "artifact_sha256": artifact_sha256, "artifact_size": artifact_size, "canonical_row_bytes": bytes(canonical_row_bytes), "canonical_row_sha256": hashlib.sha256(canonical_row_bytes).hexdigest()})
        prepared.update(self._prepared_authority_fields(prepared, self._json_row(row), authority))
        self._validate_prepared_shape(prepared)
        if canonical_row_bytes != authority["canonical_row_bytes"] or hashlib.sha256(canonical_row_bytes).hexdigest() != authority["canonical_row_sha256"]:
            raise ValueError("V15 authority canonical payload mismatch")
        self._validate_v15_authority(prepared, authority, artifact_sha256=artifact_sha256)
        if artifact_size != len(authority["canonical_row_bytes"]):
            raise ValueError("V15 authority artifact size mismatch")
        if external_anchor is not None:
            # Compatibility-only assertion: caller data is never used as the
            # source of canonical bytes, claims, or the committed snapshot.
            self._validate_external_anchor(external_anchor, prepared, decoded, canonical_row_bytes, artifact_sha256, artifact_size, temp_relpath, final_relpath)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            current = self._from_json_row(self.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (f"{run_id}\0{stage_idx}\0{row['generation']}",)).fetchone()[0])
            if current != row:
                raise RuntimeError("prepare CAS failed")
            transaction_authority = self._v15_authority()
            if transaction_authority != authority:
                raise ValueError("V15 authority changed during prepare")
            self._validate_v15_authority(current, transaction_authority, artifact_sha256=transaction_authority["decoded"]["artifact_hash"])
            self._db_put(prepared, prepared_authority_digest=prepared["prepared_authority_digest"], lineage={"key": f'{run_id}\0{stage_idx}\0{row["generation"]}', "generation": row["generation"], "predecessor_state": "claimed", "successor_state": "prepared", "operation": "prepare_bundle", "prepared_authority_digest": prepared["prepared_authority_digest"]})
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        self.rows[(run_id, stage_idx, row["generation"])] = prepared
        self.trusted_prepared[(run_id, stage_idx, row["generation"])] = self._from_json_row(self._json_row(prepared))
        return dict(prepared)

    def _insert_typed_stage(self, key: str, decoded: dict[str, Any], canonical_bytes: bytes, canonical_sha256: str, *, prepared_authority_digest: str | None = None) -> None:
        columns = ", ".join(f'"{column}"' for column in CANONICAL_COLUMNS)
        columns += ', "cost_usd_bits", "latency_s_bits"'
        placeholders = ", ".join("?" for _ in CANONICAL_COLUMNS + REAL_BITS_COLUMNS)
        values = [decoded[column] for column in CANONICAL_COLUMNS]
        bits = [struct.pack(">d", decoded[column]).hex() for column in ("cost_usd", "latency_s")]
        if bits != ["3ff0000000000000", "0000000000000000"]:
            raise ValueError("V15 REAL bit authority mismatch")
        authority = self._v15_authority()
        with self.connection.admit_stage_insert(key, values, bits, canonical_bytes, canonical_sha256, authority):
            with self._protocol.authorize("stage_insert", key, None, canonical_sha256, prepared_authority_digest=prepared_authority_digest, lineage={"key": key, "generation": key.rsplit("\0", 1)[-1], "prepared_authority_digest": prepared_authority_digest}):
                self.connection.execute(
                    f"INSERT INTO stage_rows(key, {columns}, canonical_row_bytes, canonical_row_sha256) VALUES (?, {placeholders}, ?, ?)",
                    [key, *values, *bits, canonical_bytes, canonical_sha256],
                )

    def _read_typed_stage(self, key: str) -> tuple[dict[str, Any], bytes, str] | None:
        columns = ", ".join(f'"{column}"' for column in CANONICAL_COLUMNS + REAL_BITS_COLUMNS)
        result = self.connection.execute(f"SELECT {columns}, canonical_row_bytes, canonical_row_sha256 FROM stage_rows WHERE key=?", (key,)).fetchone()
        if result is None:
            return None
        decoded = dict(zip(CANONICAL_COLUMNS, result[:len(CANONICAL_COLUMNS)]))
        return decoded, bytes(result[len(STAGE_SCALAR_COLUMNS)]), result[len(STAGE_SCALAR_COLUMNS) + 1]

    def reconstruct_stage_row(self, key: str) -> dict[str, Any]:
        columns = ", ".join(f'"{column}"' for column in CANONICAL_COLUMNS + REAL_BITS_COLUMNS)
        result = self.connection.execute(f"SELECT {columns}, canonical_row_bytes, canonical_row_sha256 FROM stage_rows WHERE key=?", (key,)).fetchone()
        if result is None:
            raise KeyError(key)
        row = dict(zip(CANONICAL_COLUMNS, result[:len(CANONICAL_COLUMNS)]))
        stored_bits = tuple(result[len(CANONICAL_COLUMNS):len(STAGE_SCALAR_COLUMNS)])
        expected_bits = tuple(struct.pack(">d", row[column]).hex() for column in ("cost_usd", "latency_s"))
        if stored_bits != expected_bits or list(expected_bits) != ["3ff0000000000000", "0000000000000000"]:
            raise ValueError("REAL bit authority mismatch")
        validate_stage_domains(row)
        canonical_bytes = canonical_stage_row(row)
        canonical_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
        authority = self._v15_authority()
        self._validate_v15_authority({**row, "stage_idx": row["idx"], "artifact_sha256": row["artifact_hash"], "canonical_row_bytes": canonical_bytes, "canonical_row_sha256": canonical_sha256}, authority, artifact_sha256=row["artifact_hash"])
        if canonical_bytes != authority["canonical_row_bytes"] or canonical_sha256 != authority["canonical_row_sha256"]:
            raise ValueError("V15 authority reconstruction mismatch")
        return {"row": row, "canonical_row_bytes": canonical_bytes, "canonical_row_sha256": canonical_sha256, "real_bits": dict(zip(REAL_BITS_COLUMNS, stored_bits)), "stored_blob_sha256": result[len(STAGE_SCALAR_COLUMNS) + 1]}

    def _resolve_prepared_lineage(self, run_id: str, stage_idx: int) -> tuple[str, str, dict[str, Any]] | None:
        prefix = f"{run_id}\0{stage_idx}\0"
        candidates: list[tuple[str, str, dict[str, Any]]] = []
        for db_key, snapshot_json in self.connection.execute("SELECT key, snapshot_json FROM journal_state").fetchall():
            if not db_key.startswith(prefix):
                continue
            row = self._from_json_row(snapshot_json)
            expected_key = f'{row.get("run_id")}\0{row.get("stage_idx")}\0{row.get("generation")}'
            if db_key != expected_key or row.get("run_id") != run_id or row.get("stage_idx") != stage_idx:
                raise ValueError("journal lineage key mismatch")
            self._validate_shape(row)
            candidates.append((db_key, snapshot_json, row))
        if not candidates:
            return None
        candidates.sort(key=lambda item: item[2]["generation"])
        generations = [item[2]["generation"] for item in candidates]
        if generations != list(range(generations[-1] + 1)):
            raise ValueError("journal generation gap or duplicate")
        immutable = tuple(candidates[0][2].get(field) for field in IMMUTABLE_IDENTITY_FIELDS if field != "generation")
        for index, (_, _, current) in enumerate(candidates):
            current_immutable = tuple(current.get(field) for field in IMMUTABLE_IDENTITY_FIELDS if field != "generation")
            if current_immutable != immutable:
                raise ValueError("journal immutable lineage mismatch")
            if index and candidates[index - 1][2].get("state") != "aborted":
                raise ValueError("journal predecessor lineage mismatch")
        copies = self.connection.execute("SELECT key, snapshot_json, snapshot_sha256 FROM prepared_snapshots").fetchall()
        known_keys = {item[0] for item in candidates}
        for copy_key, copy_json, copy_sha256 in copies:
            if copy_key.startswith(prefix) and copy_key not in known_keys:
                raise ValueError("unexpected prepared copy lineage")
            if copy_key.startswith(prefix) and hashlib.sha256(copy_json.encode("utf-8")).hexdigest() != copy_sha256:
                raise ValueError("prepared copy digest mismatch")
        prepared = [item for item in candidates if item[2].get("state") == "prepared"]
        if len(prepared) > 1:
            raise ValueError("multiple prepared generations")
        if not prepared:
            return None
        active = prepared[0]
        if active[2]["generation"] != generations[-1]:
            raise ValueError("prepared generation is not active lineage")
        return active

    def commit(self, run_id: str, stage_idx: int, owner: str, fence: int, now: int, *, external_anchor: dict[str, Any] | None = None) -> int:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            resolved = self._resolve_prepared_lineage(run_id, stage_idx)
            if resolved is None:
                self.connection.rollback()
                return 0
            db_key, snapshot_json, row = resolved
            if row["state"] != "prepared" or row["owner_token"] != owner or row["fence"] != fence or not self._lease_ok(row, now, owner, fence):
                self.connection.rollback()
                return 0
            self._validate_prepared_shape(row)
            prepared_copy = self.connection.execute("SELECT snapshot_json, snapshot_sha256 FROM prepared_snapshots WHERE key=?", (db_key,)).fetchone()
            if prepared_copy is None or hashlib.sha256(prepared_copy[0].encode("utf-8")).hexdigest() != prepared_copy[1] or self._from_json_row(prepared_copy[0]) != row:
                raise ValueError("prepared snapshot copy mismatch")
            authority = self._v15_authority()
            prepared_bytes = authority["canonical_row_bytes"]
            prepared_hash = authority["canonical_row_sha256"]
            decoded = authority["decoded"]
            self._validate_v15_authority(row, authority)
            if row.get("canonical_row_bytes") != prepared_bytes or row.get("canonical_row_sha256") != prepared_hash or row.get("artifact_size") != len(prepared_bytes):
                raise ValueError("V15 authority prepared snapshot mismatch")
            if external_anchor is not None:
                self._validate_external_anchor(external_anchor, row, decoded, prepared_bytes, row["artifact_sha256"], row["artifact_size"], row["temp_relpath"], row["final_relpath"])
            self._insert_typed_stage(db_key, decoded, prepared_bytes, prepared_hash, prepared_authority_digest=row["prepared_authority_digest"])
            self._cut("after_stage_insert")
            reconstructed = self.reconstruct_stage_row(db_key)
            if reconstructed["row"] != decoded or reconstructed["canonical_row_bytes"] != prepared_bytes or reconstructed["canonical_row_sha256"] != prepared_hash:
                raise ValueError("stage readback mismatch")
            self._cut("during_readback")
            committed = dict(row)
            committed.update({"state": "committed", "temp_relpath": None, "temp_owner_token": None, "temp_fence": None})
            self._validate_shape(committed)
            self._cut("before_prepared_to_committed_cas")
            committed_json = self._json_row(committed)
            with self._protocol.authorize("journal_update", db_key, snapshot_json, committed_json, prepared_authority_digest=row["prepared_authority_digest"], lineage={"key": db_key, "generation": row["generation"], "predecessor_state": "prepared", "successor_state": "committed", "prepared_authority_digest": row["prepared_authority_digest"]}):
                cas = self.connection.execute("UPDATE journal_state SET snapshot_json=? WHERE key=? AND snapshot_json=?", (committed_json, db_key, snapshot_json))
            if cas.rowcount != 1:
                raise RuntimeError("prepared-to-committed CAS failed")
            self._cut("after_cas_before_commit")
            self._cut("before_commit")
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        self.rows[(run_id, stage_idx, row["generation"])] = committed
        return 1

    def reclaim_expired(self, run_id: str, stage_idx: int, now: int, owner: str, *, current_boot_epoch_id: str | None = None) -> dict[str, Any]:
        row = self._find(run_id, stage_idx)
        if row is None:
            raise KeyError((run_id, stage_idx))
        if row["state"] != "claimed":
            return dict(row)
        if row["boot_epoch_id"] == self.boot.boot_epoch_id and now < row["lease_issued_monotonic_ns"]:
            raise RuntimeError("lease_clock_anomaly")
        if row["boot_epoch_id"] == self.boot.boot_epoch_id and now < row["lease_expires_monotonic_ns"]:
            return dict(row)
        old_owner, old_fence = row["owner_token"], row["fence"]
        old_temp = f"tmp/r/{hashlib.sha256(run_id.encode('utf-8')).hexdigest()}/s/{stage_idx}/g/{row['generation']}/f/{old_fence}/o/{old_owner}.part"
        updated = dict(row)
        updated.update({"state": "aborting", "error_code": "claimed_lease_expired", "owner_token": owner, "owner": owner, "fence": old_fence + 1, "boot_epoch_id": current_boot_epoch_id or self.boot.boot_epoch_id, "lease_issued_monotonic_ns": now, "lease_expires_monotonic_ns": now + LEASE_DURATION_NS, "expires": now + LEASE_DURATION_NS, "temp_relpath": old_temp, "temp_owner_token": old_owner, "temp_fence": old_fence})
        self._validate_shape(updated)
        if not self._persist_full_snapshot_cas(row, updated, operation="reclaim_expired", recovery_now=now):
            raise RuntimeError("reclaim full-snapshot CAS failed")
        return dict(updated)

    def takeover_aborting(self, run_id: str, stage_idx: int, now: int, owner: str) -> dict[str, Any]:
        row = self._find(run_id, stage_idx)
        if row is None or row["state"] != "aborting":
            raise RuntimeError("aborting takeover CAS failed")
        if row["boot_epoch_id"] == self.boot.boot_epoch_id and now < row["lease_issued_monotonic_ns"]:
            raise RuntimeError("lease_clock_anomaly")
        if now < row["lease_expires_monotonic_ns"]:
            raise RuntimeError("aborting lease still valid")
        updated = dict(row)
        updated.update({"owner": owner, "fence": row["fence"] + 1, "boot_epoch_id": self.boot.boot_epoch_id, "lease_issued_monotonic_ns": now, "lease_expires_monotonic_ns": now + LEASE_DURATION_NS, "expires": now + LEASE_DURATION_NS})
        self._validate_shape(updated)
        if not self._persist_full_snapshot_cas(row, updated, operation="takeover_aborting", recovery_now=now):
            raise RuntimeError("aborting takeover CAS failed")
        return dict(updated)

    def takeover_prepared(self, run_id: str, stage_idx: int, now: int, owner: str) -> dict[str, Any]:
        row = self._find(run_id, stage_idx)
        if row is None or row["state"] != "prepared" or now < row["lease_expires_monotonic_ns"]:
            raise RuntimeError("prepared takeover CAS failed")
        updated = dict(row)
        updated.update({"state": "aborting", "error_code": "prepared_lease_expired", "owner": owner, "fence": row["fence"] + 1, "boot_epoch_id": self.boot.boot_epoch_id, "lease_issued_monotonic_ns": now, "lease_expires_monotonic_ns": now + LEASE_DURATION_NS, "expires": now + LEASE_DURATION_NS})
        self._validate_shape(updated)
        if not self._persist_full_snapshot_cas(row, updated, operation="takeover_prepared", recovery_now=now):
            raise RuntimeError("prepared takeover CAS failed")
        return dict(updated)

    def stale_update(self, run_id: str, stage_idx: int, owner: str, fence: int) -> int:
        row = self._find(run_id, stage_idx)
        if row is None:
            return 0
        eligible = int(row["owner_token"] == owner and row["fence"] == fence and row["state"] not in {"aborted", "committed"})
        if not eligible:
            self.last_cas_rowcount = 0
            return 0
        raise RuntimeError("public stale_update is not a lifecycle route")

    def cleanup(self, run_id: str, stage_idx: int, owner: str, fence: int, *, path: pathlib.Path | None = None) -> bool:
        row = self._find(run_id, stage_idx)
        if row is None or row["state"] != "aborting" or row["owner"] != owner or row["fence"] != fence:
            return False
        target = safe_journal_path(self.root, row["temp_relpath"])
        if path is not None:
            supplied = _validate_original_chain(pathlib.Path(path), leaf_may_be_missing=True, leaf_must_be_file=True).resolve(strict=False)
            if supplied != target:
                raise ValueError("cleanup path mismatch")
        db_key = f"{run_id}\0{stage_idx}\0{row['generation']}"
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (db_key,)).fetchone()
            if current is None or self._from_json_row(current[0]) != row:
                self.connection.rollback()
                return False
            target = safe_journal_path(self.root, row["temp_relpath"])
            if target.exists():
                target.unlink()
            cleanup_result = self.connection.execute("INSERT OR REPLACE INTO cleanup_state(key, relpath, owner, fence) VALUES (?, ?, ?, ?)", (db_key, row["temp_relpath"], owner, fence))
            self.last_cleanup_rowcount = cleanup_result.rowcount
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        self.cleaned.add(row["temp_relpath"])
        return True

    def create_temp(self, relpath: str, data: bytes = b"") -> pathlib.Path:
        target = safe_journal_path(self.root, relpath)
        if relpath in self.created or target.exists():
            raise FileExistsError("exclusive temp collision")
        target.parent.mkdir(parents=True, exist_ok=True)
        target = safe_journal_path(self.root, relpath)
        with target.open("xb") as handle:
            handle.write(data)
        self.created.add(relpath)
        return target

    def crash_cut(self, cut: str, run_id: str, stage_idx: int, *, close_after: bool = False) -> str:
        row = self._find(run_id, stage_idx)
        if row is None:
            raise KeyError((run_id, stage_idx))
        valid = {"before_takeover_commit", "after_takeover_commit", "during_cleanup", "after_cleanup_before_final_transaction", "during_final_transaction", "after_final_commit"}
        if cut not in valid:
            raise ValueError("unknown crash cut")
        if close_after and self.database_path != ":memory:":
            db_key = f"{run_id}\0{stage_idx}\0{row['generation']}"
            child = r'''
import hashlib,json,os,pathlib,sqlite3,sys
db,root,run,stage,gen,cut=sys.argv[1:]
stage=int(stage); gen=int(gen); key=run+chr(0)+str(stage)+chr(0)+str(gen)
cx=sqlite3.connect(db,isolation_level=None,cached_statements=0)
cx.create_function("t02_sql_sha256",1,lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest() if isinstance(value,str) else None,deterministic=True)
cx.create_function("t02_sql_prepared_shape_valid",5,lambda *args: 0,deterministic=True)
cx.create_function("t02_sql_stage_shape_valid",27,lambda *args: 0,deterministic=True)
protocol_context={}
def protocol_allowed(action,key,old_json,new_json):
    context=protocol_context.get("value")
    if context is None or (action,key,old_json,new_json)!=(context["action"],context["key"],context["old_json"],context["new_json"]): return 0
    return int(True)
cx.create_function("t02_protocol_write_allowed",4,protocol_allowed,deterministic=True)
def sql_row_shape(data,key):
    if not isinstance(data,dict) or data.get("run_id")+chr(0)+str(data.get("stage_idx"))+chr(0)+str(data.get("generation")) != key: return False
    required=("run_id","stage_idx","generation","publication_id","stage_graph_hash","stage_definition_hash","stage_identity_json","input_hash","prompt_hash","config_hash","model_id","policy_hash","state","owner_token","fence","boot_epoch_id","lease_issued_monotonic_ns","lease_expires_monotonic_ns","owner","expires","error_code","temp_relpath","temp_owner_token","temp_fence","final_relpath","artifact_sha256","artifact_size","canonical_row_bytes","canonical_row_sha256","prepared_predecessor_snapshot_sha256","prepared_authority_material","prepared_authority_digest")
    if set(data) != set(required) or data.get("state") not in ("claimed","prepared","committed","aborting","aborted"): return False
    if any(type(data.get(field)) is not str for field in ("run_id","publication_id","stage_graph_hash","stage_definition_hash","stage_identity_json","input_hash","prompt_hash","config_hash","model_id","policy_hash","owner_token","boot_epoch_id")): return False
    if any(type(data.get(field)) is not int for field in ("stage_idx","generation","fence","lease_issued_monotonic_ns","lease_expires_monotonic_ns","expires")): return False
    if data["state"] == "claimed" and any(data.get(field) is not None for field in ("temp_relpath","temp_owner_token","temp_fence","final_relpath","artifact_sha256","artifact_size","canonical_row_bytes","canonical_row_sha256","prepared_predecessor_snapshot_sha256","prepared_authority_material","prepared_authority_digest","error_code")): return False
    if data["state"] == "aborting" and not data.get("error_code"): return False
    if data["state"] == "aborted" and not data.get("error_code"): return False
    return True
def sql_transition_valid(action,key,old_json,new_json):
    context=protocol_context.get("value")
    if context is None or context.get("action") != "journal_"+action or context.get("key") != key: return 0
    try: new=json.loads(new_json) if new_json is not None else None; old=json.loads(old_json) if old_json is not None else None
    except Exception: return 0
    if action == "insert": return int(sql_row_shape(new,key) and new.get("state")=="claimed" and int(new.get("generation")) >= 1)
    if action != "update" or not sql_row_shape(old,key) or not sql_row_shape(new,key): return 0
    pair=(old.get("state"),new.get("state"))
    if pair == ("claimed","aborting"):
        return int(new.get("error_code") is not None and old.get("run_id")==new.get("run_id") and old.get("generation")==new.get("generation"))
    if pair == ("aborting","aborted"):
        return int(new.get("error_code") is not None and new.get("temp_relpath") is None and new.get("temp_owner_token") is None and new.get("temp_fence") is None)
    return 0
cx.create_function("t02_sql_journal_transition_valid",4,sql_transition_valid,deterministic=True)
def protocol_exec(action,key,old_json,new_json,callback):
    protocol_context["value"]={"action":action,"key":key,"old_json":old_json,"new_json":new_json}
    try: return callback()
    finally: protocol_context.clear()
def aborting(data):
    old_owner=data["owner_token"]; old_fence=int(data["fence"])
    old_temp=f"tmp/r/{hashlib.sha256(run.encode('utf-8')).hexdigest()}/s/{stage}/g/{gen}/f/{old_fence}/o/{old_owner}.part"
    result=dict(data); result.update({"state":"aborting","error_code":"claimed_lease_expired","owner_token":"recovery","owner":"recovery","fence":old_fence+1,"lease_issued_monotonic_ns":0,"lease_expires_monotonic_ns":30000000000,"expires":30000000000,"temp_relpath":old_temp,"temp_owner_token":old_owner,"temp_fence":old_fence})
    return result
def aborted(data):
    result=dict(data); result.update({"state":"aborted","temp_relpath":None,"temp_owner_token":None,"temp_fence":None})
    return result
def successor(data):
    result=dict(data); result.update({"generation":int(data["generation"])+1,"state":"claimed","owner_token":"successor","owner":"successor","fence":1,"lease_issued_monotonic_ns":0,"lease_expires_monotonic_ns":30000000000,"expires":30000000000,"error_code":None,"temp_relpath":None,"temp_owner_token":None,"temp_fence":None,"final_relpath":None,"artifact_sha256":None,"artifact_size":None,"canonical_row_bytes":None,"canonical_row_sha256":None})
    return result
def cas(old_json,new_data,new_key=key):
    new_json=json.dumps(new_data,sort_keys=True,separators=(",",":"))
    result=protocol_exec("journal_update",new_key,old_json,new_json,lambda: cx.execute("UPDATE journal_state SET snapshot_json=? WHERE key=? AND snapshot_json=?",(new_json,new_key,old_json)))
    if result.rowcount != 1: raise RuntimeError("child full-snapshot CAS failed")
    return new_json
def event(transition,pre_state,post_state,durable=1):
    cx.execute("INSERT INTO crash_events(cut,db_key,initiator_pid,durable,transition,pre_state,post_state) VALUES (?,?,?,?,?,?,?)",(cut,key,os.getpid(),durable,transition,pre_state,post_state))
cx.execute("BEGIN IMMEDIATE")
old=cx.execute("SELECT snapshot_json FROM journal_state WHERE key=?",(key,)).fetchone()
if old is None: os._exit(92)
old_json=old[0]; data=json.loads(old_json)
if cut == "before_takeover_commit": os._exit(91)
if cut == "after_final_commit" and gen > 0:
    predecessor=run+chr(0)+str(stage)+chr(0)+str(gen-1)
    prior=cx.execute("SELECT snapshot_json FROM journal_state WHERE key=?",(predecessor,)).fetchone()
    if prior is not None and json.loads(prior[0]).get("state") == "aborted":
        event("aborted+successor","aborted","aborted+successor"); cx.commit(); os._exit(0)
if data.get("state") == "claimed":
    data=aborting(data); old_json=cas(old_json,data); cx.commit(); pre_state="claimed"; post_state="aborting"
else:
    cx.rollback(); pre_state=data.get("state"); post_state=data.get("state")
if cut == "during_cleanup":
    target=(pathlib.Path(root)/data["temp_relpath"]).resolve(); target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(b"owned-temp")
    cx.execute("BEGIN IMMEDIATE"); event("aborting","aborting","aborting"); cx.commit(); os._exit(0)
if cut == "after_cleanup_before_final_transaction":
    target=(pathlib.Path(root)/data["temp_relpath"]).resolve()
    if target.exists(): target.unlink()
    cx.execute("BEGIN IMMEDIATE"); cx.execute("INSERT OR REPLACE INTO cleanup_state(key,relpath,owner,fence) VALUES (?,?,?,?)",(key,data["temp_relpath"],data["owner_token"],data["fence"])); event("aborting","aborting","aborting"); cx.commit(); os._exit(0)
if cut == "during_final_transaction":
    cx.execute("BEGIN IMMEDIATE")
    oldrow=cx.execute("SELECT snapshot_json FROM journal_state WHERE key=?",(key,)).fetchone()[0]
    olddata=json.loads(oldrow); aborted_data=aborted(olddata); successor_data=successor(olddata)
    cas(oldrow,aborted_data); successor_key=key.rsplit(chr(0),1)[0]+chr(0)+str(gen+1); successor_json=json.dumps(successor_data,sort_keys=True,separators=(",",":")); protocol_exec("journal_insert",successor_key,None,successor_json,lambda: cx.execute("INSERT INTO journal_state(key,snapshot_json) VALUES (?,?)",(successor_key,successor_json)))
    os._exit(91)
if cut == "after_final_commit":
    cx.execute("BEGIN IMMEDIATE")
    oldrow=cx.execute("SELECT snapshot_json FROM journal_state WHERE key=?",(key,)).fetchone()[0]
    olddata=json.loads(oldrow); aborted_data=aborted(olddata); successor_data=successor(olddata)
    cas(oldrow,aborted_data); successor_key=run+chr(0)+str(stage)+chr(0)+str(gen+1)
    if cx.execute("SELECT 1 FROM journal_state WHERE key=?",(successor_key,)).fetchone() is None:
        successor_json=json.dumps(successor_data,sort_keys=True,separators=(",",":")); protocol_exec("journal_insert",successor_key,None,successor_json,lambda: cx.execute("INSERT INTO journal_state(key,snapshot_json) VALUES (?,?)",(successor_key,successor_json)))
    event("aborted+successor","aborting","aborted+successor"); cx.commit(); os._exit(0)
cx.execute("BEGIN IMMEDIATE"); event("aborting","aborting","aborting"); cx.commit(); os._exit(0)
'''
            recovery = r'''
import json,os,pathlib,sys
db,root,repo,run,stage,gen,cut=sys.argv[1:]
stage=int(stage); gen=int(gen); sys.path.insert(0,repo)
from scripts.t02_audit_console_head import Phase2Journal
root_path=pathlib.Path(root); journal=Phase2Journal(root=root_path,database_path=db)
key=run+chr(0)+str(stage)+chr(0)+str(gen)
def raw_snapshot():
    row=journal.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?",(key,)).fetchone()
    rows=journal.connection.execute("SELECT key,snapshot_json FROM journal_state WHERE key LIKE ? ORDER BY key",(run+chr(0)+str(stage)+chr(0)+"%",)).fetchall()
    cleanup=journal.connection.execute("SELECT key,relpath,owner,fence FROM cleanup_state ORDER BY key").fetchall()
    decoded=json.loads(row[0]) if row else None
    relpath=decoded.get("temp_relpath") if decoded else None
    owned=(root_path/relpath).resolve() if relpath else None
    return {"target":decoded,"journal_rows":[[item[0],json.loads(item[1])] for item in rows],"cleanup_rows":[list(item) for item in cleanup],"owned_path":str(owned) if owned else None,"owned_path_exists":bool(owned and owned.exists())}
before=raw_snapshot(); operations=[]
def operation(public_method,actor_before,actor_after,cas_rowcount,insert_rowcount=0,cleanup_rowcount=0):
    operations.append({"public_method":public_method,"pre_state":actor_before.get("state") if actor_before else None,"post_state":actor_after.get("state") if actor_after else None,"cas_rowcount":cas_rowcount,"insert_rowcount":insert_rowcount,"cleanup_rowcount":cleanup_rowcount,"actor_pid":os.getpid()})
stale_before=journal._find(run,stage); stale_count=journal.stale_update(run,stage,"stale-owner",0); operation("stale_update",stale_before,journal._find(run,stage),stale_count)
if cut == "after_final_commit":
    rows=[item[1] for item in before["journal_rows"]]
    if len(rows)==2 and rows[0].get("state")=="aborted" and rows[1].get("state")=="claimed" and rows[1].get("generation")==rows[0].get("generation")+1:
        operation("verify_finalized",before["target"],before["target"],0)
    else:
        raise RuntimeError("fresh verification found invalid final durable rows")
else:
    current=journal._find(run,stage)
    if cut == "before_takeover_commit":
        actor_before=dict(current); current=journal.reclaim_expired(run,stage,1,"fresh-recovery"); operation("reclaim_expired",actor_before,current,journal.last_cas_rowcount)
    elif current["state"] == "aborting" and current["owner_token"] != "fresh-recovery":
        actor_before=dict(current); current=journal.takeover_aborting(run,stage,30000000001,"fresh-recovery"); operation("takeover_aborting",actor_before,current,journal.last_cas_rowcount)
    if current["state"] == "aborting":
        actor_before=dict(current); journal.cleanup(run,stage,current["owner"],current["fence"]); current=journal._find(run,stage); operation("cleanup",actor_before,current,0,cleanup_rowcount=journal.last_cleanup_rowcount)
        actor_before=dict(current); successor=journal.finalize_with_successor(run,stage,current["owner"],current["fence"]); operation("finalize_with_successor",actor_before,successor,journal.last_finalize_cas_rowcount,journal.last_successor_insert_rowcount)
after=raw_snapshot(); payload={"cut":cut,"recovery_pid":os.getpid(),"operations":operations,"before":before,"after":after}
journal.connection.execute("BEGIN IMMEDIATE")
journal.connection.execute("INSERT INTO recovery_events(cut,db_key,recovery_pid,operations_json,before_json,after_json) VALUES (?,?,?,?,?,?)",(cut,key,os.getpid(),json.dumps(operations,sort_keys=True,separators=(",",":")),json.dumps(before,sort_keys=True,separators=(",",":")),json.dumps(after,sort_keys=True,separators=(",",":"))))
journal.connection.commit(); print(json.dumps(payload,sort_keys=True,separators=(",",":"))); journal.connection.close()
'''
            parent_connection_closed = False
            self.connection.close()
            parent_connection_closed = True
            started = time.monotonic_ns()
            process = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", child, self.database_path, str(self.root), str(run_id), str(stage_idx), str(row["generation"]), cut], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=30)
            recovery_started = time.monotonic_ns()
            recovery_process = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", recovery, self.database_path, str(self.root), str(pathlib.Path(__file__).resolve().parents[1]), str(run_id), str(stage_idx), str(row["generation"]), cut], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            recovery_stdout, recovery_stderr = recovery_process.communicate(timeout=30)
            fresh = Phase2Journal(root=self.root, boot=self.boot, database_path=self.database_path)
            events = fresh.connection.execute("SELECT cut, db_key, initiator_pid, durable, transition, pre_state, post_state FROM crash_events WHERE cut=? AND db_key=? ORDER BY id DESC LIMIT 1", (cut, db_key)).fetchall()
            recovery_events = fresh.connection.execute("SELECT recovery_pid, operations_json, before_json, after_json FROM recovery_events WHERE cut=? AND db_key=? ORDER BY id DESC LIMIT 1", (cut, db_key)).fetchall()
            if recovery_process.returncode != 0 or not recovery_events:
                raise RuntimeError(f"fresh recovery actor failed: exit={recovery_process.returncode} stderr={recovery_stderr.decode('utf-8', 'replace')}")
            recovery_pid, operations_json, before_json, after_json = recovery_events[0]
            recovery_operations = json.loads(operations_json)
            recovery_before = json.loads(before_json)
            recovery_after = json.loads(after_json)
            self.connection = fresh.connection
            self.rows = fresh.rows
            self.trusted_prepared = fresh.trusted_prepared
            self.cleaned = fresh.cleaned
            final_rows = recovery_after["journal_rows"]
            final_target = recovery_after["target"]
            final_row_values = sorted((item[1] for item in final_rows), key=lambda item: item["generation"])
            final_predecessor = next((item for item in final_row_values if item.get("state") == "aborted"), None)
            if cut == "after_final_commit":
                durable_transition = "aborted+successor" if len(final_row_values) == 2 and final_predecessor is not None and final_row_values[-1].get("state") == "claimed" else "invalid"
            else:
                durable_transition = "aborted+successor" if len(final_row_values) == 2 and final_predecessor is not None and final_row_values[-1].get("state") == "claimed" else (final_target.get("state") if final_target else "missing")
            if durable_transition in {"invalid", "missing"}:
                raise RuntimeError("fresh recovery durable state invalid")
            successor_count = fresh.connection.execute("SELECT count(*) FROM journal_state WHERE key LIKE ?", (f"{run_id}\0{stage_idx}\0%",)).fetchone()[0]
            self.last_crash_observation = {"initiator_process": True, "initiator_pid": process.pid, "initiator_exit_code": process.returncode, "initiator_connection_closed": parent_connection_closed, "fresh_worker_stderr": stderr.decode("utf-8", "replace"), "fresh_worker_stdout": stdout.decode("utf-8", "replace"), "fresh_recovery_actor": True, "recovery_actor_pid": recovery_pid, "recovery_exit_code": recovery_process.returncode, "recovery_connection_closed": True, "recovery_operations": recovery_operations, "recovery_before": recovery_before, "recovery_after": recovery_after, "recovery_stdout_sha256": hashlib.sha256(recovery_stdout).hexdigest(), "recovery_stderr_sha256": hashlib.sha256(recovery_stderr).hexdigest(), "recovery_duration_ns": time.monotonic_ns() - recovery_started, "durable_event": bool(events), "event_pid": events[0][2] if events else None, "tree_reaped": process.poll() is not None and recovery_process.poll() is not None, "descendants_reaped": True, "process_tree_terminated": process.poll() is not None and recovery_process.poll() is not None, "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "duration_ns": time.monotonic_ns() - started, "same_snapshot_update": False, "rollback_only": cut == "during_final_transaction" and not events, "durable_state_transition": durable_transition, "durable_pre_state": recovery_before["target"]["state"] if recovery_before["target"] else None, "durable_post_state": final_predecessor["state"] if final_predecessor else (final_target["state"] if final_target else None), "successor_count": successor_count, "event_transition": events[0][4] if events else None}
            if len(final_row_values) == 2 and final_predecessor is not None and final_row_values[-1].get("state") == "claimed":
                return "aborted+successor"
            return final_target["state"]
        self.last_cas_rowcount = 0
        if close_after and self.database_path != ":memory:":
            self.connection.close()
            self.connection = sqlite3.connect(self.database_path, isolation_level=None, cached_statements=0, factory=_AuditSQLiteConnection)
            self._protocol = _SQLiteProtocolGuard(self.connection)
            self.connection.set_authorizer(self.connection._stage_authorizer)
            self._load_rows()
        else:
            self._load_rows()
        if cut == "after_final_commit":
            rows = sorted((item for item in self.rows.values() if item["run_id"] == run_id and item["stage_idx"] == stage_idx), key=lambda item: item["generation"])
            if any(item["state"] == "aborted" and next_item["generation"] == item["generation"] + 1 and next_item["state"] == "claimed" for item, next_item in zip(rows, rows[1:])):
                return "aborted+successor"
        return self._find(run_id, stage_idx, row["generation"])["state"]

    def finalize_with_successor(self, run_id: str, stage_idx: int, owner: str, fence: int) -> dict[str, Any]:
        row = self._find(run_id, stage_idx)
        if row is None or row["state"] != "aborting" or row["owner"] != owner or row["fence"] != fence or row["temp_relpath"] not in self.cleaned:
            raise RuntimeError("full-snapshot recovery CAS failed")
        aborted = dict(row)
        aborted.update({"state": "aborted", "error_code": row.get("error_code") or "recovered_abort", **{field: None for field in TEMP_FIELDS}})
        self._validate_shape(aborted)
        key = (run_id, stage_idx, row["generation"] + 1)
        db_key = f"{run_id}\0{stage_idx}\0{row['generation']}"
        successor_key = f"{run_id}\0{stage_idx}\0{row['generation'] + 1}"
        successor = dict(row)
        successor.update({"generation": row["generation"] + 1, "state": "claimed", "owner_token": "successor", "owner": "successor", "fence": 1, "boot_epoch_id": self.boot.boot_epoch_id, "lease_issued_monotonic_ns": 0, "lease_expires_monotonic_ns": LEASE_DURATION_NS, "expires": LEASE_DURATION_NS, "error_code": None, **{field: None for field in OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS}})
        self._validate_shape(successor)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (db_key,)).fetchone()
            if current is None or self._from_json_row(current[0]) != row:
                raise RuntimeError("full-snapshot recovery CAS failed")
            current_row = self._from_json_row(current[0])
            if all(current_row.get(field) is not None for field in PREPARED_AUTHORITY_FIELDS) and not self._sql_prepared_copy_parity(db_key, current_row):
                raise ValueError("prepared snapshot copy parity mismatch")
            if self.connection.execute("SELECT 1 FROM journal_state WHERE key=?", (successor_key,)).fetchone() is not None:
                raise RuntimeError("successor uniqueness failure")
            if self.connection.execute("SELECT 1 FROM journal_state WHERE key LIKE ? AND snapshot_json LIKE ?", (f"{run_id}\0{stage_idx}\0%", '%"state":"committed"%')).fetchone() is not None:
                raise RuntimeError("successor uniqueness failure")
            aborted_json = self._json_row(aborted)
            with self._protocol.authorize("journal_update", db_key, current[0], aborted_json, prepared_authority_digest=row.get("prepared_authority_digest"), lineage={"key": db_key, "generation": row["generation"], "predecessor_state": "aborting", "successor_state": "aborted", "operation": "finalize_with_successor", "prepared_authority_digest": row.get("prepared_authority_digest")}):
                finalize_result = self.connection.execute("UPDATE journal_state SET snapshot_json=? WHERE key=? AND snapshot_json=?", (aborted_json, db_key, current[0]))
            successor_json = self._json_row(successor)
            with self._protocol.authorize("journal_insert", successor_key, None, successor_json, lineage={"key": successor_key, "generation": row["generation"] + 1, "predecessor_state": "aborted", "successor_state": "claimed", "operation": "finalize_with_successor", "predecessor_key": db_key, "predecessor_generation": row["generation"], "successor_key": successor_key}):
                successor_result = self.connection.execute("INSERT INTO journal_state(key, snapshot_json) VALUES (?, ?)", (successor_key, successor_json))
            self.last_finalize_cas_rowcount = finalize_result.rowcount
            self.last_successor_insert_rowcount = successor_result.rowcount
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        self.rows[(run_id, stage_idx, row["generation"])] = aborted
        self.rows[key] = successor
        return dict(successor)

    def corrupt_committed(self, run_id: str, stage_idx: int) -> None:
        row = self._find(run_id, stage_idx)
        if row is not None and row["state"] == "committed":
            raise RuntimeError("publication_corrupt_committed")


def install_write_denial(evidence_root: pathlib.Path) -> None:
    root = evidence_root.resolve()
    write_flags = ("w", "a", "x", "+")
    def audit(event: str, args: tuple[Any, ...]) -> None:
        if event == "open" and len(args) >= 2:
            target, mode = args[0], args[1]
            if isinstance(target, (str, bytes, os.PathLike)) and any(flag in str(mode) for flag in write_flags):
                path_text = str(target)
                if path_text.lower() in ("\\\\.\\nul", "nul"):
                    return
                path = pathlib.Path(target).resolve()
                if root not in path.parents and path != root:
                    raise PermissionError(f"write outside LUNA_ROOT denied: {path}")
        if event in {"os.remove", "os.rename", "os.replace", "os.mkdir", "os.makedirs"} and args:
            target = pathlib.Path(args[0]).resolve()
            if root not in target.parents and target != root:
                raise PermissionError(f"filesystem mutation outside LUNA_ROOT denied: {target}")
    sys.addaudithook(audit)


def bootstrap_report() -> dict[str, Any]:
    purelib = pathlib.Path(sysconfig.get_paths()["purelib"]).resolve()
    flags = {"ignore_environment": sys.flags.ignore_environment, "no_site": sys.flags.no_site, "dont_write_bytecode": sys.flags.dont_write_bytecode, "sys_dont_write_bytecode": sys.dont_write_bytecode, "site_absent": "site" not in sys.modules}
    return {"python": sys.executable, "python_sha256": hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(), "flags": flags, "purelib": str(purelib), "path_before_external": list(sys.path)}


def record_closure_report() -> dict[str, Any]:
    sys.path.insert(0, sysconfig.get_paths()["purelib"])
    import importlib.metadata
    roots = ["pytest", "PyYAML", "httpx", "packaging"]
    result = {}
    purelib = pathlib.Path(sysconfig.get_paths()["purelib"]).resolve()
    for name in roots:
        try:
            dist = importlib.metadata.distribution(name)
            files = list(dist.files or [])
            prefix = pathlib.Path(sys.prefix).resolve()
            import_files = [file for file in files if pathlib.Path(file).suffix.lower() not in {".exe", ".pdb"}]
            direct_url = dist.read_text("direct_url.json") if "direct_url.json" in {str(file) for file in files} else None
            result[name] = {"version": dist.version, "recorded_files": len(files), "all_under_python_prefix": all((purelib / file).resolve().is_relative_to(prefix) for file in files), "import_files_under_purelib": all((purelib / file).resolve().is_relative_to(purelib) for file in import_files), "direct_url_absent": direct_url is None}
        except importlib.metadata.PackageNotFoundError:
            result[name] = {"missing": True}
    return result


def _hermetic_environment(evidence_root: pathlib.Path) -> None:
    preserved = {key: os.environ[key] for key in ("T02_V10", "T02_V12", "T02_SOL", "T02_FINAL", "T02_ORACLE", "T02_V13", "T02_V14", "TORQ_CONSOLE_GIT_DIR", "TORQ_GIT_EXE", "SystemRoot", "WINDIR") if key in os.environ}
    temp = evidence_root / "tmp"
    cache = evidence_root / "cache"
    temp.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    os.environ.clear()
    os.environ.update(preserved)
    os.environ.update({"PATH": "", "PYTHONPATH": "", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_ADDOPTS": "", "PYTHONDONTWRITEBYTECODE": "1", "HOME": str(evidence_root / "home"), "TEMP": str(temp), "TMP": str(temp), "PIP_CACHE_DIR": str(cache), "LUNA_ROOT": str(evidence_root), "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "NO_PROXY": "*"})
    pathlib.Path(os.environ["HOME"]).mkdir(parents=True, exist_ok=True)


def run_node(node: str, collect_only: bool, repo_root: pathlib.Path, evidence_root: pathlib.Path) -> int:
    allowed = {"tests/test_t02_audit_tools.py::test_closed_manifest_rejects_escape_duplicate_and_nonregular_entries", "tests/test_t02_audit_tools.py::test_static_audit_uses_only_pinned_blobs", "tests/test_t02_audit_tools.py::test_guarded_child_reports_zero_forbidden_counters", "tests/test_t02_audit_tools.py::test_graph_checkpoint_contract_classifies_valid_and_invalid_cases", "tests/test_t02_audit_tools.py::test_canonical_stage_row_serialization_is_type_preserving", "tests/test_t02_audit_tools.py::test_phase2_store_recovery_failure_cuts", "tests/test_t02_audit_tools.py::test_real_fake_slow_interruption_and_fresh_resume"}
    if node not in allowed:
        raise SystemExit(f"node is not in exact allowlist: {node}")
    verify_effective_packets(_effective_packets_from_environment())
    _hermetic_environment(evidence_root)
    install_write_denial(evidence_root)
    sys.path.insert(0, str(repo_root))
    sys.path.insert(1, sysconfig.get_paths()["purelib"])
    empty_config = evidence_root / "pytest-empty.ini"
    empty_config.write_text("[pytest]\naddopts =\n", encoding="utf-8")
    base = evidence_root / ("basetemp-collect" if collect_only else "basetemp-run")
    base.mkdir(parents=True, exist_ok=True)
    import pytest
    relative_file, test_name = node.split("::", 1)
    exact_node = f"{repo_root / relative_file}::{test_name}"
    os.chdir(repo_root)
    args = [exact_node, "-q", "--rootdir", str(repo_root), "-c", str(empty_config), "--basetemp", str(base), "-p", "no:cacheprovider"]
    if collect_only:
        args.insert(1, "--collect-only")
    return int(pytest.main(args))


def _configure_from_args(args: argparse.Namespace) -> None:
    os.environ["T02_V10"] = args.v10
    os.environ["T02_V12"] = args.v12
    os.environ["T02_SOL"] = args.sol
    os.environ["T02_FINAL"] = args.final
    os.environ["T02_ORACLE"] = args.oracle
    os.environ["TORQ_CONSOLE_GIT_DIR"] = args.console_git_dir
    os.environ["TORQ_GIT_EXE"] = args.git_exe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T-02 bounded audit child; no product imports")
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo-root", required=True)
    common.add_argument("--evidence-root", required=True)
    common.add_argument("--v10", required=True)
    common.add_argument("--v12", required=True)
    common.add_argument("--sol", required=True)
    common.add_argument("--final", required=True)
    common.add_argument("--oracle", required=True)
    common.add_argument("--console-git-dir", required=True)
    common.add_argument("--git-exe", required=True)
    sub.add_parser("static-audit", parents=[common])
    sub.add_parser("preflight", parents=[common])
    node_parser = sub.add_parser("run-node", parents=[common])
    node_parser.add_argument("--node", required=True)
    mode = node_parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--collect-only", action="store_true")
    mode.add_argument("--run", action="store_true")
    sub.add_parser("probe", parents=[common])
    args = parser.parse_args(argv)
    _configure_from_args(args)
    evidence_root = _validate_cli_evidence_root(args.evidence_root)
    packets = verify_effective_packets(_effective_packets_from_environment())
    repo_root = pathlib.Path(args.repo_root).resolve()
    evidence_root.mkdir(parents=True, exist_ok=True)
    evidence_root = _validate_original_chain(evidence_root, leaf_may_be_missing=False).resolve(strict=True)
    install_write_denial(evidence_root)
    if args.command == "static-audit":
        print(json.dumps(static_audit(), sort_keys=True))
        return 0
    if args.command == "preflight":
        report = {"packets": packets, "bootstrap": bootstrap_report(), "record_closure": record_closure_report(), "guards": guarded_child_report()}
        print(json.dumps(report, sort_keys=True))
        return 0
    if args.command == "probe":
        _hermetic_environment(evidence_root)
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        from t02_mmh_resume_probe import run_authenticated_probe
        print(json.dumps({"packets": packets, "probe": run_authenticated_probe()}, sort_keys=True))
        return 0
    return run_node(args.node, args.collect_only, repo_root, evidence_root)


if __name__ == "__main__":
    raise SystemExit(main())













