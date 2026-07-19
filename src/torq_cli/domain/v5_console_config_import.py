"""Bounded, source-free adapter for the sanitized Console V5 YAML contract."""

from __future__ import annotations

import base64
import binascii
import datetime as _datetime
import json
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

import yaml
from yaml import events, nodes

MAX_BYTES = 65_536
MAX_EVENTS = 1_024
MAX_DEPTH = 8
TARGET_SHA256 = "63ffadbe88e6b04ac732d5a282e27e0af1a2bbd80f89412ad1a4364e01a3650e"

_STR_TAG = "tag:yaml.org,2002:str"
_INT_TAG = "tag:yaml.org,2002:int"
_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"
_FLOAT_TAG = "tag:yaml.org,2002:float"
_COST_RE = re.compile(r"^[0-9]{1,7}\.[0-9]{2}$", re.ASCII)
_DRIVE_RE = re.compile(r"^[A-Za-z]:", re.ASCII)
_PATH_CONFUSABLES = frozenset("∕⁄⧸／＼﹨．․")
_PATH_ALLOWLIST = frozenset(
    {
        "artifacts/00_input/prd.md",
        "artifacts/01_design/build_spec.md",
        "artifacts/01_design/design_questions.md",
        "artifacts/01_design/gate1_review.md",
        "artifacts/02_build/build_result.md",
        "artifacts/03_audit/audit_report.md",
        "artifacts/04_refine/bug_refinement.md",
        "artifacts/04_refine/ui_refinement.md",
    }
)
_EXPECTED_ROLES = ("g1d", "g1r", "builder", "g2a", "refine_bug", "refine_ui")
_RAW_AGENTS: dict[str, dict[str, str]] = {
    "g1d": {"role": "Gate 1 Design Authority", "model": "claude-fable-5", "cli": "claude-sub", "prompt": "prompts/gate1_design.md"},
    "g1r": {"role": "Gate 1 Adversarial Review", "model": "claude-opus-4-7", "cli": "claude-sub", "prompt": "prompts/gate1_review.md"},
    "builder": {"role": "Builder", "model": "deepseek-v4-pro", "cli": "claude-deepseek", "prompt": "prompts/builder.md", "endpoint": "https://api.deepseek.com/anthropic"},
    "g2a": {"role": "Gate 2 Build Authority / Audit", "model": "claude-opus-4-7", "cli": "claude-sub", "prompt": "prompts/gate2_audit.md"},
    "refine_bug": {"role": "Bug / Race / Self-correction refinement", "model": "kimi-k3", "cli": "claude-kimi", "prompt": "prompts/refine_bug.md", "endpoint": "https://api.moonshot.ai/anthropic/"},
    "refine_ui": {"role": "UI polish refinement", "model": "glm-5.2", "cli": "claude-zai", "prompt": "prompts/refine_ui.md", "endpoint": "https://api.z.ai/api/anthropic"},
}
_ORACLE_AGENTS: dict[str, dict[str, str | None]] = {
    "g1d": {"role_id": "g1d", "model": "claude-opus-4-7", "cli": "claude-sub", "prompt": "prompts/gate1_design.md", "endpoint": None},
    "g1r": {"role_id": "g1r", "model": "claude-opus-4-7", "cli": "claude-sub", "prompt": "prompts/gate1_review.md", "endpoint": None},
    "builder": {"role_id": "builder", "model": "deepseek-v4-pro", "cli": "claude-deepseek", "prompt": "prompts/builder.md", "endpoint": "https://api.deepseek.com/anthropic"},
    "g2a": {"role_id": "g2a", "model": "claude-opus-4-7", "cli": "claude-sub", "prompt": "prompts/gate2_audit.md", "endpoint": None},
    "refine_bug": {"role_id": "refine_bug", "model": "kimi-k2.7-code", "cli": "claude-kimi", "prompt": "prompts/refine_bug.md", "endpoint": "https://api.moonshot.ai/anthropic/"},
    "refine_ui": {"role_id": "refine_ui", "model": "glm-5.2", "cli": "claude-zai", "prompt": "prompts/refine_ui.md", "endpoint": "https://api.z.ai/api/anthropic"},
}
_EXPECTED_STATE_STATES = (
    "ready", "design_complete", "gate1_passed", "design_revision_needed", "build_complete",
    "build_revision_needed", "refine_needed", "complete", "human_escalation",
)
_EXPECTED_ROUTING = {
    "architecture_issue": "builder", "bug_or_race": "refine_bug", "ui_polish": "refine_ui",
    "spec_is_wrong": "g1d", "ambiguous": "human_escalation",
}
_EXPECTED_CRITERIA = ("rejection_count", "wall_clock", "cost", "post_push_issues")
_DENIED_KEYS = frozenset(
    {
        "api_key", "apikey", "api_token", "x_api_key", "access_token", "auth_token",
        "authorization", "bearer_token", "refresh_token", "id_token", "session_token",
        "token", "password", "passphrase", "secret", "secret_key", "client_secret",
        "credential", "credentials", "private_key", "ssh_private_key", "cookie", "cookies",
        "set_cookie", "openai_api_key", "anthropic_api_key", "deepseek_api_key",
        "moonshot_api_key", "kimi_api_key", "zai_api_key", "glm_api_key",
    }
)
_PEM_RE = re.compile(
    r"-----BEGIN (?:PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|DSA PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----"
)
_AUTH_RE = re.compile(
    r"(?<![A-Za-z0-9._~+/-])(?:Bearer|Basic)[ \t]+[A-Za-z0-9._~+/-]{8,512}(?![A-Za-z0-9._~+/-])",
    re.ASCII | re.IGNORECASE,
)
_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:sk[-_]|rk_|ghp_|github_pat_)[A-Za-z0-9_-]{16,256}(?![A-Za-z0-9_-])",
    re.ASCII,
)
_AKIA_RE = re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])", re.ASCII)
_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:authorization|proxy-authorization|cookie|set-cookie)[ \t]*[:=][ \t]*[^\x00-\x20]{8,512}",
    re.ASCII | re.IGNORECASE,
)
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{8,4096}={0,2}\.[A-Za-z0-9_-]{8,4096}={0,2}\.[A-Za-z0-9_-]{8,4096}={0,2})(?![A-Za-z0-9_-])",
    re.ASCII,
)
_URL_RE = re.compile(r"https?://[^\x00-\x20<>\"']{1,4096}", re.ASCII | re.IGNORECASE)
_HOST_LABEL_RE = re.compile(rb"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)
_PORT_RE = re.compile(rb"[1-9][0-9]{0,4}\Z", re.ASCII)
_SIGNED_QUERY_NAMES = frozenset(
    {"signature", "sig", "x_amz_signature", "x_goog_signature", "token", "access_token", "api_key", "x_api_key"}
)
_HEX = frozenset(b"0123456789abcdefABCDEF")


class ConsoleSyntaxError(ValueError):
    """The YAML stream violates a parser-policy rule."""


class ConsoleSchemaError(ValueError):
    """The constructed document violates the closed source schema."""


def _path_for(key: str) -> str:
    return "/" + key.replace("~", "~0").replace("/", "~1")


def _scalar_tag(node: Any, path: str) -> None:
    tag = getattr(node, "tag", None)
    value = getattr(node, "value", "")
    expected = _STR_TAG
    if path == "/version":
        expected = _INT_TAG
        if value != "5":
            raise ConsoleSyntaxError()
    elif path == "/created":
        expected = _TIMESTAMP_TAG
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value, re.ASCII):
            raise ConsoleSyntaxError()
        try:
            _datetime.date.fromisoformat(value)
        except ValueError as exc:
            raise ConsoleSyntaxError() from exc
    elif path.startswith("/cost_guardrails/"):
        expected = _FLOAT_TAG
        if not _COST_RE.fullmatch(value):
            raise ConsoleSyntaxError()
    if tag != expected:
        raise ConsoleSyntaxError()


def _node_walk(node: Any, path: str = "", level: int = 0) -> None:
    if isinstance(node, nodes.MappingNode):
        if level > MAX_DEPTH:
            raise ConsoleSyntaxError()
        identities: set[str] = set()
        for key_node, value_node in node.value:
            if not isinstance(key_node, nodes.ScalarNode) or key_node.tag != _STR_TAG:
                raise ConsoleSyntaxError()
            identity = unicodedata.normalize("NFC", key_node.value)
            if identity in identities:
                raise ConsoleSyntaxError()
            identities.add(identity)
            child = _path_for(key_node.value) if not path else f"{path}{_path_for(key_node.value)}"
            _node_walk(value_node, child, level + 1)
        return
    if isinstance(node, nodes.SequenceNode):
        if level > MAX_DEPTH:
            raise ConsoleSyntaxError()
        for index, item in enumerate(node.value):
            _node_walk(item, f"{path}/{index}", level + 1)
        return
    if isinstance(node, nodes.ScalarNode):
        _scalar_tag(node, path)
        return
    raise ConsoleSyntaxError()


def preflight_console_yaml(raw: bytes) -> None:
    """Reject unsafe YAML constructs before any Python value is constructed."""
    if len(raw) > MAX_BYTES or raw.startswith(b"\xef\xbb\xbf"):
        raise ConsoleSyntaxError()
    count = 0
    try:
        for event in yaml.parse(raw, Loader=yaml.SafeLoader):
            if not isinstance(event, (events.StreamStartEvent, events.StreamEndEvent)):
                count += 1
            if count > MAX_EVENTS:
                raise ConsoleSyntaxError()
            if isinstance(event, events.AliasEvent) or getattr(event, "anchor", None) is not None:
                raise ConsoleSyntaxError()
            if getattr(event, "tag", None) is not None:
                raise ConsoleSyntaxError()
        documents = list(yaml.compose_all(raw, Loader=yaml.SafeLoader))
    except ConsoleSyntaxError:
        raise
    except (UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
        raise ConsoleSyntaxError() from exc
    if len(documents) != 1 or documents[0] is None or not isinstance(documents[0], nodes.MappingNode):
        raise ConsoleSyntaxError()
    _node_walk(documents[0])


def construct_console_yaml(raw: bytes) -> Mapping[str, Any]:
    """Construct only after ``preflight_console_yaml`` has completed."""
    try:
        loader = yaml.SafeLoader(raw)
        try:
            document = loader.get_single_data()
        finally:
            loader.dispose()  # type: ignore[no-untyped-call]
    except (UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
        raise ConsoleSyntaxError() from exc
    if not isinstance(document, Mapping):
        raise ConsoleSyntaxError()
    return document


def _control_free(value: str) -> bool:
    return not any(unicodedata.category(character) == "Cc" for character in value)


def _valid_path(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        return False
    if not 1 <= len(encoded) <= 64 or any(byte < 0x20 or byte == 0x7F for byte in encoded):
        return False
    if _DRIVE_RE.match(value) or value.startswith("/") or value.startswith("//"):
        return False
    if any(character in value for character in ("%", "\\", ":")) or "//" in value:
        return False
    segments = value.split("/")
    if any(not segment or segment in {".", ".."} for segment in segments):
        return False
    if any(character in _PATH_CONFUSABLES for character in value):
        return False
    return value in _PATH_ALLOWLIST


def _valid_sequence_paths(value: Any) -> bool:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        return False
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or item in seen or not _valid_path(item):
            return False
        seen.add(item)
    return True


def _valid_agent(agent_id: str, value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    expected = {"role", "model", "cli", "prompt", "reads", "writes"}
    if agent_id in {"builder", "refine_ui"}:
        expected.add("endpoint")
    if agent_id == "refine_bug":
        expected.update({"endpoint", "notes"})
    if set(value) != expected:
        return False
    if not all(isinstance(value.get(key), str) for key in ("role", "model", "cli", "prompt")):
        return False
    if value.get("role") != _RAW_AGENTS[agent_id]["role"]:
        return False
    if "endpoint" in expected and not isinstance(value.get("endpoint"), str):
        return False
    if not _valid_sequence_paths(value.get("reads")) or not _valid_sequence_paths(value.get("writes")):
        return False
    if agent_id == "refine_bug":
        notes = value.get("notes")
        if not isinstance(notes, str) or not notes or len(notes) > 512 or not _control_free(notes):
            return False
    return True


def validate_console_schema(document: Mapping[str, Any]) -> bool:
    """Validate the closed raw source grammar after safe construction."""
    if set(document) != {
        "version", "created", "supersedes", "agents", "state_machine", "rejection_routing",
        "cost_guardrails", "success_criteria",
    }:
        return False
    if type(document.get("version")) is not int or document["version"] != 5:
        return False
    if not isinstance(document.get("created"), _datetime.date) or isinstance(document["created"], _datetime.datetime):
        return False
    if document.get("supersedes") != "v4":
        return False
    agents = document.get("agents")
    if not isinstance(agents, Mapping) or set(agents) != set(_EXPECTED_ROLES):
        return False
    if any(not _valid_agent(role, agents[role]) for role in _EXPECTED_ROLES):
        return False
    state_machine = document.get("state_machine")
    if not isinstance(state_machine, Mapping) or set(state_machine) != {"states"}:
        return False
    if state_machine.get("states") != list(_EXPECTED_STATE_STATES):
        return False
    if document.get("rejection_routing") != _EXPECTED_ROUTING:
        return False
    costs = document.get("cost_guardrails")
    if not isinstance(costs, Mapping) or set(costs) != {"max_cost_per_prd_usd", "alert_threshold_usd"}:
        return False
    maximum = costs.get("max_cost_per_prd_usd")
    threshold = costs.get("alert_threshold_usd")
    if type(maximum) is not float or type(threshold) is not float:
        return False
    if not math.isfinite(maximum) or not math.isfinite(threshold):
        return False
    if not 0.0 <= threshold <= maximum <= 1_000_000.0:
        return False
    criteria = document.get("success_criteria")
    if not isinstance(criteria, list) or len(criteria) != len(_EXPECTED_CRITERIA):
        return False
    for item, key in zip(criteria, _EXPECTED_CRITERIA):
        if not isinstance(item, Mapping) or list(item) != [key] or not isinstance(item[key], str):
            return False
        if not item[key] or len(item[key]) > 256 or not _control_free(item[key]):
            return False
    return True


def _normalize_secret_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold().replace("-", "_")


def _percent_decode(value: bytes) -> str:
    output = bytearray()
    index = 0
    while index < len(value):
        byte = value[index]
        if byte == ord("%"):
            if index + 2 >= len(value) or value[index + 1] not in _HEX or value[index + 2] not in _HEX:
                raise ValueError()
            output.append(int(value[index + 1:index + 3], 16))
            index += 3
        else:
            output.append(byte)
            index += 1
    return bytes(output).decode("utf-8", errors="strict")


def _signed_url_candidate(candidate: str) -> bool:
    try:
        raw = candidate.encode("ascii", errors="strict")
        scheme, remainder = raw.split(b"://", 1)
        if scheme.lower() not in {b"http", b"https"}:
            return True
        first_delimiter = len(remainder)
        for delimiter in (b"/", b"?", b"#"):
            position = remainder.find(delimiter)
            if position >= 0:
                first_delimiter = min(first_delimiter, position)
        authority = remainder[:first_delimiter]
        if not authority or b"@" in authority or b"[" in authority or b"]" in authority:
            return True
        if authority.count(b":") > 1:
            return True
        if b":" in authority:
            host, port = authority.split(b":", 1)
            if not _PORT_RE.fullmatch(port) or not 1 <= int(port) <= 65_535:
                return True
        else:
            host = authority
        if not 1 <= len(host) <= 253 or not all(_HOST_LABEL_RE.fullmatch(label) for label in host.split(b".")):
            return True
        rest = remainder[first_delimiter:]
        fragment = rest.find(b"#")
        without_fragment = rest if fragment < 0 else rest[:fragment]
        question = without_fragment.find(b"?")
        if question < 0:
            return False
        path = without_fragment[:question]
        if path and not path.startswith(b"/"):
            return True
        query = without_fragment[question + 1:]
        if not query:
            return False
        components = query.split(b"&")
        if any(not component for component in components):
            return True
        for component in components:
            if b"=" in component:
                name_bytes, value_bytes = component.split(b"=", 1)
            else:
                name_bytes, value_bytes = component, None
            name = _percent_decode(name_bytes)
            if value_bytes is None:
                continue
            value = _percent_decode(value_bytes)
            if value and _normalize_secret_key(name) in _SIGNED_QUERY_NAMES:
                return True
        return False
    except (UnicodeDecodeError, ValueError, UnicodeError):
        return True


def _jwt_candidate_is_secret(value: str) -> bool:
    for match in _JWT_RE.finditer(value):
        candidate = match.group(1)
        if match.end() < len(value) and value[match.end()] == "=":
            continue
        parts = candidate.split(".")
        decoded: list[Any] = []
        valid = True
        for part in parts[:2]:
            padding = len(part) - len(part.rstrip("="))
            if padding > 2:
                valid = False
                break
            unpadded = part.rstrip("=")
            if len(unpadded) % 4 == 1:
                valid = False
                break
            padded = unpadded + "=" * ((4 - len(unpadded) % 4) % 4)
            try:
                decoded.append(json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", errors="strict")))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error):
                valid = False
                break
        if valid and isinstance(decoded[0], Mapping) and isinstance(decoded[1], Mapping):
            if isinstance(decoded[0].get("alg"), str) and decoded[0]["alg"]:
                return True
    return False


def _scalar_has_secret(value: str) -> bool:
    if _PEM_RE.search(value) is not None:
        return True
    if _AUTH_RE.search(value) is not None:
        return True
    if _TOKEN_RE.search(value) is not None or _AKIA_RE.search(value) is not None:
        return True
    if _ASSIGNMENT_RE.search(value) is not None:
        return True
    if _jwt_candidate_is_secret(value):
        return True
    return any(_signed_url_candidate(match.group(0)) for match in _URL_RE.finditer(value))


def contains_console_secret(value: Any) -> bool:
    """Scan values in insertion order without retaining or returning matched text."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and _normalize_secret_key(key) in _DENIED_KEYS:
                return True
            if contains_console_secret(item):
                return True
        return False
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(contains_console_secret(item) for item in value)
    return isinstance(value, str) and _scalar_has_secret(value)


def _oracle_agents(reference: Mapping[str, Any]) -> dict[str, Mapping[str, Any]] | None:
    raw_agents = reference.get("agents")
    if not isinstance(raw_agents, list) or len(raw_agents) != len(_EXPECTED_ROLES):
        return None
    result: dict[str, Mapping[str, Any]] = {}
    for item in raw_agents:
        if not isinstance(item, Mapping) or set(item) != {"role_id", "cli", "endpoint", "model", "prompt"}:
            return None
        role_id = item.get("role_id")
        if not isinstance(role_id, str) or role_id in result:
            return None
        result[role_id] = item
    if set(result) != set(_EXPECTED_ROLES):
        return None
    return result


def validate_console_mapping(document: Mapping[str, Any], reference: Mapping[str, Any]) -> bool:
    """Require raw fields, normalized oracle fields, and their fixed relation."""
    oracle_agents = _oracle_agents(reference)
    raw_agents = document.get("agents")
    if oracle_agents is None or not isinstance(raw_agents, Mapping):
        return False
    for role_id in _EXPECTED_ROLES:
        raw = raw_agents.get(role_id)
        oracle = oracle_agents.get(role_id)
        if not isinstance(raw, Mapping) or oracle is None:
            return False
        raw_expected = _RAW_AGENTS[role_id]
        if any(raw.get(key) != value for key, value in raw_expected.items()):
            return False
        expected_oracle = _ORACLE_AGENTS[role_id]
        if any(oracle.get(key) != value for key, value in expected_oracle.items()):
            return False
    return True
