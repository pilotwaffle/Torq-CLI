import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from scripts.provision_ci_wheelhouse import (
    PACKAGE_NAMES,
    _load_manifest,
    _lock_hashes,
    _validate_artifact_records,
    _validate_lock,
)
from torq_cli.application import import_v5_console_config
from torq_cli.application import import_v5_console_config as console_app
from torq_cli.domain import v5_console_config_import as console_domain
from torq_cli.domain.drift_oracle import load_v5_config_reference
from torq_cli.domain.hermetic import (
    LegacyConfigTooLarge,
    LegacyConfigUnreadable,
    ProtectedPathError,
)
from torq_cli.domain.registry_schema import (
    RegistryDocumentError,
    RegistryResourceMissing,
    RegistrySyntaxError,
    RegistryUnreadable,
    load_registry,
)
from torq_cli.domain.v5_console_config_import import (
    ConsoleSyntaxError,
    construct_console_yaml,
    preflight_console_yaml,
    validate_console_schema,
)
from torq_cli.interfaces import cli as cli_module
from torq_cli.interfaces.cli import main
REPO_ROOT = Path(__file__).parents[1]


FIXTURE = Path(__file__).parent / "fixtures" / "t06c" / "raw-console-config.sanitized.yaml"
TARGET_SHA256 = "63ffadbe88e6b04ac732d5a282e27e0af1a2bbd80f89412ad1a4364e01a3650e"
LOCK = Path(__file__).parents[1] / "ci" / "t06c-wheelhouse" / "requirements-py311.txt"
MANIFEST = Path(__file__).parents[1] / "ci" / "t06c-wheelhouse" / "manifest-py311.json"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
WINDOWS_ROLE_TEST_ROOT_ASSIGNMENT = (
    r'$env:TORQ_T06C_ROLE_TEST_ROOT = "$env:RUNNER_TEMP\t06c-role-specific-cases"'
)

LITERAL_ROLES = ("g1d", "g1r", "builder", "g2a", "refine_bug", "refine_ui")
LITERAL_PATHS = (
    "artifacts/00_input/prd.md",
    "artifacts/01_design/build_spec.md",
    "artifacts/01_design/design_questions.md",
    "artifacts/01_design/gate1_review.md",
    "artifacts/02_build/build_result.md",
    "artifacts/03_audit/audit_report.md",
    "artifacts/04_refine/bug_refinement.md",
    "artifacts/04_refine/ui_refinement.md",
)
LITERAL_RAW_AGENTS = {
    "g1d": {"role": "Gate 1 Design Authority", "model": "claude-fable-5", "cli": "claude-sub", "prompt": "prompts/gate1_design.md"},
    "g1r": {"role": "Gate 1 Adversarial Review", "model": "claude-opus-4-7", "cli": "claude-sub", "prompt": "prompts/gate1_review.md"},
    "builder": {"role": "Builder", "model": "deepseek-v4-pro", "cli": "claude-deepseek", "prompt": "prompts/builder.md", "endpoint": "https://api.deepseek.com/anthropic"},
    "g2a": {"role": "Gate 2 Build Authority / Audit", "model": "claude-opus-4-7", "cli": "claude-sub", "prompt": "prompts/gate2_audit.md"},
    "refine_bug": {"role": "Bug / Race / Self-correction refinement", "model": "kimi-k3", "cli": "claude-kimi", "prompt": "prompts/refine_bug.md", "endpoint": "https://api.moonshot.ai/anthropic/", "notes": "Account currently suspended - recharge Moonshot to enable this lane"},
    "refine_ui": {"role": "UI polish refinement", "model": "glm-5.2", "cli": "claude-zai", "prompt": "prompts/refine_ui.md", "endpoint": "https://api.z.ai/api/anthropic"},
}
LITERAL_ORACLE_AGENTS = {
    "g1d": {"role_id": "g1d", "model": "claude-opus-4-7", "cli": "claude-sub", "prompt": "prompts/gate1_design.md", "endpoint": None},
    "g1r": {"role_id": "g1r", "model": "claude-opus-4-7", "cli": "claude-sub", "prompt": "prompts/gate1_review.md", "endpoint": None},
    "builder": {"role_id": "builder", "model": "deepseek-v4-pro", "cli": "claude-deepseek", "prompt": "prompts/builder.md", "endpoint": "https://api.deepseek.com/anthropic"},
    "g2a": {"role_id": "g2a", "model": "claude-opus-4-7", "cli": "claude-sub", "prompt": "prompts/gate2_audit.md", "endpoint": None},
    "refine_bug": {"role_id": "refine_bug", "model": "kimi-k2.7-code", "cli": "claude-kimi", "prompt": "prompts/refine_bug.md", "endpoint": "https://api.moonshot.ai/anthropic/"},
    "refine_ui": {"role_id": "refine_ui", "model": "glm-5.2", "cli": "claude-zai", "prompt": "prompts/refine_ui.md", "endpoint": "https://api.z.ai/api/anthropic"},
}
ROLE_REQUIRED_MEMBERS = {
    "g1d": ("role", "model", "cli", "prompt", "reads", "writes"),
    "g1r": ("role", "model", "cli", "prompt", "reads", "writes"),
    "builder": ("role", "model", "cli", "prompt", "reads", "writes", "endpoint"),
    "g2a": ("role", "model", "cli", "prompt", "reads", "writes"),
    "refine_bug": ("role", "model", "cli", "prompt", "reads", "writes", "endpoint", "notes"),
    "refine_ui": ("role", "model", "cli", "prompt", "reads", "writes", "endpoint"),
}
LITERAL_STATE_STATES = (
    "ready", "design_complete", "gate1_passed", "design_revision_needed", "build_complete",
    "build_revision_needed", "refine_needed", "complete", "human_escalation",
)
LITERAL_ROUTING = {
    "architecture_issue": "builder", "bug_or_race": "refine_bug", "ui_polish": "refine_ui",
    "spec_is_wrong": "g1d", "ambiguous": "human_escalation",
}
LITERAL_CRITERIA = ("rejection_count", "wall_clock", "cost", "post_push_issues")
LITERAL_DENIED_KEYS = (
    "api_key", "apikey", "api_token", "x_api_key", "access_token", "auth_token", "authorization",
    "bearer_token", "refresh_token", "id_token", "session_token", "token", "password", "passphrase",
    "secret", "secret_key", "client_secret", "credential", "credentials", "private_key",
    "ssh_private_key", "cookie", "cookies", "set_cookie", "openai_api_key", "anthropic_api_key",
    "deepseek_api_key", "moonshot_api_key", "kimi_api_key", "zai_api_key", "glm_api_key",
)
LITERAL_LOCK_HASHES = {
    "PyYAML": {"e10ce637b18caea04431ce14fabcf5c64a1c61ec9c56b071a4b7ca131ca52d44", "cc1c1159b3d456576af7a3e4d1ba7e6924cb39de8f67111c735f6fc832082774", "3ad2a3decf9aaba3d29c8f537ac4b243e36bef957511b4766cb0057d32b0be85"},
    "setuptools": {"a59e362652f08dcd477c78bb6e7bd9d80a7995bc73ce773050228a348ce2e5bb"},
    "wheel": {"212281cab4dff978f6cedd499cd893e1f620791ca6ff7107cf270781e587eced"},
    "packaging": {"b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529"},
}
LITERAL_ARTIFACTS = {
    "windows-py311": (
        {"name": "PyYAML", "version": "6.0.2", "filename": "PyYAML-6.0.2-cp311-cp311-win_amd64.whl", "size": 161980, "sha256": "e10ce637b18caea04431ce14fabcf5c64a1c61ec9c56b071a4b7ca131ca52d44", "python_tag": "cp311", "abi_tag": "cp311", "platform_tag": "win_amd64"},
        {"name": "setuptools", "version": "82.0.1", "filename": "setuptools-82.0.1-py3-none-any.whl", "size": 1006223, "sha256": "a59e362652f08dcd477c78bb6e7bd9d80a7995bc73ce773050228a348ce2e5bb", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "wheel", "version": "0.47.0", "filename": "wheel-0.47.0-py3-none-any.whl", "size": 32218, "sha256": "212281cab4dff978f6cedd499cd893e1f620791ca6ff7107cf270781e587eced", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "packaging", "version": "26.0", "filename": "packaging-26.0-py3-none-any.whl", "size": 74366, "sha256": "b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
    ),
    "macos-15-intel-py311-x86_64": (
        {"name": "PyYAML", "version": "6.0.2", "filename": "PyYAML-6.0.2-cp311-cp311-macosx_10_9_x86_64.whl", "size": 184612, "sha256": "cc1c1159b3d456576af7a3e4d1ba7e6924cb39de8f67111c735f6fc832082774", "python_tag": "cp311", "abi_tag": "cp311", "platform_tag": "macosx_10_9_x86_64"},
        {"name": "setuptools", "version": "82.0.1", "filename": "setuptools-82.0.1-py3-none-any.whl", "size": 1006223, "sha256": "a59e362652f08dcd477c78bb6e7bd9d80a7995bc73ce773050228a348ce2e5bb", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "wheel", "version": "0.47.0", "size": 32218, "filename": "wheel-0.47.0-py3-none-any.whl", "sha256": "212281cab4dff978f6cedd499cd893e1f620791ca6ff7107cf270781e587eced", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "packaging", "version": "26.0", "filename": "packaging-26.0-py3-none-any.whl", "size": 74366, "sha256": "b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
    ),
    "linux-py311": (
        {"name": "PyYAML", "version": "6.0.2", "filename": "PyYAML-6.0.2-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "size": 762952, "sha256": "3ad2a3decf9aaba3d29c8f537ac4b243e36bef957511b4766cb0057d32b0be85", "python_tag": "cp311", "abi_tag": "cp311", "platform_tag": "manylinux_2_17_x86_64.manylinux2014_x86_64"},
        {"name": "setuptools", "version": "82.0.1", "filename": "setuptools-82.0.1-py3-none-any.whl", "size": 1006223, "sha256": "a59e362652f08dcd477c78bb6e7bd9d80a7995bc73ce773050228a348ce2e5bb", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "wheel", "version": "0.47.0", "filename": "wheel-0.47.0-py3-none-any.whl", "size": 32218, "sha256": "212281cab4dff978f6cedd499cd893e1f620791ca6ff7107cf270781e587eced", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "packaging", "version": "26.0", "filename": "packaging-26.0-py3-none-any.whl", "size": 74366, "sha256": "b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
    ),
}


def _complete_manifest_hashes() -> dict[str, set[str]]:
    manifest = _load_manifest(MANIFEST)
    platforms = manifest["platforms"]
    union = {name: set() for name in PACKAGE_NAMES}
    assert isinstance(platforms, dict)
    for platform_record in platforms.values():
        assert isinstance(platform_record, dict)
        for artifact in _validate_artifact_records(platform_record["artifacts"]):
            union[artifact["name"]].add(artifact["sha256"])
    return union


def _assert_source_free_invalid(
    result: subprocess.CompletedProcess[bytes], finding_id: str, stage: str, path: str = "/"
) -> dict[str, object]:
    envelope = _assert_compact_process_envelope(result, 2, finding_id)
    assert envelope["command"] == "config_import_v5_console"
    assert envelope["data"] == {}
    finding = envelope["findings"][0]
    assert isinstance(finding, dict)
    is_protected = finding_id == "console_config_protected_path_denied"
    is_critical = finding_id in {"console_config_secret_field_forbidden", "console_config_protected_path_denied"}
    assert {key: finding[key] for key in ("id", "path", "stage", "severity", "bucket", "status_class")} == {
        "id": finding_id,
        "path": path,
        "stage": stage,
        "severity": "critical" if is_critical else "high" if finding_id.startswith("console_config_") else "medium",
        "bucket": "A" if is_critical else "B",
        "status_class": "blocked" if is_protected else "invalid",
    }
    snapshot = envelope["snapshot"]
    assert isinstance(snapshot, dict)
    assert snapshot["config_path"] is None
    serialized = result.stdout.decode("utf-8")
    assert all(marker not in serialized for marker in ("bad.yaml", "utf16"))
    return envelope


def _run(capsys, path: Path, *extra: str) -> tuple[int, dict[str, object], str]:
    code = main(["config", "import-v5-console", "--config", str(path.resolve()), *extra])
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert captured.out.encode("utf-8") == json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    assert "\r" not in captured.out
    assert captured.err == ""
    return code, result, captured.err


def _run_source_console(path: Path, *extra: str) -> subprocess.CompletedProcess[bytes]:
    environment = {
        'PYTHONPATH': str(REPO_ROOT / 'src'),
        'PYTHONDONTWRITEBYTECODE': '1',
    }
    return subprocess.run(
        [sys.executable, '-m', 'torq_cli', 'config', 'import-v5-console', '--config', str(path.resolve()), *extra],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        check=False,
    )


def _assert_compact_process_envelope(
    result: subprocess.CompletedProcess[bytes], expected_code: int, expected_finding: str | None = None
) -> dict[str, object]:
    assert result.returncode == expected_code
    assert result.stderr == b''
    envelope = json.loads(result.stdout.decode('utf-8'))
    compact = json.dumps(envelope, sort_keys=True, separators=(',', ':')).encode('utf-8') + b'\n'
    assert result.stdout == compact, f'stdout_tail={result.stdout[-8:].hex()}'
    assert result.stdout.count(b'\n') == 1
    assert b'\r' not in result.stdout
    if expected_finding is not None:
        assert envelope['findings'][0]['id'] == expected_finding
    return envelope


def test_sanitized_console_fixture_projects_to_fixed_target(capsys) -> None:
    code, result, stderr = _run(capsys, FIXTURE)

    assert code == 0
    assert stderr == ""
    assert result["command"] == "config_import_v5_console"
    assert result["status"] == "ok"
    data = result["data"]
    assert isinstance(data, dict)
    target = data["canonical_target_config_utf8"]
    assert isinstance(target, str)
    target_bytes = target.encode("utf-8")
    assert len(target_bytes) == 1029
    assert hashlib.sha256(target_bytes).hexdigest() == TARGET_SHA256
    assert target_bytes.endswith(b"\n")
    assert not target_bytes.startswith(b"\xef\xbb\xbf")


def test_output_is_rejected_before_any_import_io(monkeypatch, capsys) -> None:
    from torq_cli.application import import_v5_console_config

    def fail(*args, **kwargs):
        raise AssertionError("I/O must not occur for --output")

    monkeypatch.setattr(import_v5_console_config, "load_registry", fail)
    monkeypatch.setattr(import_v5_console_config, "read_bounded_legacy_config", fail)

    code = main(["config", "import-v5-console", "--config", str(FIXTURE.resolve()), "--output", "x"])
    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert code == 2
    assert captured.err == ""
    assert result["status"] == "invalid"
    assert result["findings"][0]["id"] == "console_config_projection_invalid"
    assert result["snapshot"] is None
    assert result["data"] == {}


def test_console_syntax_failure_is_source_path_free(tmp_path: Path, capsys) -> None:
    path = tmp_path / "bad.yaml"
    path.write_bytes(b"root: [")

    code, result, stderr = _run(capsys, path)

    assert code == 2
    assert stderr == ""
    assert result["findings"][0]["id"] == "console_config_syntax_invalid"
    assert result["findings"][0]["path"] == "/"
    snapshot = result["snapshot"]
    assert isinstance(snapshot, dict)
    assert snapshot["config_path"] is None
    assert result["data"] == {}


@pytest.mark.parametrize(
    "encoding",
    ("utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"),
)
def test_direct_parser_rejects_non_utf8_encodings(encoding: str) -> None:
    raw = FIXTURE.read_bytes().decode("utf-8").encode(encoding)
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(raw)
    with pytest.raises(ConsoleSyntaxError):
        construct_console_yaml(raw)


@pytest.mark.parametrize(
    "raw",
    (b"\xef\xbb\xbf" + FIXTURE.read_bytes(), b"\xff\xfe\x00", b"\xc3\x28"),
)
def test_direct_parser_rejects_bom_and_malformed_utf8(raw: bytes) -> None:
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(raw)
    with pytest.raises(ConsoleSyntaxError):
        construct_console_yaml(raw)


def test_parser_accepts_inclusive_byte_limit_and_rejects_one_over() -> None:
    padding = b"\n#" + b"x" * (65_536 - len(FIXTURE.read_bytes()) - 2)
    accepted = FIXTURE.read_bytes() + padding
    assert len(accepted) == 65_536
    preflight_console_yaml(accepted)
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(accepted + b"x")
    with pytest.raises(ConsoleSyntaxError):
        construct_console_yaml(accepted + b"x")


@pytest.mark.parametrize("mutation", ("unknown_root", "missing_root", "version", "role", "path"))
def test_direct_schema_closed_negative_matrix(mutation: str) -> None:
    document = construct_console_yaml(FIXTURE.read_bytes())
    assert validate_console_schema(document)
    candidate = copy.deepcopy(document)
    if mutation == "unknown_root":
        candidate["unknown"] = True
    elif mutation == "missing_root":
        del candidate["version"]
    elif mutation == "version":
        candidate["version"] = 6
    elif mutation == "role":
        candidate["agents"]["g1d"]["role"] = "not-a-role"
    else:
        candidate["agents"]["g1d"]["reads"] = ["../secret.txt"]
    assert not validate_console_schema(candidate)


@pytest.mark.parametrize(
    "raw",
    (
        FIXTURE.read_bytes() + b"\n---\n{}\n",
        b"scalar\n",
        b"- scalar\n",
        b"!custom {value: scalar}\n",
        b"root: &anchor {value: scalar}\ncopy: *anchor\n",
        b"root: {<<: {value: scalar}}\n",
        b"? [complex]\n: scalar\n",
            "\u00e9: one\ne\u0301: two\n".encode("utf-8"),
    ),
)
def test_direct_parser_rejects_closed_yaml_policy_boundaries(raw: bytes) -> None:
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(raw)


def test_direct_parser_rejects_event_and_depth_limits() -> None:
    many_events = ("root: [" + ",".join("scalar" for _ in range(1_022)) + "]\n").encode()
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(many_events)
    nested = "scalar"
    for _ in range(10):
        nested = "root: {" + nested + "}\n"
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(nested.encode())


@pytest.mark.parametrize(
    "encoding",
    ("utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"),
)
def test_process_rejects_non_utf8_encodings_without_disclosure(tmp_path: Path, encoding: str) -> None:
    path = tmp_path / f"encoded-{encoding}.yaml"
    path.write_bytes(FIXTURE.read_bytes().decode("utf-8").encode(encoding))
    result = _run_source_console(path)
    _assert_source_free_invalid(result, "console_config_syntax_invalid", "console_config_parse")


def test_process_rejects_utf8_bom_without_disclosure(tmp_path: Path) -> None:
    path = tmp_path / "utf8-bom.yaml"
    path.write_bytes(b"\xef\xbb\xbf" + FIXTURE.read_bytes())
    result = _run_source_console(path)
    _assert_source_free_invalid(result, "console_config_syntax_invalid", "console_config_parse")


def test_console_mapping_mismatch_is_rejected(tmp_path: Path, capsys) -> None:
    payload = FIXTURE.read_bytes().replace(b"claude-fable-5", b"claude-fable-6", 1)
    path = tmp_path / "mapping.yaml"
    path.write_bytes(payload)

    code, result, stderr = _run(capsys, path)

    assert code == 2
    assert stderr == ""
    assert result["findings"][0]["id"] == "console_config_mapping_unsupported"
    assert "claude-fable-6" not in json.dumps(result)


def test_console_secret_is_rejected_without_echo(tmp_path: Path, capsys) -> None:
    path = tmp_path / "secret.yaml"
    path.write_bytes(FIXTURE.read_bytes() + b"token: marker\n")

    code, result, stderr = _run(capsys, path)

    assert code == 2
    assert stderr == ""
    assert result["findings"][0]["id"] == "console_config_secret_field_forbidden"
    assert "marker" not in json.dumps(result)


def test_t06c_source_subprocess_emits_exact_utf8_final_lf() -> None:
    result = _run_source_console(FIXTURE)
    envelope = _assert_compact_process_envelope(result, 0)

    assert envelope['status'] == 'ok'
    data = envelope['data']
    assert isinstance(data, dict)
    target = data['canonical_target_config_utf8']
    assert isinstance(target, str)
    assert hashlib.sha256(target.encode('utf-8')).hexdigest() == TARGET_SHA256


def test_t06c_source_subprocess_output_rejection_is_exact_utf8_final_lf() -> None:
    result = _run_source_console(FIXTURE, '--output', 'ignored')
    envelope = _assert_compact_process_envelope(result, 2, 'console_config_projection_invalid')

    assert envelope['snapshot'] is None
    assert envelope['data'] == {}


def test_t06c_source_subprocess_syntax_failure_is_exact_utf8_final_lf(tmp_path: Path) -> None:
    path = tmp_path / 'bad.yaml'
    path.write_bytes(b'root: [')

    result = _run_source_console(path)
    envelope = _assert_compact_process_envelope(result, 2, 'console_config_syntax_invalid')

    assert envelope['data'] == {}
    assert 'bad.yaml' not in result.stdout.decode('utf-8')


class _TextOnlyCapture:
    def __init__(self) -> None:
        self.writes: list[str] = []
        self.flushes = 0
        self.reconfigure_calls = 0

    def write(self, value: str) -> int:
        self.writes.append(value)
        return len(value)

    def flush(self) -> None:
        self.flushes += 1

    def reconfigure(self, **kwargs: object) -> None:
        self.reconfigure_calls += 1


def test_t06c_writer_text_capture_fallback_has_one_lf_without_reconfigure(monkeypatch) -> None:
    stream = _TextOnlyCapture()
    monkeypatch.setattr(cli_module.sys, 'stdout', stream)

    assert cli_module._write_t06c_envelope(import_v5_console_config.output_rejected()) is False

    rendered = ''.join(stream.writes)
    assert rendered.endswith('\n')
    assert rendered.count('\n') == 1
    assert '\r' not in rendered
    assert stream.flushes == 1
    assert stream.reconfigure_calls == 0


class _FailingBinary:
    def write(self, value: bytes) -> int:
        raise OSError('binary write failed')

    def flush(self) -> None:
        raise OSError('binary flush failed')


class _BinaryFailureCapture:
    def __init__(self) -> None:
        self.buffer = _FailingBinary()

    def write(self, value: str) -> int:
        raise AssertionError('binary failure must not retry through text')


def test_t06c_writer_binary_failure_does_not_retry(monkeypatch) -> None:
    stream = _BinaryFailureCapture()
    monkeypatch.setattr(cli_module.sys, 'stdout', stream)

    assert cli_module._write_t06c_envelope(import_v5_console_config.output_rejected()) is True


def test_older_commands_retain_shared_text_output_path(monkeypatch, tmp_path: Path, capsys) -> None:
    calls: list[bool] = []
    original = cli_module._print_envelope

    def spy(envelope, *, compact: bool) -> bool:
        calls.append(compact)
        return original(envelope, compact=compact)

    monkeypatch.setattr(cli_module, '_print_envelope', spy)
    normalized = (
        REPO_ROOT / 'src' / 'torq_cli' / 'data' / 'oracles' / 'torq-console-3ae19610'
        / 'v5_config.normalized.json'
    )
    assert main(['config', 'import-v5-normalized', '--config', str(normalized)]) == 0
    assert json.loads(capsys.readouterr().out)['command'] == 'config_import_v5_normalized'

    config = tmp_path / 'config.json'
    config.write_text(
        json.dumps({
            'config_version': 1,
            'profile': {'id': 'torq-v5-6-live', 'version': '1.0.0'},
            'binding_overrides': {},
            'connectors': {},
            'policy': {
                'independence_mode': 'profile_minimum',
                'unattestable_action': 'deny',
                'loop_budget': 1,
                'resource_limits': {
                    'max_runtime_seconds': 60,
                    'max_cost_cents': 100,
                    'max_file_count': 10,
                    'max_changed_lines': 100,
                },
            },
        }),
        encoding='utf-8',
    )
    assert main(['profile', 'validate', '--config', str(config)]) == 0
    assert json.loads(capsys.readouterr().out)['command'] == 'profile_validate'
    assert main(['status', '--offline', '--config', str(config)]) == 0
    assert json.loads(capsys.readouterr().out)['command'] == 'status_offline'
    assert calls == [True, False, False]


def test_committed_wheelhouse_lock_accepts_safe_global_option() -> None:
    hashes = _lock_hashes(LOCK)
    assert set(hashes) == {'PyYAML', 'setuptools', 'wheel', 'packaging'}
    assert {name: len(values) for name, values in hashes.items()} == {
        'PyYAML': 3,
        'setuptools': 1,
        'wheel': 1,
        'packaging': 1,
    }


def test_committed_lock_equals_complete_manifest_hash_union() -> None:
    _validate_lock(LOCK, _complete_manifest_hashes())
    assert {name: len(values) for name, values in _complete_manifest_hashes().items()} == {
        "PyYAML": 3,
        "setuptools": 1,
        "wheel": 1,
        "packaging": 1,
    }


def test_complete_manifest_validates_all_platform_records() -> None:
    manifest = _load_manifest(MANIFEST)
    platforms = manifest["platforms"]
    assert isinstance(platforms, dict)
    assert set(platforms) == {"windows-py311", "macos-15-intel-py311-x86_64", "linux-py311"}
    for platform_record in platforms.values():
        assert isinstance(platform_record, dict)
        assert len(_validate_artifact_records(platform_record["artifacts"])) == len(PACKAGE_NAMES)


@pytest.mark.parametrize(
    "label",
    (
        "missing-root-key",
        "extra-root-key",
        "wrong-root-type",
        "wrong-schema-literal",
        "wrong-index-literal",
        "missing-python-key",
        "extra-python-key",
        "wrong-python-type",
        "wrong-implementation",
        "wrong-major",
        "boolean-major",
        "wrong-minor",
        "missing-platform-key",
        "extra-platform-key",
        "missing-platform-member",
        "extra-platform-member",
        "wrong-runner",
        "wrong-sys-platform",
        "wrong-machine",
    ),
)
def test_W2_closed_manifest_wrapper_mutations_stop_before_download(
    monkeypatch, tmp_path: Path, label: str
) -> None:
    import scripts.provision_ci_wheelhouse as provisioner

    manifest = _load_manifest(MANIFEST)
    platforms = manifest["platforms"]
    assert isinstance(platforms, dict)
    if label == "missing-root-key":
        del manifest["schema"]
    elif label == "extra-root-key":
        manifest["unexpected"] = "wrapper-marker"
    elif label == "wrong-root-type":
        manifest["platforms"] = []
    elif label == "wrong-schema-literal":
        manifest["schema"] = "wrong-schema"
    elif label == "wrong-index-literal":
        manifest["official_index"] = "https://example.invalid/simple"
    elif label == "missing-python-key":
        del manifest["python"]["minor"]
    elif label == "extra-python-key":
        manifest["python"]["unexpected"] = 11
    elif label == "wrong-python-type":
        manifest["python"] = "cpython-3.11"
    elif label == "wrong-implementation":
        manifest["python"]["implementation"] = "pypy"
    elif label == "wrong-major":
        manifest["python"]["major"] = 4
    elif label == "boolean-major":
        manifest["python"]["major"] = True
    elif label == "wrong-minor":
        manifest["python"]["minor"] = 10
    elif label == "missing-platform-key":
        del platforms["linux-py311"]
    elif label == "extra-platform-key":
        platforms["unknown-py311"] = copy.deepcopy(platforms["linux-py311"])
    elif label == "missing-platform-member":
        del platforms["linux-py311"]["runner"]
    elif label == "extra-platform-member":
        platforms["linux-py311"]["unexpected"] = "wrapper-marker"
    elif label == "wrong-runner":
        platforms["linux-py311"]["runner"] = "other-runner"
    elif label == "wrong-sys-platform":
        platforms["linux-py311"]["sys_platform"] = "win32"
    elif label == "wrong-machine":
        platforms["linux-py311"]["machine"] = "aarch64"
    else:
        raise AssertionError(label)

    manifest_path = tmp_path / f"{label}.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    root = tmp_path / f"{label}-root"
    monkeypatch.setenv("TORQ_T06C_CI_TEMP_ROOT", str(tmp_path.parent))
    monkeypatch.delenv("TORQ_T06C_OFFICIAL_INDEX", raising=False)
    monkeypatch.setattr(provisioner, "_assert_runtime", lambda _: None)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        provisioner.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command) or SimpleNamespace(returncode=0),
    )

    with pytest.raises(SystemExit):
        provisioner.main([
            "--root", str(root), "--platform", "linux-py311", "--lock", str(LOCK),
            "--manifest", str(manifest_path),
        ])
    assert calls == []
    assert not root.exists()


@pytest.mark.parametrize("location", ("root", "python", "platform"))
def test_W2_duplicate_manifest_members_stop_before_download(
    monkeypatch, tmp_path: Path, location: str
) -> None:
    import scripts.provision_ci_wheelhouse as provisioner

    payload = MANIFEST.read_text(encoding="utf-8")
    if location == "root":
        needle = '  "schema": "torq-t06c-wheelhouse-v1",\n'
        duplicate = needle + '  "schema": "torq-t06c-wheelhouse-v1",\n'
    elif location == "python":
        needle = '    "implementation": "cpython",\n'
        duplicate = needle + '    "implementation": "cpython",\n'
    else:
        needle = '      "runner": "windows-2022",\n'
        duplicate = needle + '      "runner": "windows-2022",\n'
    assert payload.count(needle) == 1
    manifest_path = tmp_path / f"duplicate-{location}.json"
    manifest_path.write_text(payload.replace(needle, duplicate, 1), encoding="utf-8")
    root = tmp_path / f"duplicate-{location}-root"
    monkeypatch.setenv("TORQ_T06C_CI_TEMP_ROOT", str(tmp_path.parent))
    monkeypatch.delenv("TORQ_T06C_OFFICIAL_INDEX", raising=False)
    monkeypatch.setattr(provisioner, "_assert_runtime", lambda _: None)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        provisioner.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command) or SimpleNamespace(returncode=0),
    )

    with pytest.raises(SystemExit):
        provisioner.main([
            "--root", str(root), "--platform", "linux-py311", "--lock", str(LOCK),
            "--manifest", str(manifest_path),
        ])
    assert calls == []
    assert not root.exists()


def test_wheelhouse_lock_rejects_extra_manifest_hash(tmp_path: Path) -> None:
    lines = LOCK.read_text(encoding="utf-8").splitlines()
    hash_indices = [index for index, line in enumerate(lines) if line.strip().startswith("--hash")]
    lines[hash_indices[2]] += " \\"
    lines.insert(hash_indices[2] + 1, "    --hash=sha256:" + "f" * 64)
    lock = tmp_path / "extra-hash.txt"
    lock.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="complete manifest"):
        _validate_lock(lock, _complete_manifest_hashes())


def test_wheelhouse_lock_rejects_appended_comment(tmp_path: Path) -> None:
    lock = tmp_path / "comment.txt"
    lock.write_text(LOCK.read_text(encoding="utf-8") + "# appended comment\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="unexpected trailing line"):
        _lock_hashes(lock)


@pytest.mark.parametrize("line", ("", " ", "\t", "# comment", "--no-index", "PyYAML==6.0.2"))
def test_wheelhouse_lock_rejects_unexpected_physical_lines(tmp_path: Path, line: str) -> None:
    lock = tmp_path / "unexpected-line.txt"
    lines = LOCK.read_text(encoding="utf-8").splitlines()
    lines.insert(1, line)
    lock.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        _lock_hashes(lock)


def test_wheelhouse_lock_rejects_duplicate_hash(tmp_path: Path) -> None:
    lines = LOCK.read_text(encoding="utf-8").splitlines()
    hash_indices = [index for index, line in enumerate(lines) if line.strip().startswith("--hash")]
    duplicate = lines[hash_indices[0]].replace(" \\", "")
    lines[hash_indices[0]] = lines[hash_indices[0]].replace(" \\", "") + " \\"
    lines.insert(hash_indices[0] + 1, duplicate)
    lock = tmp_path / "duplicate-hash.txt"
    lock.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="duplicate hash"):
        _lock_hashes(lock)


def test_wheelhouse_lock_rejects_missing_complete_manifest_hash(tmp_path: Path) -> None:
    lines = LOCK.read_text(encoding="utf-8").splitlines()
    del lines[4]
    lock = tmp_path / "missing-hash.txt"
    lock.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        _validate_lock(lock, _complete_manifest_hashes())


def test_wheelhouse_lock_rejects_requirement_after_open_hash_continuation(
    tmp_path: Path,
) -> None:
    lock = tmp_path / 'requirements.txt'
    lines = LOCK.read_text(encoding='utf-8').splitlines()
    hash_lines = [index for index, line in enumerate(lines) if line.strip().startswith('--hash')]
    lines[hash_lines[2]] += chr(92)
    lock.write_text(chr(10).join(lines) + chr(10), encoding='utf-8')

    with pytest.raises(SystemExit):
        _lock_hashes(lock)


def test_wheelhouse_lock_rejects_open_hash_continuation_at_eof(tmp_path: Path) -> None:
    lock = tmp_path / 'requirements.txt'
    lines = LOCK.read_text(encoding='utf-8').splitlines()
    lines[-1] += chr(92)
    lock.write_text(chr(10).join(lines) + chr(10), encoding='utf-8')

    with pytest.raises(SystemExit):
        _lock_hashes(lock)


@pytest.mark.parametrize(
    'line',
    (
        '',
        '# comment while continuation is open',
        '--only-binary=:all:',
        'setuptools==82.0.1',
        '--find-links=https://evil.example',
        '--hash=sha256:not-a-valid-hash',
        'bare-token',
    ),
)
def test_wheelhouse_lock_rejects_non_hash_line_while_continuation_is_open(
    tmp_path: Path, line: str
) -> None:
    lock = tmp_path / 'requirements.txt'
    lines = LOCK.read_text(encoding='utf-8').splitlines()
    hash_lines = [index for index, value in enumerate(lines) if value.strip().startswith('--hash')]
    lines.insert(hash_lines[0] + 1, line)
    lock.write_text(chr(10).join(lines) + chr(10), encoding='utf-8')

    with pytest.raises(SystemExit):
        _lock_hashes(lock)


@pytest.mark.parametrize(
    "option",
    (
        "--only-binary=all",
        "--only-binary=:all: --index-url=https://pypi.org/simple",
        "--index-url=https://pypi.org/simple",
        "--find-links=E:/wheelhouse",
        "--trusted-host=pypi.org",
    ),
)
def test_wheelhouse_lock_rejects_unsafe_or_near_miss_options(tmp_path: Path, option: str) -> None:
    lock = tmp_path / "requirements.txt"
    lock.write_text(
        LOCK.read_text(encoding="utf-8").replace("--only-binary=:all:", option, 1),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="unsupported global option"):
        _lock_hashes(lock)


@pytest.mark.parametrize(
    "requirement_line",
    (
        "PyYAML==6.0.2 --index-url=https://evil.example \\",
        "PyYAML==6.0.2 --hash=sha256:e10ce637b18caea04431ce14fabcf5c64a1c61ec9c56b071a4b7ca131ca52d44 \\",
        "PyYAML==6.0.2 \\ --find-links=E:/wheelhouse",
    ),
)
def test_wheelhouse_lock_rejects_appended_requirement_tokens(
    tmp_path: Path, requirement_line: str
) -> None:
    lock = tmp_path / "requirements.txt"
    payload = LOCK.read_text(encoding="utf-8").replace("PyYAML==6.0.2 \\", requirement_line, 1)
    lock.write_text(payload, encoding="utf-8")

    with pytest.raises(SystemExit, match="invalid requirement line"):
        _lock_hashes(lock)


@pytest.mark.parametrize(
    "replacement",
    (
        "PyYAML==6.0.2 \\",
        "PyYAML==6.0.3 \\",
        "unknown-package==1.0.0 \\",
    ),
)
def test_wheelhouse_lock_rejects_duplicate_or_unknown_requirements(
    tmp_path: Path, replacement: str
) -> None:
    lock = tmp_path / "requirements.txt"
    payload = LOCK.read_text(encoding="utf-8").replace(
        "setuptools==82.0.1 \\", f"{replacement}\nsetuptools==82.0.1 \\", 1
    )
    lock.write_text(payload, encoding="utf-8")

    with pytest.raises(SystemExit):
        _lock_hashes(lock)


def test_wheelhouse_lock_rejects_hash_without_continuation_before_more_hashes(
    tmp_path: Path,
) -> None:
    lock = tmp_path / "requirements.txt"
    payload = LOCK.read_text(encoding="utf-8").replace(
        "--hash=sha256:e10ce637b18caea04431ce14fabcf5c64a1c61ec9c56b071a4b7ca131ca52d44 \\",
        "--hash=sha256:e10ce637b18caea04431ce14fabcf5c64a1c61ec9c56b071a4b7ca131ca52d44",
        1,
    )
    lock.write_text(payload, encoding="utf-8")

    with pytest.raises(SystemExit, match="not a requirement continuation"):
        _lock_hashes(lock)


# The continuation matrix below is named by Terra's checklist IDs.  Each
# case calls the real approved domain/application/provisioner boundary.


def _valid_console_document() -> dict[str, object]:
    document = construct_console_yaml(FIXTURE.read_bytes())
    return copy.deepcopy(document)


def _role_test_root() -> Path:
    override = os.environ.get("TORQ_T06C_ROLE_TEST_ROOT")
    if override is None or override == "":
        root = Path(tempfile.gettempdir()).resolve() / "torq-cli-t06c-role-specific-cases"
    else:
        expanded = Path(os.path.expandvars(override)).expanduser()
        if not expanded.is_absolute():
            raise ValueError("TORQ_T06C_ROLE_TEST_ROOT must be an absolute path")
        root = expanded.resolve()

    repository = REPO_ROOT.resolve()
    if root == repository or repository in root.parents:
        raise ValueError("TORQ_T06C_ROLE_TEST_ROOT must be outside the repository")
    return root


def _external_case_path(name: str) -> Path:
    root = _role_test_root()
    root.mkdir(parents=True, exist_ok=True)
    return root / name


def _windows_quality_step(windows_job: dict[str, object]) -> tuple[dict[str, object], str]:
    steps = windows_job["steps"]
    assert isinstance(steps, list)
    quality_steps = [
        step for step in steps
        if isinstance(step, dict) and step.get("name") == "Quality checks"
    ]
    assert len(quality_steps) == 1
    quality_step = quality_steps[0]
    assert isinstance(quality_step, dict)
    assert quality_step.get("env") == {"PYTHONPATH": "src"}
    run = quality_step.get("run")
    assert isinstance(run, str)
    return quality_step, run


def _first_executable_powershell_line(lines: list[str]) -> tuple[int, str]:
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return index, stripped
    raise AssertionError("PowerShell run block has no executable line")


def _assert_windows_native_commands_are_guarded(workflow: str) -> None:
    document = yaml.safe_load(workflow)
    windows_job = document["jobs"]["quality-windows-py311"]
    job_env = windows_job.get("env", {})
    assert not isinstance(job_env, dict) or "TORQ_T06C_ROLE_TEST_ROOT" not in job_env
    assert "${{ runner.temp }}" not in workflow

    _, quality_run = _windows_quality_step(windows_job)
    quality_lines = quality_run.splitlines()
    assignment_index, first_executable = _first_executable_powershell_line(quality_lines)
    assert first_executable == WINDOWS_ROLE_TEST_ROOT_ASSIGNMENT
    quality_command_prefixes = (
        "python -m ruff check src tests",
        "python -m mypy --strict src/torq_cli",
        "python -m pytest -q",
        "python scripts/run_named_mutants.py",
    )
    quality_command_indexes = [
        index for index, line in enumerate(quality_lines)
        if line.strip().startswith(quality_command_prefixes)
    ]
    assert len(quality_command_indexes) == 5
    assert all(index > assignment_index for index in quality_command_indexes)

    native_commands: list[tuple[str, list[str], int]] = []
    for step in windows_job["steps"]:
        if step.get("shell") == "python" or not isinstance(step.get("run"), str):
            continue
        lines = step["run"].splitlines()
        for index, line in enumerate(lines):
            command = line.strip()
            if re.match(r"^(?:python|git)(?:\s|$)", command):
                native_commands.append((command, lines, index))

    commands = [command for command, _, _ in native_commands]
    required_prefixes = (
        "python -m pip install --disable-pip-version-check",
        'python -c "import platform,sys;',
        "python scripts/provision_ci_wheelhouse.py",
        "python -m pip install --no-index",
        'python -c "import yaml;',
        "python -m ruff check src tests",
        "python -m mypy --strict src/torq_cli",
        "python -m pytest -q",
        "git clone --no-local .",
        "python -m build --outdir",
        "python scripts/wheel_smoke.py",
    )
    for prefix in required_prefixes:
        assert sum(command.startswith(prefix) for command in commands) == 1, prefix
    assert commands.count("python scripts/run_named_mutants.py") == 2

    guard = re.compile(r"if \(\$LASTEXITCODE -ne 0\) \{ exit \$LASTEXITCODE \}")
    assert native_commands
    for command, lines, index in native_commands:
        assert index + 1 < len(lines), command
        assert guard.fullmatch(lines[index + 1].strip()), command


def test_role_test_root_default_is_external_and_host_independent(monkeypatch) -> None:
    monkeypatch.delenv("TORQ_T06C_ROLE_TEST_ROOT", raising=False)

    root = _role_test_root()

    assert root.is_absolute()
    assert REPO_ROOT.resolve() not in (root, *root.parents)
    former_default = f"{chr(69)}:{chr(92)}tmp{chr(92)}t06c_role_specific_cases"
    assert former_default not in Path(__file__).read_text(encoding="utf-8")


def test_role_test_root_explicit_absolute_override_is_honored(monkeypatch, tmp_path: Path) -> None:
    override = tmp_path / "external" / ".." / "role-cases"
    monkeypatch.setenv("TORQ_T06C_ROLE_TEST_ROOT", str(override))

    assert _role_test_root() == override.resolve()


def test_role_test_root_empty_override_uses_default(monkeypatch) -> None:
    monkeypatch.delenv("TORQ_T06C_ROLE_TEST_ROOT", raising=False)
    default = _role_test_root()
    monkeypatch.setenv("TORQ_T06C_ROLE_TEST_ROOT", "")

    assert _role_test_root() == default


@pytest.mark.parametrize("override", ("relative-role-cases", str(REPO_ROOT / "inside-role-cases")))
def test_role_test_root_rejects_unsafe_overrides(monkeypatch, override: str) -> None:
    monkeypatch.setenv("TORQ_T06C_ROLE_TEST_ROOT", override)

    with pytest.raises(ValueError):
        _role_test_root()


def test_role_test_process_cases_use_selected_external_root(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "role-cases"
    monkeypatch.setenv("TORQ_T06C_ROLE_TEST_ROOT", str(root))

    s1_document = _valid_console_document()
    del s1_document["agents"]["g1d"]["role"]
    s1_path = _external_case_path("s1-subprocess.yaml")
    s1_path.write_bytes(_dump_console_document(s1_document))
    s1_result = _run_source_console(s1_path)

    s2_document = _valid_console_document()
    s2_document["agents"]["g1d"]["reads"] = ["artifacts/00_input/prd.md", 1]
    s2_path = _external_case_path("s2-subprocess.yaml")
    s2_path.write_bytes(_dump_console_document(s2_document))
    s2_result = _run_source_console(s2_path)

    assert s1_result.returncode == 2
    assert s2_result.returncode == 2
    assert s1_path.parent == root.resolve()
    assert s2_path.parent == root.resolve()
    assert REPO_ROOT.resolve() not in (s1_path.resolve(), *s1_path.resolve().parents)
    assert REPO_ROOT.resolve() not in (s2_path.resolve(), *s2_path.resolve().parents)


def test_role_test_root_rejects_repository_path_before_writing(monkeypatch) -> None:
    forbidden = REPO_ROOT / f".t06c-role-test-forbidden-{os.getpid()}-{id(monkeypatch)}"
    assert not forbidden.exists()
    monkeypatch.setenv("TORQ_T06C_ROLE_TEST_ROOT", str(forbidden))

    with pytest.raises(ValueError):
        _external_case_path("should-not-be-created.yaml")
    assert not forbidden.exists()


def test_windows_workflow_contract_and_native_command_guards() -> None:
    _assert_windows_native_commands_are_guarded(WORKFLOW.read_text(encoding="utf-8"))


def test_windows_workflow_structural_validator_rejects_missing_runtime_assignment() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    mutated = workflow.replace(
        f"          {WINDOWS_ROLE_TEST_ROOT_ASSIGNMENT}\n", "", 1
    )

    with pytest.raises(AssertionError):
        _assert_windows_native_commands_are_guarded(mutated)


def test_windows_workflow_structural_validator_rejects_late_runtime_assignment() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assignment_line = f"          {WINDOWS_ROLE_TEST_ROOT_ASSIGNMENT}"
    mutated = workflow.replace(f"{assignment_line}\n", "", 1)
    mutated = mutated.replace(
        "          python -m ruff check src tests",
        f"          python -m ruff check src tests\n{assignment_line}",
        1,
    )

    with pytest.raises(AssertionError):
        _assert_windows_native_commands_are_guarded(mutated)


def test_windows_workflow_structural_validator_rejects_job_level_runner_temp_root() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    mutated = workflow.replace(
        "    runs-on: windows-2022\n",
        "    runs-on: windows-2022\n"
        "    env:\n"
        "      TORQ_T06C_ROLE_TEST_ROOT: ${{ runner.temp }}\\t06c-role-specific-cases\n",
        1,
    )

    with pytest.raises(AssertionError):
        _assert_windows_native_commands_are_guarded(mutated)


def test_windows_workflow_structural_validator_rejects_step_runner_temp_root() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    mutated = workflow.replace(
        "        env: {PYTHONPATH: src}\n        run: |\n",
        "        env:\n"
        "          PYTHONPATH: src\n"
        "          TORQ_T06C_ROLE_TEST_ROOT: ${{ runner.temp }}\\t06c-role-specific-cases\n"
        "        run: |\n",
        1,
    )

    with pytest.raises(AssertionError):
        _assert_windows_native_commands_are_guarded(mutated)


def test_windows_workflow_guard_regression_rejects_detached_guard() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    expected = "          python -m pytest -q\n          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
    assert expected in workflow
    mutated = workflow.replace(expected, "          python -m pytest -q", 1)

    with pytest.raises(AssertionError):
        _assert_windows_native_commands_are_guarded(mutated)


def _dump_console_document(document: dict[str, object]) -> bytes:
    class _ConsoleDumper(yaml.SafeDumper):
        pass

    def represent_float(dumper: yaml.SafeDumper, value: float) -> yaml.nodes.ScalarNode:
        return dumper.represent_scalar("tag:yaml.org,2002:float", f"{value:.2f}")

    _ConsoleDumper.add_representer(float, represent_float)
    return yaml.dump(
        document, Dumper=_ConsoleDumper, sort_keys=False, allow_unicode=True
    ).encode("utf-8")


def _assert_matrix_process_failure(
    result: subprocess.CompletedProcess[bytes],
    finding_id: str,
    stage: str,
    marker: str,
    path: str = "/",
) -> dict[str, object]:
    envelope = _assert_source_free_invalid(result, finding_id, stage, path)
    assert marker not in result.stdout.decode("utf-8")
    assert marker not in result.stderr.decode("utf-8")
    return envelope


def _assert_exact_t06c_failure(
    envelope: object,
    finding_id: str,
    message: str,
    stage: str,
    forbidden: tuple[str, ...],
) -> None:
    assert envelope.schema_version == "1.0.0"
    assert envelope.command == "config_import_v5_console"
    assert envelope.status == "invalid"
    assert envelope.data == {}
    assert len(envelope.findings) == 1
    finding = envelope.findings[0]
    assert {
        "id": finding.id,
        "message": finding.message,
        "severity": finding.severity.value,
        "bucket": finding.bucket,
        "status_class": finding.status_class,
        "stage": finding.stage,
        "path": finding.path,
        "context": finding.context,
    } == {
        "id": finding_id,
        "message": message,
        "severity": "high",
        "bucket": "B",
        "status_class": "invalid",
        "stage": stage,
        "path": "/",
        "context": {},
    }
    snapshot = envelope.snapshot
    assert snapshot is not None
    assert {
        "registry_id": snapshot.registry_id,
        "registry_version": snapshot.registry_version,
        "registry_resource_sha256": snapshot.registry_resource_sha256,
        "config_path": snapshot.config_path,
        "config_version": snapshot.config_version,
        "profile_id": snapshot.profile_id,
        "profile_version": snapshot.profile_version,
        "resolution_stage": snapshot.resolution_stage,
    } == {
        "registry_id": "torq-cli-role-registry",
        "registry_version": "1.0.0",
        "registry_resource_sha256": "e6c378aa5104b871baf6c6404f13d1373a5ec7cbf486283a0a28dab73da87128",
        "config_path": None,
        "config_version": None,
        "profile_id": None,
        "profile_version": None,
        "resolution_stage": stage,
    }
    for marker in forbidden:
        assert marker not in json.dumps(envelope, default=str, sort_keys=True)


def _assert_exact_t06c_process_failure(
    result: subprocess.CompletedProcess[bytes],
    finding_id: str,
    message: str,
    stage: str,
    forbidden: tuple[str, ...],
) -> None:
    assert result.returncode == 2
    assert result.stderr == b""
    expected = {
        "schema_version": "1.0.0",
        "command": "config_import_v5_console",
        "status": "invalid",
        "snapshot": {
            "registry_id": "torq-cli-role-registry",
            "registry_version": "1.0.0",
            "registry_resource_sha256": "e6c378aa5104b871baf6c6404f13d1373a5ec7cbf486283a0a28dab73da87128",
            "config_path": None,
            "config_version": None,
            "profile_id": None,
            "profile_version": None,
            "resolution_stage": stage,
        },
        "findings": [{
            "id": finding_id,
            "message": message,
            "severity": "high",
            "bucket": "B",
            "status_class": "invalid",
            "stage": stage,
            "path": "/",
            "context": {},
        }],
        "data": {},
    }
    compact = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    assert result.stdout == compact
    assert result.stdout.count(b"\n") == 1
    assert b"\r" not in result.stdout
    for marker in forbidden:
        encoded = marker.encode("utf-8")
        assert encoded not in result.stdout
        assert encoded not in result.stderr


def _assert_matrix_direct_schema_failure(document: dict[str, object]) -> None:
    assert not validate_console_schema(document)


@pytest.mark.parametrize(
    ("encoding", "expected_valid"),
    (
        ("utf-8", True),
        ("utf-8-sig", False),
        ("utf-16-le", False),
        ("utf-16-be", False),
        ("utf-32-le", False),
        ("utf-32-be", False),
    ),
)
def test_P1_direct_strict_encoding_matrix(encoding: str, expected_valid: bool) -> None:
    raw = FIXTURE.read_bytes() if encoding == "utf-8" else FIXTURE.read_bytes().decode("utf-8").encode(encoding)
    if expected_valid:
        preflight_console_yaml(raw)
        assert validate_console_schema(construct_console_yaml(raw))
    else:
        with pytest.raises(ConsoleSyntaxError):
            preflight_console_yaml(raw)
        with pytest.raises(ConsoleSyntaxError):
            construct_console_yaml(raw)


@pytest.mark.parametrize(
    ("label", "raw", "expected_code"),
    (
        ("valid-utf8", FIXTURE.read_bytes(), 0),
        ("utf8-bom", b"\xef\xbb\xbf" + FIXTURE.read_bytes(), 2),
        ("utf16-le", FIXTURE.read_bytes().decode("utf-8").encode("utf-16-le"), 2),
        ("utf16-be", FIXTURE.read_bytes().decode("utf-8").encode("utf-16-be"), 2),
        ("utf32-le", FIXTURE.read_bytes().decode("utf-8").encode("utf-32-le"), 2),
        ("utf32-be", FIXTURE.read_bytes().decode("utf-8").encode("utf-32-be"), 2),
        ("malformed-utf8", b"\xc3\x28", 2),
    ),
    ids=("valid-utf8", "utf8-bom", "utf16-le", "utf16-be", "utf32-le", "utf32-be", "malformed-utf8"),
)
def test_P1_process_encoding_matrix(
    tmp_path: Path,
    label: str,
    raw: bytes,
    expected_code: int,
) -> None:
    path = tmp_path / f"{label}.yaml"
    path.write_bytes(raw)
    result = _run_source_console(path)
    if expected_code == 0:
        envelope = _assert_compact_process_envelope(result, 0)
        assert envelope["command"] == "config_import_v5_console"
        assert envelope["status"] == "ok"
    else:
        _assert_matrix_process_failure(result, "console_config_syntax_invalid", "console_config_parse", label)


def test_P2_exact_byte_boundary_direct_and_process(tmp_path: Path) -> None:
    padding = b"\n#" + b"x" * (65_536 - len(FIXTURE.read_bytes()) - 2)
    at_limit = FIXTURE.read_bytes() + padding
    over_limit = at_limit + b"x"
    assert len(at_limit) == 65_536
    assert len(over_limit) == 65_537
    preflight_console_yaml(at_limit)
    construct_console_yaml(at_limit)
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(over_limit)
    with pytest.raises(ConsoleSyntaxError):
        construct_console_yaml(over_limit)
    accepted_path = tmp_path / "at-limit.yaml"
    rejected_path = tmp_path / "over-limit.yaml"
    accepted_path.write_bytes(at_limit)
    rejected_path.write_bytes(over_limit)
    assert _assert_compact_process_envelope(_run_source_console(accepted_path), 0)["status"] == "ok"
    _assert_matrix_process_failure(
        _run_source_console(rejected_path), "console_config_syntax_invalid", "console_config_parse", "over-limit"
    )


@pytest.mark.parametrize(
    ("label", "raw"),
    (
        ("empty", b""),
        ("second-document", FIXTURE.read_bytes() + b"\n---\n{}\n"),
        ("scalar-root", b"scalar\n"),
        ("sequence-root", b"- scalar\n"),
        ("builtin-tag", b"!<tag:yaml.org,2002:str> scalar\n"),
        ("custom-tag", b"!custom scalar\n"),
        ("anchor", b"root: &anchor {value: scalar}\n"),
        ("alias", b"root: *anchor\n"),
        ("merge", b"root: {<<: {value: scalar}}\n"),
        ("complex-key", b"? [complex]\n: scalar\n"),
        ("nfc-duplicate", "\u00e9: one\ne\u0301: two\n".encode("utf-8")),
    ),
)
def test_P3_direct_parser_policy_matrix(label: str, raw: bytes) -> None:
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(raw)
    if label not in {"anchor", "merge", "nfc-duplicate"}:
        with pytest.raises(ConsoleSyntaxError):
            construct_console_yaml(raw)
    else:
        # Construction is intentionally a separate primitive; the application
        # always performs preflight first.  This call proves the policy test is
        # not relying on a constructor-only failure.
        construct_console_yaml(raw)
    assert label


def test_P3_quoted_merge_key_is_not_an_implicit_merge() -> None:
    raw = b'"<<": scalar\n'
    preflight_console_yaml(raw)
    assert construct_console_yaml(raw)["<<"] == "scalar"


@pytest.mark.parametrize(
    ("label", "raw"),
    (
        ("empty", b""),
        ("second-document", FIXTURE.read_bytes() + b"\n---\n{}\n"),
        ("scalar-root", b"scalar\n"),
        ("sequence-root", b"- scalar\n"),
        ("builtin-tag", b"!<tag:yaml.org,2002:str> scalar\n"),
        ("custom-tag", b"!custom scalar\n"),
        ("anchor", b"root: &anchor {value: scalar}\n"),
        ("alias", b"root: *anchor\n"),
        ("merge", b"root: {<<: {value: scalar}}\n"),
        ("complex-key", b"? [complex]\n: scalar\n"),
        ("nfc-duplicate", "\u00e9: one\ne\u0301: two\n".encode("utf-8")),
    ),
    ids=("empty", "second-document", "scalar-root", "sequence-root", "builtin-tag", "custom-tag", "anchor", "alias", "merge", "complex-key", "nfc-duplicate"),
)
def test_P3_process_parser_policy_envelope(tmp_path: Path, label: str, raw: bytes) -> None:
    path = tmp_path / f"p3-{label}.yaml"
    path.write_bytes(raw)
    _assert_matrix_process_failure(
        _run_source_console(path), "console_config_syntax_invalid", "console_config_parse", label
    )


def test_P4_exact_event_boundary_pair() -> None:
    def payload(scalars: int) -> bytes:
        return ("root: [" + ",".join("scalar" for _ in range(scalars)) + "]\n").encode("utf-8")

    preflight_console_yaml(payload(1_017))
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(payload(1_018))


def test_P4_exact_depth_boundary_pair() -> None:
    def payload(depth: int) -> bytes:
        value = "scalar"
        for _ in range(depth):
            value = "{root: " + value + "}"
        return ("root: " + value + "\n").encode("utf-8")

    preflight_console_yaml(payload(8))
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(payload(9))


def test_P4_process_event_and_depth_boundary_envelopes(tmp_path: Path) -> None:
    def events_payload(scalars: int) -> bytes:
        return ("root: [" + ",".join("scalar" for _ in range(scalars)) + "]\n").encode("utf-8")

    def depth_payload(depth: int) -> bytes:
        value = "scalar"
        for _ in range(depth):
            value = "{root: " + value + "}"
        return ("root: " + value + "\n").encode("utf-8")

    cases = (
        ("events-over", events_payload(1_018)),
        ("depth-over", depth_payload(9)),
    )
    for label, raw in cases:
        path = tmp_path / f"p4-{label}.yaml"
        path.write_bytes(raw)
        _assert_matrix_process_failure(
            _run_source_console(path), "console_config_syntax_invalid", "console_config_parse", label
        )


@pytest.mark.parametrize(
    "raw",
    (
        b"created: 2025-02-30\n",
        b"created: \"2025-01-01\"\n",
        b"created: 5\n",
        b"version: true\n",
        b"cost_guardrails: {max_cost_per_prd_usd: 1.2, alert_threshold_usd: 0.50}\n",
        b"cost_guardrails: {max_cost_per_prd_usd: .nan, alert_threshold_usd: 0.50}\n",
        b"version: !!str 5\n",
    ),
)
def test_P4_scalar_tag_and_type_matrix(raw: bytes) -> None:
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(raw)


def test_P4_decimal_float_and_integer_scalar_forms_are_closed() -> None:
    preflight_console_yaml(
        b"cost_guardrails:\n  max_cost_per_prd_usd: 1.20\n  alert_threshold_usd: 0.50\n"
    )
    preflight_console_yaml(b"version: 5\n")


ROOT_KEYS = (
    "version", "created", "supersedes", "agents", "state_machine", "rejection_routing",
    "cost_guardrails", "success_criteria",
)


@pytest.mark.parametrize("missing_key", ROOT_KEYS)
def test_S1_every_root_key_is_required(missing_key: str) -> None:
    candidate = _valid_console_document()
    del candidate[missing_key]
    _assert_matrix_direct_schema_failure(candidate)


def test_S1_unknown_root_key_is_rejected() -> None:
    candidate = _valid_console_document()
    candidate["schema-marker"] = True
    _assert_matrix_direct_schema_failure(candidate)


ROLE_MEMBER_CASES = tuple(
    (role, key)
    for role, members in ROLE_REQUIRED_MEMBERS.items()
    for key in members
)


@pytest.mark.parametrize(("role", "member"), ROLE_MEMBER_CASES)
def test_S1_every_agent_member_is_closed(role: str, member: str) -> None:
    missing = _valid_console_document()
    del missing["agents"][role][member]
    _assert_matrix_direct_schema_failure(missing)
    extra = _valid_console_document()
    extra["agents"][role]["extra-marker"] = "value"
    _assert_matrix_direct_schema_failure(extra)


@pytest.mark.parametrize(("role", "member"), ROLE_MEMBER_CASES)
def test_S1_every_required_agent_member_has_process_missing_envelope(
    role: str, member: str
) -> None:
    candidate = _valid_console_document()
    del candidate["agents"][role][member]
    path = _external_case_path(f"s1-missing-{role}-{member}.yaml")
    path.write_bytes(_dump_console_document(candidate))
    _assert_exact_t06c_process_failure(
        _run_source_console(path),
        "console_config_schema_invalid",
        "Console config violates its closed compatibility schema.",
        "console_config_validate",
        (role, *(() if member in {"role", "cli"} else (member,)), str(path), "S1-missing-sentinel"),
    )


@pytest.mark.parametrize("role", LITERAL_ROLES)
def test_S1_every_role_has_process_extra_envelope(role: str) -> None:
    candidate = _valid_console_document()
    candidate["agents"][role]["unexpected_agent_member"] = "S1-extra-marker"
    path = _external_case_path(f"s1-extra-{role}.yaml")
    path.write_bytes(_dump_console_document(candidate))
    _assert_exact_t06c_process_failure(
        _run_source_console(path),
        "console_config_schema_invalid",
        "Console config violates its closed compatibility schema.",
        "console_config_validate",
        (role, "unexpected_agent_member", "S1-extra-marker", str(path), "S1-extra-sentinel"),
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "version-type", "version-range", "created-type", "cost-type", "cost-range",
        "cost-order", "state-type", "state-order", "routing-type", "routing-value",
        "criteria-type", "criteria-empty", "criteria-long", "criteria-order",
    ),
)
def test_S1_nested_type_range_and_order_matrix(mutation: str) -> None:
    candidate = _valid_console_document()
    if mutation == "version-type":
        candidate["version"] = True
    elif mutation == "version-range":
        candidate["version"] = 6
    elif mutation == "created-type":
        candidate["created"] = "2026-01-01"
    elif mutation == "cost-type":
        candidate["cost_guardrails"]["max_cost_per_prd_usd"] = "1.00"
    elif mutation == "cost-range":
        candidate["cost_guardrails"]["max_cost_per_prd_usd"] = 1_000_001.0
    elif mutation == "cost-order":
        candidate["cost_guardrails"]["alert_threshold_usd"] = candidate["cost_guardrails"]["max_cost_per_prd_usd"] + 1.0
    elif mutation == "state-type":
        candidate["state_machine"]["states"] = "ready"
    elif mutation == "state-order":
        candidate["state_machine"]["states"] = list(reversed(candidate["state_machine"]["states"]))
    elif mutation == "routing-type":
        candidate["rejection_routing"] = []
    elif mutation == "routing-value":
        candidate["rejection_routing"]["ambiguous"] = "marker"
    elif mutation == "criteria-type":
        candidate["success_criteria"][0] = "rejection_count"
    elif mutation == "criteria-empty":
        candidate["success_criteria"][0]["rejection_count"] = ""
    elif mutation == "criteria-long":
        candidate["success_criteria"][0]["rejection_count"] = "x" * 257
    else:
        candidate["success_criteria"] = list(reversed(candidate["success_criteria"]))
    _assert_matrix_direct_schema_failure(candidate)


@pytest.mark.parametrize(
    ("mapping_name", "member", "mode"),
    tuple(
        (mapping_name, member, mode)
        for mapping_name, member in (
            ("state_machine", "states"),
            ("cost_guardrails", "max_cost_per_prd_usd"),
            ("cost_guardrails", "alert_threshold_usd"),
            ("rejection_routing", "architecture_issue"),
            ("rejection_routing", "bug_or_race"),
            ("rejection_routing", "ui_polish"),
            ("rejection_routing", "spec_is_wrong"),
            ("rejection_routing", "ambiguous"),
            ("success_criteria[0]", "rejection_count"),
            ("success_criteria[1]", "wall_clock"),
            ("success_criteria[2]", "cost"),
            ("success_criteria[3]", "post_push_issues"),
        )
        for mode in ("missing", "extra")
    ),
)
def test_S1_every_nested_closed_key_has_process_envelope(
    tmp_path: Path, mapping_name: str, member: str, mode: str
) -> None:
    candidate = _valid_console_document()
    if mapping_name.startswith("success_criteria"):
        mapping = candidate["success_criteria"][int(mapping_name[-2])]
    else:
        mapping = candidate[mapping_name]
    if mode == "missing":
        del mapping[member]
    else:
        mapping["S1-process-extra"] = 1.0 if mapping_name == "cost_guardrails" else "marker"
    path = tmp_path / f"s1-{mapping_name.replace('[', '-').replace(']', '')}-{member}-{mode}.yaml"
    path.write_bytes(_dump_console_document(candidate))
    expected = "console_config_schema_invalid"
    stage = "console_config_validate"
    _assert_matrix_process_failure(_run_source_console(path), expected, stage, "S1-process-extra")


def test_S1_schema_failure_process_envelope(tmp_path: Path) -> None:
    candidate = _valid_console_document()
    marker = "S1-schema-marker"
    candidate["schema-marker"] = marker
    path = tmp_path / "s1-schema-marker.yaml"
    path.write_bytes(_dump_console_document(candidate))
    _assert_matrix_process_failure(
        _run_source_console(path), "console_config_schema_invalid", "console_config_validate", marker
    )


@pytest.mark.parametrize(
    ("mapping_name", "member"),
    (
        ("state_machine", "states"),
        ("cost_guardrails", "max_cost_per_prd_usd"),
        ("cost_guardrails", "alert_threshold_usd"),
        ("rejection_routing", "architecture_issue"),
        ("rejection_routing", "bug_or_race"),
        ("rejection_routing", "ui_polish"),
        ("rejection_routing", "spec_is_wrong"),
        ("rejection_routing", "ambiguous"),
        ("success_criteria[0]", "rejection_count"),
        ("success_criteria[1]", "wall_clock"),
        ("success_criteria[2]", "cost"),
        ("success_criteria[3]", "post_push_issues"),
    ),
)
def test_S1_every_nested_mapping_key_is_closed(mapping_name: str, member: str) -> None:
    candidate = _valid_console_document()
    mapping: dict[str, object]
    if mapping_name.startswith("success_criteria"):
        index = int(mapping_name[-2])
        mapping = candidate["success_criteria"][index]
    else:
        mapping = candidate[mapping_name]
    del mapping[member]
    _assert_matrix_direct_schema_failure(candidate)
    candidate = _valid_console_document()
    if mapping_name.startswith("success_criteria"):
        mapping = candidate["success_criteria"][index]
    else:
        mapping = candidate[mapping_name]
    mapping["unexpected_nested_marker"] = "value"
    _assert_matrix_direct_schema_failure(candidate)


ALLOWLIST_PATHS = LITERAL_PATHS
PATH_ROLES = LITERAL_ROLES


@pytest.mark.parametrize("role", PATH_ROLES)
@pytest.mark.parametrize("position", ("reads", "writes"))
@pytest.mark.parametrize("allowed_path", ALLOWLIST_PATHS)
def test_S2_every_allowlisted_path_is_valid_for_every_role_and_position(
    role: str, position: str, allowed_path: str
) -> None:
    candidate = _valid_console_document()
    candidate["agents"][role][position] = [allowed_path]
    assert validate_console_schema(candidate)


PATH_REJECTION_CASES = (
    ("non-ascii", "artifacts/\u00e9.md"), ("empty", ""), ("dot", "."), ("dot-dot", ".."),
    ("absolute", "/absolute.md"), ("drive", "C:/absolute.md"), ("unc", "\\\\server\\share"),
    ("backslash", "artifacts\\file.md"), ("colon", "artifacts:file.md"), ("percent", "artifacts/%2f.md"),
    ("ascii-double-separator", "artifacts//00_input/prd.md"),
    ("confusable-separator", "artifacts\u221500_input/prd.md"), ("not-allowlisted", "artifacts/99_nope.md"),
    ("duplicate", None), ("non-string", 1), ("non-list", "artifacts/00_input/prd.md"),
    ("underflow", []), ("overflow", list(ALLOWLIST_PATHS) + [ALLOWLIST_PATHS[0]]),
)


@pytest.mark.parametrize(("case", "value"), PATH_REJECTION_CASES)
@pytest.mark.parametrize("role", PATH_ROLES)
@pytest.mark.parametrize("position", ("reads", "writes"))
def test_S2_every_path_rejection_class_is_closed_in_both_positions(
    case: str, value: object, role: str, position: str
) -> None:
    candidate = _valid_console_document()
    if case == "duplicate":
        candidate["agents"][role][position] = [ALLOWLIST_PATHS[0], ALLOWLIST_PATHS[0]]
    elif case in {"non-list", "non-string"}:
        candidate["agents"][role][position] = value
    else:
        candidate["agents"][role][position] = value if isinstance(value, list) else [value]
    _assert_matrix_direct_schema_failure(candidate)


def test_S2_rejected_path_has_exact_process_schema_envelope(tmp_path: Path) -> None:
    candidate = _valid_console_document()
    marker = "S2-invalid-path-marker"
    candidate["agents"]["g1d"]["reads"] = [marker]
    path = tmp_path / "s2-invalid-path.yaml"
    path.write_bytes(_dump_console_document(candidate))
    _assert_matrix_process_failure(
        _run_source_console(path), "console_config_schema_invalid", "console_config_validate", marker
    )


@pytest.mark.parametrize(("case", "value"), PATH_REJECTION_CASES)
def test_S2_every_path_rejection_class_has_process_envelope(
    tmp_path: Path, case: str, value: object
) -> None:
    candidate = _valid_console_document()
    if case == "duplicate":
        candidate["agents"]["g1d"]["reads"] = [ALLOWLIST_PATHS[0], ALLOWLIST_PATHS[0]]
    elif case in {"non-list", "non-string"}:
        candidate["agents"]["g1d"]["reads"] = value
    else:
        candidate["agents"]["g1d"]["reads"] = value if isinstance(value, list) else [value]
    path = tmp_path / f"s2-{case}.yaml"
    path.write_bytes(_dump_console_document(candidate))
    expected = "console_config_syntax_invalid" if case == "non-string" else "console_config_schema_invalid"
    stage = "console_config_parse" if expected.endswith("syntax_invalid") else "console_config_validate"
    _assert_matrix_process_failure(_run_source_console(path), expected, stage, "S2-process-marker")


@pytest.mark.parametrize("position", ("reads", "writes"))
def test_S2_list_non_string_member_direct_resolver_exact_envelope(position: str) -> None:
    candidate = _valid_console_document()
    candidate["agents"]["g1d"][position] = ["artifacts/00_input/prd.md", 1]
    raw = _dump_console_document(candidate)
    with pytest.raises(ConsoleSyntaxError):
        preflight_console_yaml(raw)
    with patch.object(console_app, "read_bounded_legacy_config", return_value=raw):
        envelope = console_app.import_v5_path(f"S2-direct-{position}-sentinel.yaml")
    _assert_exact_t06c_failure(
        envelope,
        "console_config_syntax_invalid",
        "Console config syntax is invalid.",
        "console_config_parse",
        ("artifacts/00_input/prd.md", "g1d", position, "S2-list-member-sentinel"),
    )


@pytest.mark.parametrize("position", ("reads", "writes"))
def test_S2_list_non_string_member_process_exact_envelope(position: str) -> None:
    candidate = _valid_console_document()
    candidate["agents"]["g1d"][position] = ["artifacts/00_input/prd.md", 1]
    path = _external_case_path(f"s2-list-non-string-{position}.yaml")
    path.write_bytes(_dump_console_document(candidate))
    result = _run_source_console(path)
    _assert_exact_t06c_process_failure(
        result,
        "console_config_syntax_invalid",
        "Console config syntax is invalid.",
        "console_config_parse",
        ("artifacts/00_input/prd.md", "g1d", position, str(path), "S2-list-member-sentinel"),
    )
    assert re.search(rb"(?<![A-Za-z0-9_.-])1(?![A-Za-z0-9_.-])", result.stdout) is None


@pytest.mark.parametrize("role", PATH_ROLES)
def test_M1_every_raw_and_oracle_role_contract_is_exact(role: str) -> None:
    document = _valid_console_document()
    finding, reference = load_v5_config_reference()
    assert finding is None and reference is not None
    raw = document["agents"][role]
    expected_raw = LITERAL_RAW_AGENTS[role]
    expected_keys = {"role", "model", "cli", "prompt", "reads", "writes"} | (
        set(expected_raw) - {"role", "model", "cli", "prompt"}
    )
    if role == "refine_bug":
        expected_keys.add("notes")
    assert set(raw) == expected_keys
    for key, value in expected_raw.items():
        assert raw[key] == value
    oracle = next(item for item in reference["agents"] if item["role_id"] == role)
    for key, value in LITERAL_ORACLE_AGENTS[role].items():
        assert oracle[key] == value
    assert console_domain.validate_console_mapping(document, reference)


ROLE_MUTATION_CASES = tuple(
    (role, field)
    for role in PATH_ROLES
    for field in ("model", "cli", "prompt", "endpoint")
    if field in LITERAL_RAW_AGENTS[role]
)


@pytest.mark.parametrize(("role", "field"), ROLE_MUTATION_CASES)
def test_M1_each_role_binding_field_mutation_is_mapping_unsupported(role: str, field: str) -> None:
    document = _valid_console_document()
    finding, reference = load_v5_config_reference()
    assert finding is None and reference is not None
    document["agents"][role][field] = "M1-unsupported-marker"
    assert not console_domain.validate_console_mapping(document, reference)


def test_M1_mapping_failure_has_exact_process_envelope(tmp_path: Path) -> None:
    candidate = _valid_console_document()
    marker = "M1-process-marker"
    candidate["agents"]["g1d"]["model"] = marker
    path = tmp_path / "m1-mapping.yaml"
    path.write_bytes(_dump_console_document(candidate))
    _assert_matrix_process_failure(
        _run_source_console(path), "console_config_mapping_unsupported", "console_config_map", marker, "/agents"
    )


@pytest.mark.parametrize(("role", "field"), ROLE_MUTATION_CASES)
def test_M1_every_literal_binding_field_has_process_envelope(
    tmp_path: Path, role: str, field: str
) -> None:
    candidate = _valid_console_document()
    marker = f"M1-process-{role}-{field}"
    candidate["agents"][role][field] = marker
    path = tmp_path / f"m1-{role}-{field}.yaml"
    path.write_bytes(_dump_console_document(candidate))
    _assert_matrix_process_failure(
        _run_source_console(path), "console_config_mapping_unsupported", "console_config_map", marker, "/agents"
    )


def test_M2_all_raw_oracle_target_transitions_are_pinned(capsys) -> None:
    finding, reference = load_v5_config_reference()
    assert finding is None and reference is not None
    document = _valid_console_document()
    assert console_domain.validate_console_mapping(document, reference)
    expected = {
        "g1d": ("claude-fable-5", "claude-opus-4-7", "claude-opus-4-8"),
        "g2a": ("claude-opus-4-7", "claude-opus-4-7", "claude-opus-4-8"),
        "refine_bug": ("kimi-k3", "kimi-k2.7-code", "kimi-k2.7-code"),
        "g1r": ("claude-opus-4-7", "claude-opus-4-7", "claude-opus-4-7"),
        "builder": ("deepseek-v4-pro", "deepseek-v4-pro", "deepseek-v4-pro"),
        "refine_ui": ("glm-5.2", "glm-5.2", "glm-5.2"),
    }
    for role, (raw_model, oracle_model, target_model) in expected.items():
        assert document["agents"][role]["model"] == raw_model
        oracle = next(item for item in reference["agents"] if item["role_id"] == role)
        assert oracle["model"] == oracle_model
        assert target_model
        drifted_reference = copy.deepcopy(reference)
        drifted = next(item for item in drifted_reference["agents"] if item["role_id"] == role)
        drifted["model"] = "M2-oracle-drift-marker"
        assert not console_domain.validate_console_mapping(document, drifted_reference)
    code, result, stderr = _run(capsys, FIXTURE)
    assert code == 0 and stderr == ""
    assert result["data"]["runtime_effective"] is False
    assert result["data"]["canonical_target_config_sha256"] == TARGET_SHA256


@pytest.mark.parametrize("finding_id", ("oracle_model_mismatch_g1d", "oracle_model_mismatch_g2a", "oracle_fixture_missing"))
def test_M2_oracle_integrity_failure_keeps_existing_source_free_envelope(
    monkeypatch, capsys, finding_id: str
) -> None:
    monkeypatch.setattr(console_app, "load_v5_config_reference", lambda: (finding_id, None))
    code, result, stderr = _run(capsys, FIXTURE)
    assert code == 3 and stderr == ""
    assert result["command"] == "config_import_v5_console"
    assert result["findings"][0]["id"] == finding_id
    assert result["findings"][0]["path"] == "/packaged_reference"
    assert result["snapshot"]["resolution_stage"] == "oracle_validate"
    assert result["snapshot"]["config_path"] is None
    assert result["data"] == {}


def test_M2_target_projection_mismatch_keeps_existing_finding(monkeypatch, capsys) -> None:
    monkeypatch.setattr(console_app, "target_config", lambda: {})
    code, result, stderr = _run(capsys, FIXTURE)
    assert code == 2 and stderr == ""
    assert result["findings"][0]["id"] == "console_config_projection_invalid"
    assert result["findings"][0]["path"] == "/target_config"
    assert result["snapshot"]["resolution_stage"] == "console_config_project"
    assert result["data"] == {}


@pytest.mark.parametrize("role", LITERAL_ROLES)
def test_M2_literal_target_connector_and_oracle_fields_are_exact(role: str) -> None:
    from torq_cli.domain.v5_config_import import target_config

    finding, reference = load_v5_config_reference()
    assert finding is None and reference is not None
    target = target_config()
    expected_connector = {
        "g1d": ("anthropic-agent-sdk", "anthropic", "agent_sdk"),
        "g1r": ("anthropic-agent-sdk", "anthropic", "agent_sdk"),
        "builder": ("deepseek-direct-api", "deepseek", "direct_api"),
        "g2a": ("anthropic-agent-sdk", "anthropic", "agent_sdk"),
        "refine_bug": ("moonshot-direct-api", "moonshot", "direct_api"),
        "refine_ui": ("zai-direct-api", "zai", "direct_api"),
    }[role]
    binding = target["binding_overrides"][role]
    assert binding == {"connector_id": expected_connector[0], "enabled": True}
    assert target["connectors"][expected_connector[0]] == {
        "enabled": True, "provider_id": expected_connector[1], "surface": expected_connector[2]
    }
    assert LITERAL_ORACLE_AGENTS[role] == next(item for item in reference["agents"] if item["role_id"] == role)


@pytest.mark.parametrize(
    ("role", "field"),
    tuple((role, field) for role in LITERAL_ROLES for field in ("role", "model", "cli", "prompt", "endpoint") if field in LITERAL_RAW_AGENTS[role]),
)
def test_M2_each_literal_raw_binding_field_drift_is_rejected(role: str, field: str) -> None:
    finding, reference = load_v5_config_reference()
    assert finding is None and reference is not None
    document = _valid_console_document()
    document["agents"][role][field] = "M2-raw-drift-marker"
    assert not console_domain.validate_console_mapping(document, reference)
    drifted_reference = copy.deepcopy(reference)
    oracle = next(item for item in drifted_reference["agents"] if item["role_id"] == role)
    oracle[field if field != "role" else "role_id"] = "M2-oracle-drift-marker"
    assert not console_domain.validate_console_mapping(_valid_console_document(), drifted_reference)


DENIED_KEY_VARIANTS = tuple(LITERAL_DENIED_KEYS) + tuple(
    key.upper() for key in LITERAL_DENIED_KEYS
) + tuple(key.replace("_", "-") for key in LITERAL_DENIED_KEYS) + ("se\u0063ret", "TOKEN", "Api-Key")


@pytest.mark.parametrize("key", DENIED_KEY_VARIANTS)
def test_X1_every_denied_key_variant_is_detected_directly(key: str) -> None:
    assert console_domain.contains_console_secret({key: "X1-key-marker"})


@pytest.mark.parametrize("key", DENIED_KEY_VARIANTS)
def test_X1_every_denied_key_variant_has_process_no_disclosure(tmp_path: Path, key: str) -> None:
    marker = "X1-key-marker"
    document = _valid_console_document()
    document["secret-marker"] = {key: marker}
    path = tmp_path / "x1-key.yaml"
    path.write_bytes(_dump_console_document(document))
    _assert_matrix_process_failure(
        _run_source_console(path), "console_config_secret_field_forbidden", "console_config_validate", marker
    )


SECRET_VALUE_CASES = (
    ("pem", "-----BEGIN PRIVATE KEY-----"),
    ("bearer", "Bearer abcdefgh"),
    ("basic", "Basic abcdefgh"),
    ("akia", "AKIA1234567890ABCDEF"),
    ("jwt-valid", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"),
    ("malformed-authority", "https://example.com:bad/path?x=1"),
    ("malformed-port-zero", "https://example.com:0/path?x=1"),
    ("malformed-port-range", "https://example.com:65536/path?x=1"),
    ("malformed-bracket-authority", "https://[::1]/path?x=1"),
    ("malformed-userinfo-authority", "https://user@example.com/path?x=1"),
    ("malformed-host", "https://-example.com/path?x=1"),
    ("malformed-query", "https://example.com/path?&x=1"),
    ("malformed-query-empty-component", "https://example.com/path?x=1&&signature=abcdefgh"),
    ("malformed-query-percent", "https://example.com/path?signature=%ZZ"),
    ("malformed-query-no-equals", "https://example.com/path?signature&x=1&signature=abcdefgh"),
)

SECRET_VALUE_CASES += tuple(
    (f"token-prefix-{prefix}", f"{prefix}abcdefgh12345678")
    for prefix in ("sk-", "sk_", "rk_", "ghp_", "github_pat_")
)
SECRET_VALUE_CASES += tuple(
    (f"assignment-{label}-{delimiter}", f"{label}{delimiter}abcdefgh")
    for label in ("authorization", "proxy-authorization", "cookie", "set-cookie")
    for delimiter in (":", "=")
)


def _percent_encode_ascii(value: str) -> str:
    return "".join(f"%{ord(character):02x}" for character in value)


SIGNED_QUERY_NAMES = (
    "signature", "sig", "x_amz_signature", "x_goog_signature",
    "token", "access_token", "api_key", "x_api_key",
)
SECRET_VALUE_CASES += tuple(
    (f"signed-url-{name}", f"https://example.com/path?{name}=abcdefgh")
    for name in SIGNED_QUERY_NAMES
)
SECRET_VALUE_CASES += tuple(
    (f"signed-url-encoded-name-{name}", f"https://example.com/path?{_percent_encode_ascii(name)}=abcdefgh")
    for name in SIGNED_QUERY_NAMES
)
SECRET_VALUE_CASES += tuple(
    (f"signed-url-encoded-value-{name}", f"https://example.com/path?{name}=%61bcdefgh")
    for name in SIGNED_QUERY_NAMES
)


@pytest.mark.parametrize(("label", "value"), SECRET_VALUE_CASES)
def test_X1_secret_value_detector_matrix_is_ordered_and_source_free(label: str, value: str, tmp_path: Path) -> None:
    assert console_domain.contains_console_secret({"note": value})
    document = _valid_console_document()
    document["secret-marker"] = value
    path = tmp_path / f"x1-{label.replace(':', '_')}.yaml"
    path.write_bytes(_dump_console_document(document))
    result = _run_source_console(path)
    _assert_matrix_process_failure(
        result, "console_config_secret_field_forbidden", "console_config_validate", value
    )
    output = result.stdout.decode("utf-8") + result.stderr.decode("utf-8")
    assert all(
        marker not in output
        for marker in (
            "secret-marker", value, str(path), path.name,
            "ProtectedPathError", "LegacyConfigUnreadable", "LegacyConfigTooLarge",
        )
    )


@pytest.mark.parametrize(
    "value",
    (
        "Bearer", "sk-short", "aaaaaaa.bbbbbbb.ccccccc", "https://example.com/path?signature",
        "https://example.com/path?%2573ignature=abcdefgh", "https://example.com/path?x=1",
        "https://example.com/path?x&y=1", "plain harmless metadata",
    ),
)
def test_X1_valid_nonsecret_near_misses_remain_valid(value: str) -> None:
    assert not console_domain.contains_console_secret({"note": value})


def test_X1_first_secret_stops_scalar_traversal_and_preserves_order(monkeypatch) -> None:
    calls: list[str] = []

    def spy(value: str) -> bool:
        calls.append(value)
        return value == "X1-first-secret"

    monkeypatch.setattr(console_domain, "_scalar_has_secret", spy)
    assert console_domain.contains_console_secret({"first": "X1-first-secret", "later": "X1-later"})
    assert calls == ["X1-first-secret"]
    calls.clear()
    assert console_domain.contains_console_secret({"later": "X1-later", "first": "X1-first-secret"})
    assert calls == ["X1-later", "X1-first-secret"]


def test_X1_committed_product_import_audit_has_no_network_clients() -> None:
    forbidden = re.compile(r"^\s*(?:from|import)\s+(?:urllib|requests|httpx|socket)\b", re.MULTILINE)
    for relative in ("src/torq_cli/domain/v5_console_config_import.py", "scripts/provision_ci_wheelhouse.py"):
        source = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert forbidden.search(source) is None


METADATA_CASES = tuple(
    [("path", role, position, path) for role in PATH_ROLES for position in ("reads", "writes") for path in ALLOWLIST_PATHS]
    + [("cost", "", "", "cost-marker")]
    + [("criteria", "", criterion, "criteria-marker") for criterion in LITERAL_CRITERIA]
    + [("notes", "refine_bug", "", "notes-marker")]
)


@pytest.mark.parametrize(("kind", "role", "position", "value"), METADATA_CASES)
def test_D1_discarded_metadata_keeps_fixed_projection(
    monkeypatch, capsys, kind: str, role: str, position: str, value: str
) -> None:
    candidate = _valid_console_document()
    marker = f"D1-{kind}-{role}-{position}-{value}"
    if kind == "path":
        candidate["agents"][role][position] = [value]
    elif kind == "cost":
        candidate["cost_guardrails"] = {"max_cost_per_prd_usd": 7.00, "alert_threshold_usd": 2.00}
    elif kind == "criteria":
        criteria = next(item for item in candidate["success_criteria"] if position in item)
        criteria[position] = marker
    else:
        candidate["agents"][role]["notes"] = marker
    assert validate_console_schema(candidate)
    with patch.object(console_app, "read_bounded_legacy_config", return_value=_dump_console_document(candidate)):
        code, result, stderr = _run(capsys, FIXTURE)
    assert code == 0 and stderr == ""
    target = result["data"]["canonical_target_config_utf8"].encode("utf-8")
    assert len(target) == 1_029
    assert hashlib.sha256(target).hexdigest() == TARGET_SHA256
    assert result["data"]["runtime_effective"] is False
    assert marker not in json.dumps(result, sort_keys=True)


@pytest.mark.parametrize(
    ("mapping_name", "member"),
    tuple(("state_machine", member) for member in ("states",)) + tuple(
        ("rejection_routing", member) for member in LITERAL_ROUTING
    ),
)
def test_D1_fixed_state_and_routing_metadata_are_closed(mapping_name: str, member: str) -> None:
    candidate = _valid_console_document()
    if mapping_name == "state_machine":
        candidate[mapping_name][member] = list(reversed(LITERAL_STATE_STATES))
    else:
        candidate[mapping_name][member] = "D1-fixed-metadata-marker"
    _assert_matrix_direct_schema_failure(candidate)


REGISTRY_EXCEPTION_CASES = (
    ("missing", RegistryResourceMissing(), "registry_resource_missing", "registry_read", 2),
    ("unreadable", RegistryUnreadable(), "registry_unreadable", "registry_read", 2),
    ("syntax", RegistrySyntaxError(), "registry_syntax_invalid", "registry_parse", 2),
    ("schema", RegistryDocumentError(), "registry_schema_invalid", "registry_validate", 2),
)
R1_PRELOAD_MESSAGES = {
    "registry_resource_missing": "Packaged registry resource is missing.",
    "registry_unreadable": "Packaged registry cannot be read.",
    "registry_syntax_invalid": "Packaged registry syntax is invalid.",
    "registry_schema_invalid": "Packaged registry violates its closed schema.",
}
R1_LOADED_MESSAGES = {
    "registry_version_unsupported": "Registry version is unsupported.",
    "registry_duplicate_identity": "Registry contains a duplicate identity.",
    "registry_prompt_hash_mismatch": "Packaged prompt identity hash does not match resource bytes.",
    "registry_transition_invalid": "Registry contains an invalid transition edge.",
    "registry_profile_invalid": "Registry profile violates required cardinality or reference rules.",
    "policy_contract_hash_mismatch": "Policy contract hash does not match canonical policy bytes.",
    "binding_ineligible": "Binding violates role eligibility rules.",
}


@pytest.mark.parametrize(("label", "exception", "finding_id", "stage", "code"), REGISTRY_EXCEPTION_CASES)
def test_R1_registry_preload_exceptions_have_exact_envelope(
    monkeypatch, capsys, label: str, exception: Exception, finding_id: str, stage: str, code: int
) -> None:
    def fail() -> object:
        raise exception

    monkeypatch.setattr(console_app, "load_registry", fail)
    actual_code, result, stderr = _run(capsys, FIXTURE)
    assert actual_code == code and stderr == ""
    assert result["command"] == "config_import_v5_console"
    assert result["status"] == "invalid"
    assert result["findings"][0] == {
        "bucket": "B", "context": {}, "id": finding_id, "message": R1_PRELOAD_MESSAGES[finding_id],
        "path": "/registry", "severity": "high", "stage": stage, "status_class": "invalid",
    }
    assert result["data"] == {}
    assert result["snapshot"]["registry_id"] is None
    assert result["snapshot"]["registry_version"] is None
    assert result["snapshot"]["registry_resource_sha256"] is None
    assert result["snapshot"]["config_path"] is None
    assert result["snapshot"]["config_version"] is None
    assert result["snapshot"]["profile_id"] is None
    assert result["snapshot"]["profile_version"] is None
    assert result["snapshot"]["resolution_stage"] == stage
    assert label


def _registry_validation_mutation(label: str):
    registry = load_registry()
    if label == "version":
        return replace(registry, registry_version="9.9.9"), "registry_version_unsupported", 2
    if label == "duplicate":
        raw = dict(registry.raw_document)
        raw["roles"] = list(raw["roles"]) + [dict(raw["roles"][0])]
        return replace(registry, raw_document=raw), "registry_duplicate_identity", 2
    if label == "prompt":
        prompt = registry.prompts["live.g1d.design"]
        changed = {**registry.prompts, prompt.prompt_id: replace(prompt, content_sha256="0" * 64)}
        return replace(registry, prompts=changed), "registry_prompt_hash_mismatch", 2
    if label == "transition":
        return replace(registry, transitions=()), "registry_transition_invalid", 2
    if label == "profile":
        return replace(registry, profiles={}), "registry_profile_invalid", 2
    if label == "policy":
        return replace(registry, policy=replace(registry.policy, contract_sha256="0" * 64)), "policy_contract_hash_mismatch", 2
    profile = registry.profiles["torq-v5-6-live"]
    binding = replace(profile.bindings["builder"], model_id="glm-5.2")
    changed_profile = replace(profile, bindings={**profile.bindings, "builder": binding})
    return replace(registry, profiles={**registry.profiles, profile.profile_id: changed_profile}), "binding_ineligible", 2


@pytest.mark.parametrize("label", ("version", "duplicate", "prompt", "transition", "profile", "policy", "binding"))
def test_R1_registry_loaded_validation_and_binding_precedence(monkeypatch, capsys, label: str) -> None:
    registry, finding_id, expected_code = _registry_validation_mutation(label)
    monkeypatch.setattr(console_app, "load_registry", lambda: registry)
    code, result, stderr = _run(capsys, FIXTURE)
    assert code == expected_code and stderr == ""
    assert result["findings"][0]["id"] == finding_id
    assert result["findings"][0] == {
        "bucket": "C" if finding_id == "binding_ineligible" else "B", "context": {}, "id": finding_id,
        "message": R1_LOADED_MESSAGES[finding_id], "path": "/registry",
        "severity": "medium" if finding_id == "binding_ineligible" else "high",
        "stage": "eligibility" if finding_id == "binding_ineligible" else "registry_validate",
        "status_class": "blocked" if finding_id == "binding_ineligible" else "invalid",
    }
    assert result["status"] == "invalid"
    assert result["findings"][0]["path"] == "/registry"
    assert result["snapshot"]["resolution_stage"] == "registry_validate"
    assert result["snapshot"]["registry_id"] is not None
    assert result["snapshot"]["config_path"] is None
    assert result["snapshot"]["config_version"] is None
    assert result["snapshot"]["profile_id"] is None
    assert result["snapshot"]["registry_id"] == "torq-cli-role-registry"
    assert result["snapshot"]["registry_resource_sha256"] == "e6c378aa5104b871baf6c6404f13d1373a5ec7cbf486283a0a28dab73da87128"
    assert result["snapshot"]["registry_version"] == ("9.9.9" if label == "version" else "1.0.0")
    if label == "binding":
        assert result["findings"][1] == {
            "bucket": "B", "context": {}, "id": "registry_profile_invalid",
            "message": R1_LOADED_MESSAGES["registry_profile_invalid"], "path": "/registry", "severity": "high",
            "stage": "registry_validate", "status_class": "invalid",
        }
    assert result["data"] == {}


def test_R1_invalid_finding_precedes_binding_only_finding(monkeypatch, capsys) -> None:
    monkeypatch.setattr(console_app, "validate_registry", lambda _: ("binding_ineligible", "registry_schema_invalid"))
    code, result, stderr = _run(capsys, FIXTURE)
    assert code == 2 and stderr == ""
    assert result["findings"] == [
        {
            "bucket": "C", "context": {}, "id": "binding_ineligible",
            "message": R1_LOADED_MESSAGES["binding_ineligible"], "path": "/registry", "severity": "medium",
            "stage": "eligibility", "status_class": "blocked",
        },
        {
            "bucket": "B", "context": {}, "id": "registry_schema_invalid",
            "message": R1_PRELOAD_MESSAGES["registry_schema_invalid"], "path": "/registry", "severity": "high",
            "stage": "registry_validate", "status_class": "invalid",
        },
    ]
    assert result["status"] == "invalid"
    assert result["snapshot"]["resolution_stage"] == "registry_validate"


def test_R1_binding_only_is_blocked_with_exit_three(monkeypatch, capsys) -> None:
    monkeypatch.setattr(console_app, "validate_registry", lambda _: ("binding_ineligible",))
    code, result, stderr = _run(capsys, FIXTURE)
    assert code == 3 and stderr == ""
    assert result["status"] == "blocked"
    assert result["findings"][0]["id"] == "binding_ineligible"
    assert result["findings"][0] == {
        "bucket": "C", "context": {}, "id": "binding_ineligible",
        "message": R1_LOADED_MESSAGES["binding_ineligible"], "path": "/registry", "severity": "medium",
        "stage": "eligibility", "status_class": "blocked",
    }
    assert result["snapshot"]["registry_id"] is not None
    assert result["snapshot"]["config_version"] is None
    assert result["data"] == {}


@pytest.mark.parametrize(
    "finding_id",
    (
        "oracle_fixture_hash_mismatch", "oracle_fixture_schema_invalid", "oracle_prompt_mismatch_g2a",
        "oracle_prompt_path_missing_g2a_adversarial", "oracle_manifest_trusted_hash_mismatch",
    ),
)
def test_R2_all_oracle_failure_ids_keep_blocked_source_free_envelope(
    monkeypatch, capsys, finding_id: str
) -> None:
    monkeypatch.setattr(console_app, "load_v5_config_reference", lambda: (finding_id, None))
    code, result, stderr = _run(capsys, FIXTURE)
    assert code == 3 and stderr == ""
    assert result["status"] == "blocked"
    assert result["findings"][0]["id"] == finding_id
    assert result["findings"][0]["path"] == "/packaged_reference"
    assert result["snapshot"]["registry_id"] is not None
    assert result["snapshot"]["resolution_stage"] == "oracle_validate"
    assert result["snapshot"]["config_path"] is None
    assert result["data"] == {}


T06C_APPLICATION_MATRIX = (
    ("application-unreadable", LegacyConfigUnreadable(), "console_config_unreadable", "console_config_read", 2, "/console_config"),
    ("application-too-large", LegacyConfigTooLarge(), "console_config_syntax_invalid", "console_config_parse", 2, "/"),
    ("application-protected", ProtectedPathError(), "console_config_protected_path_denied", "console_config_read", 3, "/console_config"),
    ("application-reparse", ProtectedPathError(), "console_config_protected_path_denied", "console_config_read", 3, "/console_config"),
    ("application-hardlink-translation", ProtectedPathError(), "console_config_protected_path_denied", "console_config_read", 3, "/console_config"),
    ("application-nonregular-translation", ProtectedPathError(), "console_config_protected_path_denied", "console_config_read", 3, "/console_config"),
    ("application-identity-translation", ProtectedPathError(), "console_config_protected_path_denied", "console_config_read", 3, "/console_config"),
    ("application-safety-primitive-translation", ProtectedPathError(), "console_config_protected_path_denied", "console_config_read", 3, "/console_config"),
)
T06C_PROTECTED_APPLICATION_ROWS = frozenset(
    {
        "application-protected",
        "application-reparse",
        "application-hardlink-translation",
        "application-nonregular-translation",
        "application-identity-translation",
        "application-safety-primitive-translation",
    }
)


def test_H1_application_matrix_names_every_protected_outcome() -> None:
    protected_rows = {
        label
        for label, _exception, expected_id, _stage, _code, _path in T06C_APPLICATION_MATRIX
        if expected_id == "console_config_protected_path_denied"
    }
    assert protected_rows == T06C_PROTECTED_APPLICATION_ROWS


@pytest.mark.parametrize(
    ("label", "exception", "expected_id", "expected_stage", "expected_code", "expected_path"),
    T06C_APPLICATION_MATRIX,
)
def test_H1_application_boundary_translation_is_single_read_and_exact(
    monkeypatch, capsys, label: str, exception: Exception, expected_id: str,
    expected_stage: str, expected_code: int, expected_path: str,
) -> None:
    calls: list[str] = []

    def fail(path: str) -> bytes:
        calls.append(path)
        raise exception

    monkeypatch.setattr(console_app, "read_bounded_legacy_config", fail)
    code, result, stderr = _run(capsys, FIXTURE)
    assert code == expected_code and stderr == ""
    assert result["status"] == ("blocked" if expected_code == 3 else "invalid")
    assert result["findings"][0]["id"] == expected_id
    assert result["findings"][0]["stage"] == expected_stage
    assert result["findings"][0]["path"] == expected_path
    assert result["findings"][0]["context"] == {}
    assert result["findings"][0]["status_class"] == ("blocked" if expected_code == 3 else "invalid")
    assert result["findings"][0]["bucket"] == ("A" if expected_code == 3 else "B")
    assert result["findings"][0]["severity"] == ("critical" if expected_code == 3 else "high")
    assert result["data"] == {}
    assert result["snapshot"]["registry_id"] is not None
    assert result["snapshot"]["config_path"] is None
    assert result["snapshot"]["profile_id"] is None
    assert result["snapshot"]["resolution_stage"] == expected_stage
    assert len(calls) == 1
    assert label


def test_H1_process_unreadable_and_too_large_are_source_free(tmp_path: Path) -> None:
    missing = tmp_path / "missing-reader-marker.yaml"
    unreadable = _run_source_console(missing)
    _assert_matrix_process_failure(
        unreadable, "console_config_unreadable", "console_config_read", "missing-reader-marker", "/console_config"
    )
    oversized = tmp_path / "oversized-reader-marker.yaml"
    oversized.write_bytes(FIXTURE.read_bytes() + b"\n#" + b"x" * (65_537 - len(FIXTURE.read_bytes()) - 2))
    _assert_matrix_process_failure(
        _run_source_console(oversized), "console_config_syntax_invalid", "console_config_parse", "oversized-reader-marker"
    )


def test_W1_hash_package_misassociation_is_rejected(tmp_path: Path) -> None:
    lines = LOCK.read_text(encoding="utf-8").splitlines()
    pyyaml_hash = next(line for line in lines if line.startswith("    --hash=sha256:"))
    setuptools_line = next(index for index, line in enumerate(lines) if line.startswith("setuptools=="))
    lines[setuptools_line + 1] = pyyaml_hash
    path = tmp_path / "misassociated-lock.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        _validate_lock(path, _complete_manifest_hashes())


@pytest.mark.parametrize("line", (" ", "\t", "# comment", "--no-index", "--find-links=x", "-e file:///x"))
def test_W1_every_unexpected_lock_physical_line_class_is_rejected(tmp_path: Path, line: str) -> None:
    path = tmp_path / "physical-line-lock.txt"
    needle = "setuptools==82.0.1 " + "\\"
    replacement = line + "\nsetuptools==82.0.1 " + "\\"
    payload = LOCK.read_text(encoding="utf-8").replace(needle, replacement, 1)
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(SystemExit):
        _lock_hashes(path)


def _lock_mutation_for_main(label: str) -> bytes:
    lines = LOCK.read_text(encoding="utf-8").splitlines()
    if label == "extra-hash":
        index = next(index for index, line in enumerate(lines) if line.startswith("    --hash=sha256:3ad2"))
        lines[index] += " \\"
        lines.insert(index + 1, "    --hash=sha256:" + "f" * 64)
    elif label == "appended-comment":
        lines.append("# appended comment")
    elif label == "missing-hash":
        index = next(index for index, line in enumerate(lines) if line.startswith("    --hash=sha256:3ad2"))
        lines.pop(index)
    elif label == "duplicate-hash":
        index = next(index for index, line in enumerate(lines) if line.startswith("    --hash=sha256:3ad2"))
        lines[index] += " \\"
        lines.insert(index + 1, lines[index].replace(" \\", ""))
    elif label == "misassociated-hash":
        index = next(index for index, line in enumerate(lines) if line.startswith("setuptools==")) + 1
        lines[index] = "    --hash=sha256:e10ce637b18caea04431ce14fabcf5c64a1c61ec9c56b071a4b7ca131ca52d44"
    elif label == "malformed-continuation":
        index = next(index for index, line in enumerate(lines) if line.startswith("    --hash=sha256:"))
        lines[index] = "    --hash=sha256:not-a-digest"
    elif label == "unsupported-option":
        lines[0] = "--no-index"
    elif label == "wrong-order":
        first = next(index for index, line in enumerate(lines) if line.startswith("setuptools=="))
        second = next(index for index, line in enumerate(lines) if line.startswith("wheel=="))
        lines[first], lines[second] = lines[second], lines[first]
    elif label == "incomplete-set":
        lines = lines[:-2]
    elif label == "physical-line-ending":
        pass
    else:
        raise AssertionError(label)
    payload = "\n".join(lines) + "\n"
    if label == "physical-line-ending":
        return payload.replace("\n", "\r").encode("utf-8")
    return payload.encode("utf-8")


@pytest.mark.parametrize(
    ("label", "expected_message"),
    (
        ("extra-hash", "complete manifest"),
        ("appended-comment", "unexpected trailing line"),
        ("missing-hash", "requires a hash line"),
        ("duplicate-hash", "duplicate hash"),
        ("misassociated-hash", "complete manifest"),
        ("malformed-continuation", "requires a hash line"),
        ("unsupported-option", "unsupported global option"),
        ("wrong-order", "package order is invalid"),
        ("physical-line-ending", "invalid line ending"),
        ("incomplete-set", "incomplete"),
    ),
)
def test_W1_main_rejects_every_lock_grammar_family_before_download(
    monkeypatch, tmp_path: Path, label: str, expected_message: str
) -> None:
    import scripts.provision_ci_wheelhouse as provisioner

    lock = tmp_path / f"{label}.txt"
    lock.write_bytes(_lock_mutation_for_main(label))
    root = tmp_path / f"{label}-root"
    monkeypatch.setenv("TORQ_T06C_CI_TEMP_ROOT", str(tmp_path.parent))
    monkeypatch.delenv("TORQ_T06C_OFFICIAL_INDEX", raising=False)
    monkeypatch.setattr(provisioner, "_assert_runtime", lambda _: None)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        provisioner.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command) or SimpleNamespace(returncode=0),
    )
    with pytest.raises(SystemExit, match=expected_message):
        provisioner.main([
            "--root", str(root), "--platform", "linux-py311", "--lock", str(lock), "--manifest", str(MANIFEST)
        ])
    assert calls == []


@pytest.mark.parametrize(
    "label",
    (
        "malformed-record", "wrong-platform", "wrong-architecture", "wrong-python-tag", "wrong-abi-tag",
        "wrong-platform-tag", "wrong-filename", "wrong-size", "wrong-hash", "duplicate", "missing", "extra",
        "cross-platform-misassociation",
    ),
)
def test_W2_main_rejects_each_artifact_contract_dimension_before_download(
    monkeypatch, tmp_path: Path, label: str
) -> None:
    import scripts.provision_ci_wheelhouse as provisioner

    manifest = _load_manifest(MANIFEST)
    records = manifest["platforms"]["linux-py311"]["artifacts"]
    assert isinstance(records, list)
    if label == "malformed-record":
        del records[0]["sha256"]
    elif label in {"wrong-platform", "wrong-platform-tag"}:
        records[0]["platform_tag"] = "win_amd64"
    elif label == "wrong-architecture":
        records[0]["filename"] = "PyYAML-6.0.2-cp311-cp311-manylinux_2_17_aarch64.whl"
    elif label == "wrong-python-tag":
        records[0]["python_tag"] = "cp310"
    elif label == "wrong-abi-tag":
        records[0]["abi_tag"] = "abi3"
    elif label == "wrong-filename":
        records[0]["filename"] = "PyYAML-6.0.2-cp311-cp311-manylinux_2_17_x86_64.invalid.whl"
    elif label == "wrong-size":
        records[0]["size"] = 1
    elif label == "wrong-hash":
        records[0]["sha256"] = "0" * 64
    elif label == "duplicate":
        records[-1] = copy.deepcopy(records[0])
    elif label == "missing":
        records.pop()
    elif label == "extra":
        records.append(copy.deepcopy(records[0]))
    elif label == "cross-platform-misassociation":
        windows = _load_manifest(MANIFEST)["platforms"]["windows-py311"]["artifacts"][0]
        records[0] = copy.deepcopy(windows)
    manifest_path = tmp_path / f"{label}.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    root = tmp_path / f"{label}-root"
    monkeypatch.setenv("TORQ_T06C_CI_TEMP_ROOT", str(tmp_path.parent))
    monkeypatch.delenv("TORQ_T06C_OFFICIAL_INDEX", raising=False)
    monkeypatch.setattr(provisioner, "_assert_runtime", lambda _: None)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        provisioner.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command) or SimpleNamespace(returncode=0),
    )
    with pytest.raises(SystemExit, match="wheelhouse manifest artifact does not match approved platform contract"):
        provisioner.main([
            "--root", str(root), "--platform", "linux-py311", "--lock", str(LOCK), "--manifest", str(manifest_path)
        ])
    assert calls == []
    assert not root.exists()


def test_W2_unlisted_and_link_members_are_rejected_without_download(tmp_path: Path) -> None:
    manifest = _load_manifest(MANIFEST)
    expected = _validate_artifact_records(manifest["platforms"]["windows-py311"]["artifacts"])
    root = tmp_path / "wheelhouse-members"
    root.mkdir()
    (root / "unlisted.whl").write_bytes(b"not-a-wheel")
    with pytest.raises(SystemExit, match="unlisted"):
        console_domain  # keep this member check independent of product imports
        import scripts.provision_ci_wheelhouse as provisioner
        provisioner._assert_artifacts(root, expected)

    class LinkMember:
        name = "linked.whl"

        @staticmethod
        def is_symlink() -> bool:
            return True

        @staticmethod
        def is_file() -> bool:
            return False

    class LinkRoot:
        @staticmethod
        def iterdir() -> list[LinkMember]:
            return [LinkMember()]

    with pytest.raises(SystemExit, match="link"):
        provisioner._assert_artifacts(LinkRoot(), expected)


def test_W2_missing_and_duplicate_members_are_rejected(tmp_path: Path) -> None:
    import scripts.provision_ci_wheelhouse as provisioner

    manifest = _load_manifest(MANIFEST)
    expected = _validate_artifact_records(manifest["platforms"]["windows-py311"]["artifacts"])
    empty_root = tmp_path / "missing-members"
    empty_root.mkdir()
    with pytest.raises(SystemExit, match="missing"):
        provisioner._assert_artifacts(empty_root, expected)

    class DuplicateMember:
        name = "duplicate.whl"

        @staticmethod
        def is_symlink() -> bool:
            return False

        @staticmethod
        def is_file() -> bool:
            return True

    class DuplicateRoot:
        @staticmethod
        def iterdir() -> list[DuplicateMember]:
            return [DuplicateMember(), DuplicateMember()]

    with pytest.raises(SystemExit):
        provisioner._assert_artifacts(DuplicateRoot(), expected)


RUNTIME_VALID_CASES = (
    ("windows-py311", "win32", "AMD64"),
    ("windows-py311", "win32", "x86_64"),
    ("macos-py311", "darwin", "x86_64"),
    ("linux-py311", "linux", "x86_64"),
)


@pytest.mark.parametrize(("platform_id", "sys_platform", "machine"), RUNTIME_VALID_CASES)
def test_W2_runtime_valid_matrix_is_host_independent(
    monkeypatch, platform_id: str, sys_platform: str, machine: str
) -> None:
    import scripts.provision_ci_wheelhouse as provisioner

    monkeypatch.setattr(provisioner.sys, "platform", sys_platform)
    monkeypatch.setattr(provisioner.sys, "implementation", SimpleNamespace(name="cpython"))
    monkeypatch.setattr(provisioner.sys, "version_info", (3, 11))
    monkeypatch.setattr(provisioner.platform, "machine", lambda: machine)
    assert provisioner._assert_runtime(platform_id) is None


RUNTIME_MAIN_MISMATCH_CASES = (
    pytest.param("windows-py311", "linux", "AMD64", "cpython", (3, 11), "Windows CPython 3.11 AMD64 runtime assertion failed", id="windows-platform"),
    pytest.param("macos-py311", "linux", "x86_64", "cpython", (3, 11), "macos-15-intel CPython 3.11 x86_64 runtime assertion failed", id="macos-platform"),
    pytest.param("linux-py311", "win32", "x86_64", "cpython", (3, 11), "Ubuntu CPython 3.11 x86_64 runtime assertion failed", id="linux-platform"),
    pytest.param("windows-py311", "win32", "ARM64", "cpython", (3, 11), "Windows CPython 3.11 AMD64 runtime assertion failed", id="windows-architecture"),
    pytest.param("macos-py311", "darwin", "arm64", "cpython", (3, 11), "macos-15-intel CPython 3.11 x86_64 runtime assertion failed", id="macos-architecture"),
    pytest.param("linux-py311", "linux", "aarch64", "cpython", (3, 11), "Ubuntu CPython 3.11 x86_64 runtime assertion failed", id="linux-architecture"),
    pytest.param("windows-py311", "win32", "AMD64", "pypy", (3, 11), "unsupported Python implementation or version; stopped before download", id="windows-implementation"),
    pytest.param("macos-py311", "darwin", "x86_64", "pypy", (3, 11), "unsupported Python implementation or version; stopped before download", id="macos-implementation"),
    pytest.param("linux-py311", "linux", "x86_64", "pypy", (3, 11), "unsupported Python implementation or version; stopped before download", id="linux-implementation"),
    pytest.param("windows-py311", "win32", "AMD64", "cpython", (3, 10), "unsupported Python implementation or version; stopped before download", id="windows-version"),
    pytest.param("macos-py311", "darwin", "x86_64", "cpython", (3, 10), "unsupported Python implementation or version; stopped before download", id="macos-version"),
    pytest.param("linux-py311", "linux", "x86_64", "cpython", (3, 10), "unsupported Python implementation or version; stopped before download", id="linux-version"),
)


@pytest.mark.parametrize(
    ("platform_id", "sys_platform", "machine", "implementation", "version_info", "message"),
    RUNTIME_MAIN_MISMATCH_CASES,
)
def test_W2_runtime_mismatch_matrix_stops_before_download(
    monkeypatch, tmp_path: Path, platform_id: str, sys_platform: str, machine: str,
    implementation: str, version_info: tuple[int, int], message: str,
) -> None:
    import scripts.provision_ci_wheelhouse as provisioner

    monkeypatch.setenv("TORQ_T06C_CI_TEMP_ROOT", str(tmp_path))
    monkeypatch.delenv("TORQ_T06C_OFFICIAL_INDEX", raising=False)
    monkeypatch.setattr(provisioner.sys, "platform", sys_platform)
    monkeypatch.setattr(provisioner.sys, "implementation", SimpleNamespace(name=implementation))
    monkeypatch.setattr(provisioner.sys, "version_info", version_info)
    monkeypatch.setattr(provisioner.platform, "machine", lambda: machine)
    calls: list[list[str]] = []
    monkeypatch.setattr(provisioner.subprocess, "run", lambda command, **kwargs: calls.append(command) or SimpleNamespace(returncode=0))
    manifest_calls: list[Path] = []

    def fail_manifest(path: Path) -> object:
        manifest_calls.append(path)
        raise AssertionError("manifest loaded")

    monkeypatch.setattr(provisioner, "_load_manifest", fail_manifest)
    artifact_calls: list[Path] = []

    def fail_artifacts(root: Path, artifacts: object) -> object:
        artifact_calls.append(root)
        raise AssertionError("artifacts audited")

    monkeypatch.setattr(provisioner, "_assert_artifacts", fail_artifacts)
    root = tmp_path / f"runtime-mismatch-{platform_id}-{sys_platform}-{machine}-{implementation}-{version_info[1]}"
    assert not root.exists()

    with pytest.raises(SystemExit) as error:
        provisioner.main(["--root", str(root), "--platform", platform_id, "--lock", str(LOCK), "--manifest", str(MANIFEST)])

    assert str(error.value) == message
    assert calls == []
    assert manifest_calls == []
    assert artifact_calls == []
    assert not root.exists()
    assert not (root / "audit.json").exists()
    assert str(root) not in str(error.value)


def test_W2_nonempty_root_and_nonofficial_index_stop_before_pip(monkeypatch, tmp_path: Path) -> None:
    import scripts.provision_ci_wheelhouse as provisioner

    monkeypatch.setenv("TORQ_T06C_CI_TEMP_ROOT", str(tmp_path.parent))
    monkeypatch.setattr(provisioner, "_assert_runtime", lambda _: None)
    calls: list[list[str]] = []
    monkeypatch.setattr(provisioner.subprocess, "run", lambda command, **kwargs: calls.append(command) or SimpleNamespace(returncode=0))
    nonempty = tmp_path / "nonempty-root"
    nonempty.mkdir()
    (nonempty / "cache-marker").write_text("x", encoding="utf-8")
    with pytest.raises(SystemExit, match="not empty"):
        provisioner.main(["--root", str(nonempty), "--platform", "linux-py311", "--lock", str(LOCK), "--manifest", str(MANIFEST)])
    assert calls == []
    monkeypatch.setenv("TORQ_T06C_OFFICIAL_INDEX", "https://evil.example/simple")
    index_root = tmp_path / "index-root"
    with pytest.raises(SystemExit, match="official PyPI"):
        provisioner.main(["--root", str(index_root), "--platform", "linux-py311", "--lock", str(LOCK), "--manifest", str(MANIFEST)])
    assert calls == []


@pytest.mark.parametrize("platform_id", ("windows-py311", "macos-py311", "linux-py311"))
def test_W3_valid_main_command_shape_for_all_platforms(monkeypatch, tmp_path: Path, platform_id: str) -> None:
    import scripts.provision_ci_wheelhouse as provisioner

    monkeypatch.setenv("TORQ_T06C_CI_TEMP_ROOT", str(tmp_path.parent))
    monkeypatch.delenv("TORQ_T06C_OFFICIAL_INDEX", raising=False)
    monkeypatch.setattr(provisioner, "_assert_runtime", lambda _: None)
    monkeypatch.setattr(provisioner, "_assert_artifacts", lambda root, artifacts: None)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(provisioner.subprocess, "run", fake_run)
    root = tmp_path / platform_id
    result = provisioner.main([
        "--root", str(root), "--platform", platform_id, "--lock", str(LOCK), "--manifest", str(MANIFEST)
    ])
    assert result == 0
    assert len(calls) == 1
    command, kwargs = calls[0]
    expected_key = provisioner.PLATFORM_KEYS[platform_id]
    manifest_records = _load_manifest(MANIFEST)["platforms"][expected_key]["artifacts"]
    assert isinstance(manifest_records, list)
    assert manifest_records == list(LITERAL_ARTIFACTS[expected_key])
    assert command == [
        sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--no-deps", "--require-hashes",
        "--no-cache-dir", "--disable-pip-version-check", "--no-input", "--index-url", "https://pypi.org/simple",
        "--dest", str(root.resolve()), "-r", str(LOCK.resolve()),
    ]
    assert kwargs["cwd"] == provisioner.ROOT
    assert kwargs["check"] is False
    assert kwargs["env"]["PIP_NO_CACHE_DIR"] == "1"
    assert kwargs["env"]["PIP_DISABLE_PIP_VERSION_CHECK"] == "1"
    assert kwargs["env"]["PIP_NO_INPUT"] == "1"
    assert _lock_hashes(LOCK) == LITERAL_LOCK_HASHES
    audit = json.loads((root / "audit.json").read_text(encoding="utf-8"))
    assert audit == {
        "schema": "torq-t06c-wheelhouse-audit-v1",
        "platform": expected_key,
        "artifacts": [
            {"filename": item["filename"], "size": item["size"], "sha256": item["sha256"]}
            for item in LITERAL_ARTIFACTS[expected_key]
        ],
    }
