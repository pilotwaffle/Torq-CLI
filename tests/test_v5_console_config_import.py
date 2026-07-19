import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.provision_ci_wheelhouse import _lock_hashes
from torq_cli.application import import_v5_console_config
from torq_cli.interfaces import cli as cli_module
from torq_cli.interfaces.cli import main
REPO_ROOT = Path(__file__).parents[1]


FIXTURE = Path(__file__).parent / "fixtures" / "t06c" / "raw-console-config.sanitized.yaml"
TARGET_SHA256 = "63ffadbe88e6b04ac732d5a282e27e0af1a2bbd80f89412ad1a4364e01a3650e"
LOCK = Path(__file__).parents[1] / "ci" / "t06c-wheelhouse" / "requirements-py311.txt"


def _run(capsys, path: Path, *extra: str) -> tuple[int, dict[str, object], str]:
    code = main(["config", "import-v5-console", "--config", str(path.resolve()), *extra])
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured.err


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
