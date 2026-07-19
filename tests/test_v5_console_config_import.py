import hashlib
import json
from pathlib import Path

import pytest

from scripts.provision_ci_wheelhouse import _lock_hashes
from torq_cli.interfaces.cli import main


FIXTURE = Path(__file__).parent / "fixtures" / "t06c" / "raw-console-config.sanitized.yaml"
TARGET_SHA256 = "63ffadbe88e6b04ac732d5a282e27e0af1a2bbd80f89412ad1a4364e01a3650e"
LOCK = Path(__file__).parents[1] / "ci" / "t06c-wheelhouse" / "requirements-py311.txt"


def _run(capsys, path: Path, *extra: str) -> tuple[int, dict[str, object], str]:
    code = main(["config", "import-v5-console", "--config", str(path.resolve()), *extra])
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured.err


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


def test_committed_wheelhouse_lock_accepts_safe_global_option() -> None:
    hashes = _lock_hashes(LOCK)

    assert set(hashes) == {"PyYAML", "setuptools", "wheel", "packaging"}
    assert all(hashes[name] for name in hashes)


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
