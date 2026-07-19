"""Audit and exercise installed T06C wheel and sdist artifacts offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA256 = "63ffadbe88e6b04ac732d5a282e27e0af1a2bbd80f89412ad1a4364e01a3650e"
FIXTURE_NAMES = ("raw-console-config.sanitized.yaml", "raw-console-config.provenance.json")


def _fail(message: str) -> None:
    raise SystemExit(message)


def _absolute(value: str, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        _fail(f"{label} must be absolute")
    return path.resolve()


def _under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _archive_has_fixture(names: list[str]) -> bool:
    return any(
        "tests/fixtures/t06c/" in name
        or any(name == fixture or name.endswith("/" + fixture) for fixture in FIXTURE_NAMES)
        for name in names
    )


def _archive_audit(wheel: Path, sdist: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
    if _archive_has_fixture(wheel_names):
        _fail("fixture entered wheel archive")
    with tarfile.open(sdist, mode="r:gz") as archive:
        sdist_names = archive.getnames()
        if any(member.issym() or member.islnk() for member in archive.getmembers()):
            _fail("sdist contains a link member")
    if _archive_has_fixture(sdist_names):
        _fail("fixture entered sdist archive")


def _platform_key() -> str:
    if sys.platform == "win32":
        return "windows-py311"
    if sys.platform == "darwin":
        if platform.machine() != "x86_64":
            _fail("wheel smoke requires x86_64 macOS")
        return "macos-15-intel-py311-x86_64"
    if sys.platform == "linux" and platform.machine() == "x86_64":
        return "linux-py311"
    _fail("unsupported wheel smoke platform")
    raise AssertionError


def _wheelhouse_audit(wheelhouse: Path) -> None:
    manifest_path = ROOT / "ci" / "t06c-wheelhouse" / "manifest-py311.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        selected = manifest["platforms"][_platform_key()]
        artifacts = selected["artifacts"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        _fail("wheelhouse manifest is invalid")
        raise AssertionError from exc
    expected = {str(item["filename"]): item for item in artifacts}
    actual = {path.name: path for path in wheelhouse.iterdir() if path.name.endswith(".whl")}
    if set(actual) != set(expected):
        _fail("wheelhouse members disagree with manifest")
    for name, artifact in expected.items():
        path = actual[name]
        if path.is_symlink() or not path.is_file():
            _fail("wheelhouse contains a link or non-file")
        if path.stat().st_size != artifact["size"] or hashlib.sha256(path.read_bytes()).hexdigest() != artifact["sha256"]:
            _fail("wheelhouse member hash or size mismatch")


def _verified_fixture(destination: Path) -> Path:
    fixture_root = ROOT / "tests" / "fixtures" / "t06c"
    raw_path = fixture_root / FIXTURE_NAMES[0]
    provenance_path = fixture_root / FIXTURE_NAMES[1]
    try:
        raw = raw_path.read_bytes()
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail("fixture or provenance cannot be read")
        raise AssertionError from exc
    if hashlib.sha256(raw).hexdigest() != provenance.get("sanitized_fixture_sha256"):
        _fail("fixture SHA-256 disagrees with provenance")
    if len(raw) != provenance.get("byte_count") or raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw:
        _fail("fixture bytes disagree with provenance encoding contract")
    if provenance.get("encoding") != "UTF-8" or provenance.get("bom") is not False or provenance.get("line_endings") != "LF":
        _fail("fixture provenance encoding contract is invalid")
    destination.mkdir(parents=True, exist_ok=True)
    copied = destination / raw_path.name
    copied.write_bytes(raw)
    return copied


def _python(venv_root: Path) -> Path:
    return venv_root / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def _torq(venv_root: Path) -> Path:
    return venv_root / ("Scripts/torq.exe" if sys.platform == "win32" else "bin/torq")


def _run(command: list[str], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, cwd=cwd, env=env, capture_output=True, check=False)


def _installed_assertions(torq: Path, fixture: Path, cwd: Path, env: dict[str, str]) -> None:
    result = _run([str(torq), "config", "import-v5-console", "--config", str(fixture)], cwd, env)
    if result.returncode != 0 or result.stderr != b"":
        _fail("installed Console import command failed or wrote stderr")
    if result.stdout.count(b"\n") != 1 or not result.stdout.endswith(b"\n"):
        _fail("installed command did not emit exactly one final-LF JSON line")
    try:
        envelope = json.loads(result.stdout.decode("utf-8"))
        compact = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        _fail("installed command emitted invalid JSON")
        raise AssertionError from exc
    if result.stdout != compact or envelope.get("status") != "ok":
        _fail("installed command output is not the fixed compact success envelope")
    snapshot = envelope.get("snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("config_path") is not None:
        _fail("installed snapshot is not source-path-free")
    data = envelope.get("data")
    if not isinstance(data, dict):
        _fail("installed success data is invalid")
    target = data.get("canonical_target_config_utf8")
    if not isinstance(target, str):
        _fail("installed target projection is absent")
    target_bytes = target.encode("utf-8")
    if len(target_bytes) != 1029 or hashlib.sha256(target_bytes).hexdigest() != TARGET_SHA256:
        _fail("installed target projection bytes disagree")


def _install_and_smoke(artifact: Path, wheelhouse: Path, root: Path, fixture: Path, label: str) -> None:
    environment = os.environ.copy()
    environment.update({
        "PIP_NO_INDEX": "1",
        "PIP_FIND_LINKS": str(wheelhouse),
        "PIP_CACHE_DIR": str(root / "pip-cache"),
        "PIP_NO_INPUT": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONNOUSERSITE": "1",
    })
    venv_root = root / label
    venv.EnvBuilder(with_pip=True, system_site_packages=False, clear=True).create(venv_root)
    python = _python(venv_root)
    install = _run([
        str(python), "-m", "pip", "install", "--no-index", "--find-links", str(wheelhouse), str(artifact),
    ], root, environment)
    if install.returncode != 0:
        _fail(f"offline {label} installation failed")
    _installed_assertions(_torq(venv_root), fixture, root, environment)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        _fail("dist, --wheelhouse, and --work-root are required")
    parser = argparse.ArgumentParser(prog="wheel_smoke")
    parser.add_argument("dist")
    parser.add_argument("--wheelhouse", required=True)
    parser.add_argument("--work-root", required=True)
    args = parser.parse_args(arguments)
    dist = _absolute(args.dist, "dist")
    wheelhouse = _absolute(args.wheelhouse, "--wheelhouse")
    work_root = _absolute(args.work_root, "--work-root")
    for path, label in ((dist, "dist"), (wheelhouse, "--wheelhouse"), (work_root, "--work-root")):
        if _under(path, ROOT.resolve()):
            _fail(f"{label} must be outside the repository")
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        _fail("dist must contain exactly one wheel and one sdist")
    _wheelhouse_audit(wheelhouse)
    _archive_audit(wheels[0], sdists[0])
    work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work_root, prefix="t06c-wheel-smoke-") as directory:
        root = Path(directory)
        fixture = _verified_fixture(root / "external-fixture")
        _install_and_smoke(wheels[0], wheelhouse, root, fixture, "wheel-venv")
        _install_and_smoke(sdists[0], wheelhouse, root, fixture, "sdist-venv")
    print("wheel_smoke: offline wheel and sdist installs passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
