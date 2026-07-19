"""Provision and audit the hash-locked T06C CPython 3.11 wheelhouse."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PLATFORM_KEYS = {
    "windows-py311": "windows-py311",
    "macos-py311": "macos-15-intel-py311-x86_64",
    "linux-py311": "linux-py311",
}
PACKAGE_NAMES = ("PyYAML", "setuptools", "wheel", "packaging")
PACKAGE_VERSIONS = {"PyYAML": "6.0.2", "setuptools": "82.0.1", "wheel": "0.47.0", "packaging": "26.0"}
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})\b", re.ASCII)
HASH_OPTION_RE = re.compile(
    r"--hash=sha256:[0-9a-f]{64}(?P<continuation>[ \t]*\\)?\Z",
    re.ASCII,
)
REQUIREMENT_RE = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9_.-]*)"
    r"(?P<continuation>[ \t]*\\)?\Z",
    re.ASCII,
)
SAFE_GLOBAL_OPTIONS = frozenset({"--only-binary=:all:"})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="provision_ci_wheelhouse")
    parser.add_argument("--root", required=True)
    parser.add_argument("--platform", choices=tuple(PLATFORM_KEYS), required=True)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--manifest", required=True)
    return parser


def _fail(message: str) -> None:
    raise SystemExit(message)


def _under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _temporary_root() -> Path:
    configured = os.environ.get("TORQ_T06C_CI_TEMP_ROOT") or os.environ.get("RUNNER_TEMP")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(tempfile.gettempdir()).resolve()


def _assert_runtime(platform_id: str) -> None:
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 11):
        _fail("unsupported Python implementation or version; stopped before download")
    machine = platform.machine()
    if platform_id == "windows-py311":
        if sys.platform != "win32" or machine not in {"AMD64", "x86_64"}:
            _fail("Windows CPython 3.11 AMD64 runtime assertion failed")
    elif platform_id == "macos-py311":
        if sys.platform != "darwin" or machine != "x86_64":
            _fail("macos-15-intel CPython 3.11 x86_64 runtime assertion failed")
    elif sys.platform != "linux" or machine != "x86_64":
        _fail("Ubuntu CPython 3.11 x86_64 runtime assertion failed")


def _wheel_tags(filename: str) -> tuple[str, str, str]:
    if not filename.endswith(".whl"):
        _fail("manifest member is not a wheel")
    parts = filename[:-4].rsplit("-", 3)
    if len(parts) != 4:
        _fail("wheel filename does not have three tags")
    return parts[1], parts[2], parts[3]


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail("wheelhouse manifest cannot be read")
        raise AssertionError from exc
    if not isinstance(value, dict) or value.get("schema") != "torq-t06c-wheelhouse-v1":
        _fail("wheelhouse manifest schema is invalid")
    return value


def _lock_hashes(path: Path) -> dict[str, set[str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        _fail("wheelhouse lock cannot be read")
        raise AssertionError from exc
    result: dict[str, set[str]] = {}
    current: str | None = None
    seen: set[str] = set()
    current_has_hash = False
    continuation_open = False
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("--hash"):
            if current is None:
                _fail("wheelhouse lock hash appears before a requirement")
            if not continuation_open:
                _fail("wheelhouse lock hash is not a requirement continuation")
            hash_match = HASH_OPTION_RE.fullmatch(stripped)
            if hash_match is None:
                _fail("wheelhouse lock contains an invalid hash option")
            result[current].update(HASH_RE.findall(stripped))
            current_has_hash = True
            continuation_open = hash_match.group("continuation") is not None
            continue
        if stripped in SAFE_GLOBAL_OPTIONS:
            continue
        if stripped.startswith("--"):
            _fail("wheelhouse lock contains an unsupported global option")
        match = REQUIREMENT_RE.fullmatch(stripped)
        if match is None:
            _fail("wheelhouse lock contains an invalid requirement line")
        if current is not None and not current_has_hash:
            _fail("wheelhouse lock requirement has no attached hash")
        name = match.group("name")
        version = match.group("version")
        if name not in PACKAGE_VERSIONS:
            _fail("wheelhouse lock contains an unknown package")
        if version != PACKAGE_VERSIONS[name]:
            _fail("wheelhouse lock contains an unsupported package version")
        if name in seen:
            _fail("wheelhouse lock contains a duplicate requirement")
        seen.add(name)
        current = name
        result[current] = set()
        current_has_hash = False
        continuation_open = match.group("continuation") is not None
    if current is not None and not current_has_hash:
        _fail("wheelhouse lock requirement has no attached hash")
    return result


def _validate_lock(path: Path, artifacts: list[dict[str, Any]]) -> None:
    hashes = _lock_hashes(path)
    if set(hashes) != set(PACKAGE_NAMES):
        _fail("wheelhouse lock and manifest package sets disagree")
    for artifact in artifacts:
        if artifact["sha256"] not in hashes[artifact["name"]]:
            _fail("wheelhouse lock is missing a manifest artifact hash")


def _validate_artifact_records(artifacts: Any) -> list[dict[str, Any]]:
    if not isinstance(artifacts, list) or len(artifacts) != len(PACKAGE_NAMES):
        _fail("platform manifest artifact set is invalid")
    required = {"name", "version", "filename", "size", "sha256", "python_tag", "abi_tag", "platform_tag"}
    records: list[dict[str, Any]] = []
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != required:
            _fail("platform manifest artifact record is invalid")
        if not isinstance(item["name"], str) or not isinstance(item["version"], str) or not isinstance(item["filename"], str):
            _fail("platform manifest artifact identity is invalid")
        if item["version"] != PACKAGE_VERSIONS.get(item["name"]) or not item["filename"].startswith(f"{item['name']}-{item['version']}-"):
            _fail("platform manifest artifact version or filename is invalid")
        if type(item["size"]) is not int or item["size"] <= 0 or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"], re.ASCII):
            _fail("platform manifest artifact digest metadata is invalid")
        if any(not isinstance(item[tag], str) or not item[tag] for tag in ("python_tag", "abi_tag", "platform_tag")):
            _fail("platform manifest wheel tag metadata is invalid")
        records.append(item)
    if {item["name"] for item in records} != set(PACKAGE_NAMES):
        _fail("platform manifest package set is invalid")
    return records


def _assert_artifacts(root: Path, artifacts: list[dict[str, Any]]) -> None:
    expected = {str(item["filename"]): item for item in artifacts}
    members = list(root.iterdir())
    for member in members:
        if member.is_symlink() or not member.is_file():
            _fail("wheelhouse contains a link or non-file member")
    actual = {member.name: member for member in members}
    if set(actual) != set(expected):
        _fail("wheelhouse contains missing or unlisted wheels")
    for filename, artifact in expected.items():
        member = actual[filename]
        python_tag, abi_tag, platform_tag = _wheel_tags(filename)
        if (python_tag, abi_tag, platform_tag) != (
            artifact["python_tag"], artifact["abi_tag"], artifact["platform_tag"]
        ):
            _fail("wheelhouse wheel tags disagree with manifest")
        digest = hashlib.sha256(member.read_bytes()).hexdigest()
        if member.stat().st_size != artifact["size"] or digest != artifact["sha256"]:
            _fail("wheelhouse wheel bytes disagree with manifest")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(args.root).expanduser()
    if not root.is_absolute():
        _fail("--root must be absolute")
    root = root.resolve()
    if _under(root, ROOT.resolve()):
        _fail("--root must be outside the repository")
    temp_root = _temporary_root()
    if not _under(root, temp_root):
        _fail("--root must be under the CI temporary root")
    _assert_runtime(args.platform)
    manifest = _load_manifest(Path(args.manifest).resolve())
    manifest_key = PLATFORM_KEYS[args.platform]
    platforms = manifest.get("platforms")
    if not isinstance(platforms, dict) or set(platforms) != {"windows-py311", "macos-15-intel-py311-x86_64", "linux-py311"} or manifest_key not in platforms:
        _fail("unknown platform manifest key")
    selected = platforms[manifest_key]
    artifacts = _validate_artifact_records(selected.get("artifacts") if isinstance(selected, dict) else None)
    if root.exists() and any(root.iterdir()):
        _fail("wheelhouse root is not empty; cache reuse is forbidden")
    root.mkdir(parents=True, exist_ok=True)
    _validate_lock(Path(args.lock).resolve(), artifacts)
    index = os.environ.get("TORQ_T06C_OFFICIAL_INDEX", manifest.get("official_index"))
    if index != "https://pypi.org/simple":
        _fail("only the configured official PyPI index is permitted")
    environment = os.environ.copy()
    environment.update({"PIP_NO_CACHE_DIR": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1"})
    command = [
        sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--no-deps",
        "--require-hashes", "--no-cache-dir", "--disable-pip-version-check", "--no-input",
        "--index-url", index, "--dest", str(root), "-r", str(Path(args.lock).resolve()),
    ]
    result = subprocess.run(command, cwd=ROOT, env=environment, check=False)
    if result.returncode != 0:
        return result.returncode
    _assert_artifacts(root, artifacts)
    observed = {
        "schema": "torq-t06c-wheelhouse-audit-v1",
        "platform": manifest_key,
        "artifacts": [{"filename": item["filename"], "size": item["size"], "sha256": item["sha256"]} for item in artifacts],
    }
    (root / "audit.json").write_text(json.dumps(observed, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
