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
MANIFEST_ROOT_KEYS = frozenset({"schema", "official_index", "python", "platforms"})
PYTHON_KEYS = frozenset({"implementation", "major", "minor"})
PLATFORM_RECORD_KEYS = frozenset({"runner", "sys_platform", "machine", "artifacts"})
PLATFORM_METADATA = {
    "windows-py311": ("windows-2022", "win32", "AMD64"),
    "macos-15-intel-py311-x86_64": ("macos-15-intel", "darwin", "x86_64"),
    "linux-py311": ("ubuntu-22.04", "linux", "x86_64"),
}
PACKAGE_NAMES = ("PyYAML", "setuptools", "wheel", "packaging")
PACKAGE_VERSIONS = {"PyYAML": "6.0.2", "setuptools": "82.0.1", "wheel": "0.47.0", "packaging": "26.0"}
APPROVED_PLATFORM_ARTIFACTS: dict[str, tuple[dict[str, Any], ...]] = {
    "windows-py311": (
        {"name": "PyYAML", "version": "6.0.2", "filename": "PyYAML-6.0.2-cp311-cp311-win_amd64.whl", "size": 161980, "sha256": "e10ce637b18caea04431ce14fabcf5c64a1c61ec9c56b071a4b7ca131ca52d44", "python_tag": "cp311", "abi_tag": "cp311", "platform_tag": "win_amd64"},
        {"name": "setuptools", "version": "82.0.1", "filename": "setuptools-82.0.1-py3-none-any.whl", "size": 1006223, "sha256": "a59e362652f08dcd477c78bb6e7bd9d80a7995bc73ce773050228a348ce2e5bb", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "wheel", "version": "0.47.0", "filename": "wheel-0.47.0-py3-none-any.whl", "size": 32218, "sha256": "212281cab4dff978f6cedd499cd893e1f620791ca6ff7107cf270781e587eced", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "packaging", "version": "26.0", "filename": "packaging-26.0-py3-none-any.whl", "size": 74366, "sha256": "b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
    ),
    "macos-15-intel-py311-x86_64": (
        {"name": "PyYAML", "version": "6.0.2", "filename": "PyYAML-6.0.2-cp311-cp311-macosx_10_9_x86_64.whl", "size": 184612, "sha256": "cc1c1159b3d456576af7a3e4d1ba7e6924cb39de8f67111c735f6fc832082774", "python_tag": "cp311", "abi_tag": "cp311", "platform_tag": "macosx_10_9_x86_64"},
        {"name": "setuptools", "version": "82.0.1", "filename": "setuptools-82.0.1-py3-none-any.whl", "size": 1006223, "sha256": "a59e362652f08dcd477c78bb6e7bd9d80a7995bc73ce773050228a348ce2e5bb", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "wheel", "version": "0.47.0", "filename": "wheel-0.47.0-py3-none-any.whl", "size": 32218, "sha256": "212281cab4dff978f6cedd499cd893e1f620791ca6ff7107cf270781e587eced", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "packaging", "version": "26.0", "filename": "packaging-26.0-py3-none-any.whl", "size": 74366, "sha256": "b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
    ),
    "linux-py311": (
        {"name": "PyYAML", "version": "6.0.2", "filename": "PyYAML-6.0.2-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "size": 762952, "sha256": "3ad2a3decf9aaba3d29c8f537ac4b243e36bef957511b4766cb0057d32b0be85", "python_tag": "cp311", "abi_tag": "cp311", "platform_tag": "manylinux_2_17_x86_64.manylinux2014_x86_64"},
        {"name": "setuptools", "version": "82.0.1", "filename": "setuptools-82.0.1-py3-none-any.whl", "size": 1006223, "sha256": "a59e362652f08dcd477c78bb6e7bd9d80a7995bc73ce773050228a348ce2e5bb", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "wheel", "version": "0.47.0", "filename": "wheel-0.47.0-py3-none-any.whl", "size": 32218, "sha256": "212281cab4dff978f6cedd499cd893e1f620791ca6ff7107cf270781e587eced", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
        {"name": "packaging", "version": "26.0", "filename": "packaging-26.0-py3-none-any.whl", "size": 74366, "sha256": "b36f1fef9334a5588b4166f8bcd26a14e521f2b55e6b9de3aaa80d3ff7a37529", "python_tag": "py3", "abi_tag": "none", "platform_tag": "any"},
    ),
}
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})\b", re.ASCII)
HASH_OPTION_RE = re.compile(
    r"^    --hash=sha256:(?P<hash>[0-9a-f]{64})(?P<continuation> \\)?$",
    re.ASCII,
)
REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9_.-]*)"
    r" \\$",
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


def _reject_duplicate_json_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("wheelhouse manifest contains a duplicate JSON object member")
        result[key] = value
    return result


def _validate_manifest_wrapper(value: dict[str, Any]) -> None:
    if set(value) != MANIFEST_ROOT_KEYS:
        _fail("wheelhouse manifest wrapper is not closed")
    if not isinstance(value["schema"], str) or value["schema"] != "torq-t06c-wheelhouse-v1":
        _fail("wheelhouse manifest schema is invalid")
    if not isinstance(value["official_index"], str) or value["official_index"] != "https://pypi.org/simple":
        _fail("wheelhouse manifest official index is invalid")

    python_metadata = value["python"]
    if not isinstance(python_metadata, dict) or set(python_metadata) != PYTHON_KEYS:
        _fail("wheelhouse manifest Python wrapper is invalid")
    if python_metadata["implementation"] != "cpython":
        _fail("wheelhouse manifest Python implementation is invalid")
    if type(python_metadata["major"]) is not int or python_metadata["major"] != 3:
        _fail("wheelhouse manifest Python major version is invalid")
    if type(python_metadata["minor"]) is not int or python_metadata["minor"] != 11:
        _fail("wheelhouse manifest Python minor version is invalid")

    platforms = value["platforms"]
    if not isinstance(platforms, dict) or set(platforms) != set(PLATFORM_METADATA):
        _fail("wheelhouse manifest platform membership is invalid")
    for platform_key, metadata in PLATFORM_METADATA.items():
        record = platforms[platform_key]
        if not isinstance(record, dict) or set(record) != PLATFORM_RECORD_KEYS:
            _fail("wheelhouse manifest platform wrapper is invalid")
        if tuple(record[key] for key in ("runner", "sys_platform", "machine")) != metadata:
            _fail("wheelhouse manifest platform metadata is invalid")
        if not isinstance(record["artifacts"], list):
            _fail("wheelhouse manifest artifacts member is invalid")


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_json_members
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail("wheelhouse manifest cannot be read")
        raise AssertionError from exc
    if not isinstance(value, dict):
        _fail("wheelhouse manifest wrapper is invalid")
    _validate_manifest_wrapper(value)
    return value


def _lock_hashes(path: Path) -> dict[str, set[str]]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        _fail("wheelhouse lock cannot be read")
        raise AssertionError from exc
    if "\r" in text:
        if "\r" in text.replace("\r\n", ""):
            _fail("wheelhouse lock contains an invalid line ending")
        text = text.replace("\r\n", "\n")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines:
        _fail("wheelhouse lock must begin with the approved global option")
    if lines[0] != "--only-binary=:all:":
        if lines[0].startswith("--"):
            _fail("wheelhouse lock contains an unsupported global option")
        _fail("wheelhouse lock must begin with the approved global option")
    if len(lines) < 2:
        _fail("wheelhouse lock requirement set is incomplete")
    result: dict[str, set[str]] = {}
    index = 1
    for expected_name in PACKAGE_NAMES:
        if index >= len(lines):
            _fail("wheelhouse lock requirement set is incomplete")
        match = REQUIREMENT_RE.fullmatch(lines[index])
        if match is None:
            if lines[index].startswith("    --hash"):
                _fail("wheelhouse lock hash is not a requirement continuation")
            _fail("wheelhouse lock contains an invalid requirement line")
        name = match.group("name")
        version = match.group("version")
        if name != expected_name:
            _fail("wheelhouse lock package order is invalid")
        if version != PACKAGE_VERSIONS[name]:
            _fail("wheelhouse lock contains an unsupported package version")
        index += 1
        package_hashes: set[str] = set()
        continuation_open = True
        while continuation_open:
            if index >= len(lines):
                _fail("wheelhouse lock continuation is open at EOF")
            hash_match = HASH_OPTION_RE.fullmatch(lines[index])
            if hash_match is None:
                _fail("wheelhouse lock continuation requires a hash line")
            digest = hash_match.group("hash")
            if digest in package_hashes:
                _fail("wheelhouse lock contains a duplicate hash")
            package_hashes.add(digest)
            continuation_open = hash_match.group("continuation") is not None
            index += 1
        if not package_hashes:
            _fail("wheelhouse lock requirement has no attached hash")
        result[name] = package_hashes
    if index != len(lines):
        _fail("wheelhouse lock contains an unexpected trailing line")
    return result


def _validate_lock(path: Path, expected_hashes: dict[str, set[str]]) -> None:
    hashes = _lock_hashes(path)
    if set(hashes) != set(PACKAGE_NAMES) or set(expected_hashes) != set(PACKAGE_NAMES):
        _fail("wheelhouse lock and manifest package sets disagree")
    for name in PACKAGE_NAMES:
        if hashes[name] != expected_hashes[name]:
            _fail("wheelhouse lock hashes disagree with the complete manifest")


def _artifact_signature(record: dict[str, Any]) -> tuple[tuple[str, Any], ...]:
    return tuple((key, record[key]) for key in sorted(record))


def _validate_artifact_records(
    artifacts: Any, platform_key: str | None = None
) -> list[dict[str, Any]]:
    contract_error = "wheelhouse manifest artifact does not match approved platform contract"
    if not isinstance(artifacts, list) or len(artifacts) != len(PACKAGE_NAMES):
        _fail(contract_error)
    required = {"name", "version", "filename", "size", "sha256", "python_tag", "abi_tag", "platform_tag"}
    records: list[dict[str, Any]] = []
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != required:
            _fail(contract_error)
        if not isinstance(item["name"], str) or not isinstance(item["version"], str) or not isinstance(item["filename"], str):
            _fail(contract_error)
        if item["version"] != PACKAGE_VERSIONS.get(item["name"]) or not item["filename"].startswith(f"{item['name']}-{item['version']}-"):
            _fail(contract_error)
        if type(item["size"]) is not int or item["size"] <= 0 or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"], re.ASCII):
            _fail(contract_error)
        if any(not isinstance(item[tag], str) or not item[tag] for tag in ("python_tag", "abi_tag", "platform_tag")):
            _fail(contract_error)
        records.append(item)
    if {item["name"] for item in records} != set(PACKAGE_NAMES):
        _fail(contract_error)
    if platform_key is not None:
        expected = APPROVED_PLATFORM_ARTIFACTS.get(platform_key)
        if expected is None or tuple(_artifact_signature(item) for item in records) != tuple(
            _artifact_signature(item) for item in expected
        ):
            _fail(contract_error)
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
    records_by_platform: dict[str, list[dict[str, Any]]] = {}
    complete_hashes = {name: set() for name in PACKAGE_NAMES}
    for platform_key in ("windows-py311", "macos-15-intel-py311-x86_64", "linux-py311"):
        platform_record = platforms[platform_key]
        records = _validate_artifact_records(platform_record["artifacts"], platform_key)
        records_by_platform[platform_key] = records
        for record in records:
            complete_hashes[record["name"]].add(record["sha256"])
    artifacts = records_by_platform[manifest_key]
    _validate_lock(Path(args.lock).resolve(), complete_hashes)
    index = os.environ.get("TORQ_T06C_OFFICIAL_INDEX", manifest["official_index"])
    if index != "https://pypi.org/simple":
        _fail("only the configured official PyPI index is permitted")
    if root.exists() and any(root.iterdir()):
        _fail("wheelhouse root is not empty; cache reuse is forbidden")
    root.mkdir(parents=True, exist_ok=True)
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
