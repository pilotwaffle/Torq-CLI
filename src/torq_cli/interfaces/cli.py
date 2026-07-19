"""Argparse interface for the Foundation commands."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

from torq_cli.application import import_v5_config
from torq_cli.application.resolve import envelope_to_dict, resolve_path
from torq_cli.domain.models import ResultEnvelope


def exit_code_for(status: str, require_effective: bool, findings: Sequence[object]) -> int:
    classes = {getattr(finding, "status_class", "") for finding in findings}
    if "internal_error" in classes or status == "internal_error":
        return 5
    if "invalid" in classes or status == "invalid":
        return 2
    if "blocked" in classes or status == "blocked":
        return 3
    if require_effective and status == "unattested":
        return 4
    return 0


def _print_envelope(envelope: ResultEnvelope, *, compact: bool) -> bool:
    rendering_failed = False
    try:
        rendered: dict[str, Any] = envelope_to_dict(envelope)
    except AttributeError:
        rendering_failed = True
        rendered = {
            "schema_version": "1.0.0",
            "command": envelope.command,
            "status": "internal_error",
            "snapshot": None,
            "findings": [{
                "id": "internal_error",
                "message": "Internal failure occurred without exposing details.",
                "severity": "critical",
                "bucket": "A",
                "status_class": "internal_error",
                "stage": "complete",
                "path": "/",
                "context": {},
            }],
            "data": {},
        }
    if compact:
        print(json.dumps(rendered, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(rendered, sort_keys=True))
    return rendering_failed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="torq")
    sub = parser.add_subparsers(dest="command", required=True)
    profile = sub.add_parser("profile")
    profile_sub = profile.add_subparsers(dest="profile_command", required=True)
    validate = profile_sub.add_parser("validate")
    validate.add_argument("--config", required=True)
    status = sub.add_parser("status")
    status.add_argument("--offline", action="store_true", required=True)
    status.add_argument("--config", required=True)
    status.add_argument("--require-effective", action="store_true")
    config = sub.add_parser("config")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    import_v5 = config_sub.add_parser("import-v5-normalized")
    import_v5.add_argument("--config", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    supplied = list(argv) if argv is not None else sys.argv[1:]
    if any(argument == "--output" or argument.startswith("--output=") for argument in supplied):
        envelope = import_v5_config.output_rejected()
        return 5 if _print_envelope(envelope, compact=True) else 2
    args = _parser().parse_args(argv)
    if args.command == "config":
        try:
            envelope = import_v5_config.import_v5_path(args.config)
        except Exception:
            envelope = import_v5_config.internal_error()
        rendering_failed = _print_envelope(envelope, compact=True)
        if rendering_failed:
            return 5
        if envelope.status == "internal_error":
            return 5
        return exit_code_for(envelope.status, False, envelope.findings)
    command = "profile_validate" if args.command == "profile" else "status_offline"
    try:
        envelope = resolve_path(command, args.config, getattr(args, "require_effective", False))
    except Exception:
        from torq_cli.domain.findings import FindingCatalog
        from torq_cli.domain.models import ResultEnvelope
        envelope = ResultEnvelope("1.0.0", command, "internal_error", None, (FindingCatalog.make("internal_error", path="/"),), {})
        _print_envelope(envelope, compact=False)
        return 5
    rendering_failed = _print_envelope(envelope, compact=False)
    if rendering_failed:
        return 5
    return exit_code_for(envelope.status, getattr(args, "require_effective", False), envelope.findings)
