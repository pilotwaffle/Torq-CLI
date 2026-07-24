"""Application boundary for the bounded Console V5 compatibility import."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from torq_cli.domain.drift_oracle import load_v5_config_reference
from torq_cli.domain.findings import Finding, FindingCatalog
from torq_cli.domain.hermetic import LegacyConfigTooLarge, LegacyConfigUnreadable, ProtectedPathError, read_bounded_legacy_config
from torq_cli.domain.models import ResolutionSnapshot, ResultEnvelope
from torq_cli.domain.registry_schema import (
    Registry,
    RegistryDocumentError,
    RegistryResourceMissing,
    RegistrySyntaxError,
    RegistryUnreadable,
    load_registry,
    validate_registry,
)
from torq_cli.domain.v5_console_config_import import (
    TARGET_SHA256,
    construct_console_yaml,
    contains_console_secret,
    preflight_console_yaml,
    validate_console_mapping,
    validate_console_schema,
)
from torq_cli.domain.v5_config_import import TARGET_CONFIG_UTF8, target_config, validate_projection


COMMAND = "config_import_v5_console"


def _snapshot(registry: Registry | None, stage: str) -> ResolutionSnapshot:
    return ResolutionSnapshot(
        registry_id=registry.registry_id if registry is not None else None,
        registry_version=registry.registry_version if registry is not None else None,
        registry_resource_sha256=registry.resource_sha256 if registry is not None else None,
        config_path=None,
        config_version=1 if stage == "complete" else None,
        profile_id="torq-v5-repo-compat" if stage == "complete" else None,
        profile_version="1.0.0" if stage == "complete" else None,
        resolution_stage=stage,
    )


def _finding(finding_id: str, path: str) -> Finding:
    return FindingCatalog.make(finding_id, path=path)


def _failure(
    finding_id: str,
    stage: str,
    registry: Registry | None,
    path: str,
    status: str | None = None,
) -> ResultEnvelope:
    finding = _finding(finding_id, path)
    return ResultEnvelope("1.0.0", COMMAND, status or finding.status_class, _snapshot(registry, stage), (finding,), {})


def internal_error() -> ResultEnvelope:
    finding = _finding("internal_error", "/")
    return ResultEnvelope("1.0.0", COMMAND, "internal_error", None, (finding,), {})


def output_rejected() -> ResultEnvelope:
    finding = _finding("console_config_projection_invalid", "/target_config")
    return ResultEnvelope("1.0.0", COMMAND, "invalid", None, (finding,), {})


def _registry() -> tuple[Registry | None, ResultEnvelope | None]:
    try:
        registry = load_registry()
    except RegistryResourceMissing:
        return None, _failure("registry_resource_missing", "registry_read", None, "/registry")
    except RegistryUnreadable:
        return None, _failure("registry_unreadable", "registry_read", None, "/registry")
    except RegistrySyntaxError:
        return None, _failure("registry_syntax_invalid", "registry_parse", None, "/registry")
    except RegistryDocumentError:
        return None, _failure("registry_schema_invalid", "registry_validate", None, "/registry")
    findings = tuple(_finding(item, "/registry") for item in validate_registry(registry))
    if findings:
        status = "invalid" if any(item.status_class == "invalid" for item in findings) else "blocked"
        return None, ResultEnvelope("1.0.0", COMMAND, status, _snapshot(registry, "registry_validate"), findings, {})
    return registry, None


def _console_data() -> Mapping[str, Any]:
    return {
        "schema_valid": True,
        "declaratively_eligible": True,
        "runtime_effective": False,
        "runtime_state": "offline_unattested",
        "source_schema": "torq-console-v5-config-v1",
        "target_config_version": 1,
        "target_profile": {"id": "torq-v5-repo-compat", "version": "1.0.0"},
        "canonicalization": "registry_authoritative_lossy",
        "canonical_target_config_utf8": TARGET_CONFIG_UTF8.decode("utf-8"),
        "canonical_target_config_sha256": TARGET_SHA256,
    }


def import_v5_path(config_path: str) -> ResultEnvelope:
    try:
        registry, failure = _registry()
        if failure is not None:
            return failure
        assert registry is not None

        reference_finding, reference = load_v5_config_reference()
        if reference_finding is not None:
            return _failure(reference_finding, "oracle_validate", registry, "/packaged_reference", "blocked")
        assert reference is not None

        try:
            raw = read_bounded_legacy_config(config_path)
        except ProtectedPathError:
            return _failure("console_config_protected_path_denied", "console_config_read", registry, "/console_config", "blocked")
        except LegacyConfigTooLarge:
            return _failure("console_config_syntax_invalid", "console_config_parse", registry, "/")
        except LegacyConfigUnreadable:
            return _failure("console_config_unreadable", "console_config_read", registry, "/console_config")

        try:
            preflight_console_yaml(raw)
        except ValueError:
            return _failure("console_config_syntax_invalid", "console_config_parse", registry, "/")
        try:
            document = construct_console_yaml(raw)
        except ValueError:
            return _failure("console_config_syntax_invalid", "console_config_parse", registry, "/")

        if contains_console_secret(document):
            return _failure("console_config_secret_field_forbidden", "console_config_validate", registry, "/")
        if not validate_console_schema(document):
            return _failure("console_config_schema_invalid", "console_config_validate", registry, "/")
        if not validate_console_mapping(document, reference):
            return _failure("console_config_mapping_unsupported", "console_config_map", registry, "/agents")

        projection = target_config()
        if not validate_projection(projection, registry):
            return _failure("console_config_projection_invalid", "console_config_project", registry, "/target_config")
        if len(TARGET_CONFIG_UTF8) != 1_029 or hashlib.sha256(TARGET_CONFIG_UTF8).hexdigest() != TARGET_SHA256:
            return _failure("console_config_projection_invalid", "console_config_project", registry, "/target_config")
        return ResultEnvelope("1.0.0", COMMAND, "ok", _snapshot(registry, "complete"), (), _console_data())
    except Exception:
        return internal_error()
