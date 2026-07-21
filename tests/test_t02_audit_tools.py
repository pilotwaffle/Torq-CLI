from __future__ import annotations

import math
import struct
import sqlite3
import hashlib
import pathlib
import os
import base64
import json
import re
import subprocess

import pytest

from scripts.t02_audit_console_head import (
    BootIdentityProvider,
    CANONICAL_COLUMNS,
    OUTPUT_FIELDS,
    PREPARED_AUTHORITY_FIELDS,
    ManifestEntry,
    Phase2Journal,
    canonical_stage_row,
    decode_canonical_stage_row,
    canonical_oracle_facts,
    classify_graph_checkpoint,
    guarded_child_report,
    verify_effective_packets,
    static_audit,
    validate_manifest,
    validate_stage_domains,
    safe_journal_path,
    main,
)
from scripts.t02_mmh_resume_probe import _ForbiddenActionSentinels, _fake_provider_dispatch, _authenticate_checkpoint, _checkpoint_path, _validated_root, run_authenticated_probe


def _external_v15() -> tuple[bytes, dict[str, object]]:
    original_oracle = os.environ["T02_ORACLE"]
    attachment = pathlib.Path(original_oracle).read_bytes()
    assert len(attachment) == 1441 and attachment.endswith(b"\n")
    literal = attachment[:-1]
    assert hashlib.sha256(attachment).hexdigest() == "df11e7980c25e3eb09ae0f28bd5eb475fb54bf0f4ff316ec17be644213789488"
    assert hashlib.sha256(literal).hexdigest() == "fa35124d352b915f650236cb877a207a90b8fa43822349135b6faf5ff020bc74"
    decoded = base64.b64decode(literal, validate=True)
    assert len(decoded) == 1079
    assert hashlib.sha256(decoded).hexdigest() == "1e76c5de38228e4d3c20009e0302f14ffd6613b0614ddba994d99b922ea17cfb"
    obj = json.loads(decoded.decode("utf-8"))
    assert list(obj) == ["columns", "values"]
    assert obj["columns"] == ["run_id", "idx", "seat_id", "role_prompt_id", "effort", "input_hash", "prompt_hash", "config_hash", "model_id", "requested_provider", "actual_provider", "fallback", "adapter_version", "artifact_hash", "prompt_tokens", "completion_tokens", "reasoning_tokens", "cost_usd", "latency_s", "retries", "status"]
    assert [value[0] for value in obj["values"]] == ["text", "int", "text", "text", "text", "text", "text", "text", "text", "text", "text", "int", "text", "text", "int", "int", "int", "real", "real", "int", "text"]
    return decoded, obj


def _v15_row() -> dict[str, object]:
    _, obj = _external_v15()
    row = {}
    for column, (tag, payload) in zip(obj["columns"], obj["values"]):
        raw = base64.b64decode(payload, validate=True) if tag != "int" else payload.encode("ascii")
        row[column] = raw.decode("utf-8") if tag == "text" else int(payload) if tag == "int" else struct.unpack(">d", raw)[0]
    return row


def _claim_for(journal: Phase2Journal, row: dict[str, object], *, owner: str = "owner", fence: int = 1, expires: int = 30_000_000_000) -> None:
    journal.claim(
        row["run_id"],
        row["idx"],
        owner=owner,
        fence=fence,
        expires=expires,
        input_hash=row["input_hash"],
        prompt_hash=row["prompt_hash"],
        config_hash=row["config_hash"],
        model_id=row["model_id"],
    )


def _v15_paths(row: dict[str, object], *, owner: str = "owner", fence: int = 1, generation: int = 0) -> tuple[str, str]:
    run_hash = hashlib.sha256(str(row["run_id"]).encode("utf-8")).hexdigest()
    temp = f"tmp/r/{run_hash}/s/{row['idx']}/g/{generation}/f/{fence}/o/{owner}.part"
    final = f"artifacts/r/{run_hash}/s/{row['idx']}/a/{row['artifact_hash']}.json"
    return temp, final


def _v15e_external_anchor(journal: Phase2Journal, row: dict[str, object], expected: bytes, *, owner: str = "owner", fence: int = 1, expires: int = 30_000_000_000, temp_relpath: str = "tmp/v15e.part", final_relpath: str = "final/v15e.json") -> dict[str, object]:
    prepared_row = {
        "run_id": row["run_id"], "stage_idx": row["idx"], "generation": 0, "publication_id": "pub-0",
        "stage_graph_hash": "a" * 64, "stage_definition_hash": "b" * 64, "stage_identity_json": "{}",
        "input_hash": row["input_hash"], "prompt_hash": row["prompt_hash"], "config_hash": row["config_hash"], "model_id": row["model_id"], "policy_hash": "f" * 64,
        "state": "prepared", "owner_token": owner, "fence": fence, "boot_epoch_id": journal.boot.boot_epoch_id,
        "lease_issued_monotonic_ns": 0, "lease_expires_monotonic_ns": expires, "owner": owner, "expires": expires, "error_code": None,
        "temp_relpath": temp_relpath, "temp_owner_token": owner, "temp_fence": fence, "final_relpath": final_relpath,
        "artifact_sha256": row["artifact_hash"], "artifact_size": len(expected), "canonical_row_bytes": bytes(expected), "canonical_row_sha256": hashlib.sha256(expected).hexdigest(),
    }
    return {"row": prepared_row, "decoded": dict(row), "canonical_row_bytes": bytes(expected), "canonical_row_sha256": hashlib.sha256(expected).hexdigest()}


def _prepare_v15(journal: Phase2Journal, row: dict[str, object], expected: bytes, *, now: int = 2, artifact_size: int | None = None, temp_relpath: str = "tmp/v15e.part", final_relpath: str = "final/v15e.json") -> dict[str, object]:
    size = len(expected) if artifact_size is None else artifact_size
    temp_relpath, final_relpath = _v15_paths(row)
    anchor = _v15e_external_anchor(journal, row, expected, temp_relpath=temp_relpath, final_relpath=final_relpath)
    anchor["row"]["artifact_size"] = size
    return journal.prepare(row["run_id"], row["idx"], "owner", 1, now, expected, row["artifact_hash"], size, temp_relpath, final_relpath, external_anchor=anchor)


def _commit_v15(journal: Phase2Journal, row: dict[str, object], expected: bytes, *, now: int = 3, artifact_size: int | None = None, temp_relpath: str = "tmp/v15e.part", final_relpath: str = "final/v15e.json") -> int:
    temp_relpath, final_relpath = _v15_paths(row)
    anchor = _v15e_external_anchor(journal, row, expected, temp_relpath=temp_relpath, final_relpath=final_relpath)
    if artifact_size is not None:
        anchor["row"]["artifact_size"] = artifact_size
    return journal.commit(row["run_id"], row["idx"], "owner", 1, now, external_anchor=anchor)


def _external_legacy(label: str, env_name: str, packet_sha256: str) -> tuple[bytes, bytes, dict[str, object]]:
    packet = pathlib.Path(os.environ[env_name]).read_bytes()
    assert hashlib.sha256(packet).hexdigest() == packet_sha256
    text = packet.decode("utf-8")
    marker = f"{label}_CANONICAL_ORACLE_B64 =" + chr(10)
    literal = "".join(text.split(marker, 1)[1].split(chr(10) + chr(96) * 3, 1)[0].split())
    assert len(literal) == 1472
    decoded = base64.b64decode(literal, validate=True)
    assert len(decoded) == 1103
    assert hashlib.sha256(decoded).hexdigest() == "d6e0827d0ef38110ffca40cd8fc41f6f86a4e07f978a621a5894648f874be3d6"
    obj = json.loads(decoded.decode("utf-8"))
    row = {}
    for column, (tag, payload) in zip(obj["columns"], obj["values"]):
        raw = base64.b64decode(payload, validate=True) if tag != "int" else payload.encode("ascii")
        row[column] = raw.decode("utf-8") if tag == "text" else int(payload) if tag == "int" else struct.unpack(">d", raw)[0]
    assert [len(row[name]) for name in ("input_hash", "prompt_hash", "config_hash", "artifact_hash")] == [73, 64, 64, 73]
    return literal.encode("ascii"), decoded, row


def test_actual_v13_v14_payloads_rejected_before_mutation():
    v15, _ = _external_v15()
    v13_literal, v13_payload, v13_row = _external_legacy(
        "V13",
        "T02_V13",
        "75ff22d9cfcfda02c105384a891d0d6c07eafc5e316482edc2449bd49029c523",
    )
    v14_literal, v14_payload, v14_row = _external_legacy(
        "V14",
        "T02_V14",
        "32edb3a5d583248b8104e1e82f872846d5d5d1fbbb3feeb62c37a7403a22f906",
    )
    assert len(v13_literal) == len(v14_literal) == 1472
    assert v13_payload == v14_payload
    assert v13_payload != v15 and v14_payload != v15
    for label, payload, row in (("v13", v13_payload, v13_row), ("v14", v14_payload, v14_row)):
        journal = Phase2Journal()
        _claim_for(journal, row)
        before_memory = journal.snapshot(journal._find(row["run_id"], row["idx"]))
        before_journal = journal.connection.execute("select snapshot_json from journal_state").fetchall()
        before_stage = journal.connection.execute("select key, canonical_row_bytes, canonical_row_sha256 from stage_rows").fetchall()
        with pytest.raises(ValueError, match="SHA-256"):
            journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, payload, row["artifact_hash"][:64], 1, "tmp/legacy.part", "final/legacy.json")
        after_memory = journal.snapshot(journal._find(row["run_id"], row["idx"]))
        after_journal = journal.connection.execute("select snapshot_json from journal_state").fetchall()
        after_stage = journal.connection.execute("select key, canonical_row_bytes, canonical_row_sha256 from stage_rows").fetchall()
        assert after_memory == before_memory
        assert after_journal == before_journal
        assert after_stage == before_stage == []
        assert after_memory["canonical_row_bytes"] is None
        assert after_memory["canonical_row_sha256"] is None
        assert row["input_hash"] and row["artifact_hash"]


def test_v15_attachment_matches_external_literal_and_typed_oracle():
    expected, _ = _external_v15()
    row = _v15_row()
    assert canonical_stage_row(row) == expected
    facts = canonical_oracle_facts(row)
    assert facts["length"] == 1079 and facts["sha256"] == "1e76c5de38228e4d3c20009e0302f14ffd6613b0614ddba994d99b922ea17cfb"
    assert struct.pack(">d", row["cost_usd"]).hex() == "3ff0000000000000"
    assert struct.pack(">d", row["latency_s"]).hex() == "0000000000000000"


def test_v15_rejects_malformed_and_legacy_literal_bytes(tmp_path, monkeypatch):
    expected, _ = _external_v15()
    row = _v15_row()
    malformed = tmp_path / "malformed-oracle.b64"
    malformed.write_bytes(base64.b64encode(b"bad") + bytes([10]))
    monkeypatch.setenv("T02_ORACLE", str(malformed))
    with pytest.raises(ValueError):
        canonical_oracle_facts(row)
    legacy = tmp_path / "legacy-oracle.b64"
    legacy.write_bytes(base64.b64encode(b"legacy-v14-diagnostic") + bytes([10]))
    monkeypatch.setenv("T02_ORACLE", str(legacy))
    with pytest.raises(ValueError):
        canonical_oracle_facts(row)


def test_prepare_rejects_invalid_bytes_and_atomic_failure_cuts_rollback():
    expected, _ = _external_v15()
    row = _v15_row()
    invalid = [expected[:-1], b"not-json-canonical", expected + b" "]
    for bad in invalid:
        journal = Phase2Journal()
        _claim_for(journal, row)
        before = journal.snapshot(journal._find(row["run_id"], row["idx"]))
        with pytest.raises(ValueError):
            journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, bad, row["artifact_hash"], 1, "tmp/red.part", "final/red.json")
        assert journal.snapshot(journal._find(row["run_id"], row["idx"])) == before
    for cut in ("after_stage_insert", "during_readback", "before_prepared_to_committed_cas", "after_cas_before_commit", "before_commit"):
        journal = Phase2Journal()
        _claim_for(journal, row)
        prepared = _prepare_v15(journal, row, expected, artifact_size=len(expected), temp_relpath="tmp/red.part", final_relpath="final/red.json")
        before = journal.snapshot(journal._find(row["run_id"], row["idx"]))
        journal.failure_cut = cut
        with pytest.raises(RuntimeError, match="injected failure cut"):
            _commit_v15(journal, row, expected, artifact_size=len(expected), temp_relpath="tmp/red.part", final_relpath="final/red.json")
        assert journal.snapshot(journal._find(row["run_id"], row["idx"])) == before == prepared
        assert journal.connection.execute("select count(*) from stage_rows").fetchone()[0] == 0
        journal.failure_cut = None
        assert _commit_v15(journal, row, expected, artifact_size=len(expected), temp_relpath="tmp/red.part", final_relpath="final/red.json") == 1
        assert journal.connection.execute("select count(*) from stage_rows").fetchone()[0] == 1


def test_canonical_claim_binding_rejects_each_dual_field_before_mutation():
    expected, _ = _external_v15()
    row = _v15_row()
    mismatches = [
        ("run_id", {**row, "run_id": "different-run"}, row["artifact_hash"]),
        ("idx", {**row, "idx": 8}, row["artifact_hash"]),
        ("artifact_hash", row, "e" * 64),
        ("input_hash", {**row, "input_hash": "e" * 64}, row["artifact_hash"]),
        ("prompt_hash", {**row, "prompt_hash": "e" * 64}, row["artifact_hash"]),
        ("config_hash", {**row, "config_hash": "e" * 64}, row["artifact_hash"]),
        ("model_id", {**row, "model_id": "different-model"}, row["artifact_hash"]),
    ]
    for field, payload_row, artifact_claim in mismatches:
        journal = Phase2Journal()
        _claim_for(journal, row)
        before_memory = journal.snapshot(journal._find(row["run_id"], row["idx"]))
        before_journal = journal.connection.execute("select key, snapshot_json from journal_state order by key").fetchall()
        before_stage = journal.connection.execute("select key, canonical_row_bytes, canonical_row_sha256 from stage_rows").fetchall()
        with pytest.raises(ValueError, match="canonical claim mismatch"):
            journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, canonical_stage_row(payload_row), artifact_claim, 1, "tmp/b1.part", "final/b1.json")
        after_memory = journal.snapshot(journal._find(row["run_id"], row["idx"]))
        after_journal = journal.connection.execute("select key, snapshot_json from journal_state order by key").fetchall()
        after_stage = journal.connection.execute("select key, canonical_row_bytes, canonical_row_sha256 from stage_rows").fetchall()
        assert after_memory == before_memory
        assert after_journal == before_journal
        assert after_stage == before_stage == []
        assert after_memory["canonical_row_bytes"] is None
        assert after_memory["canonical_row_sha256"] is None
        prepared = _prepare_v15(journal, row, expected, temp_relpath="tmp/b1.part", final_relpath="final/b1.json")
        assert prepared["state"] == "prepared"
        key = f"{row['run_id']}\0{row['idx']}\0{prepared['generation']}"
        db_row = journal._from_json_row(journal.connection.execute("select snapshot_json from journal_state where key=?", (key,)).fetchone()[0])
        db_row["input_hash"] = "e" * 64
        try:
            journal.connection.execute("update journal_state set snapshot_json=? where key=?", (journal._json_row(db_row), key))
        except sqlite3.IntegrityError as exc:
            assert "immutable" in str(exc)
        else:
            with pytest.raises(ValueError, match="external anchor|canonical claim mismatch|prepared snapshot"):
                _commit_v15(journal, row, expected, temp_relpath="tmp/b1.part", final_relpath="final/b1.json")
        assert journal.connection.execute("select count(*) from stage_rows").fetchone()[0] == 0
        journal._load_rows()
        assert _commit_v15(journal, row, expected, temp_relpath="tmp/b1.part", final_relpath="final/b1.json") == 1
        assert _commit_v15(journal, row, expected, temp_relpath="tmp/b1.part", final_relpath="final/b1.json") == 0
        assert journal.connection.execute("select count(*) from stage_rows").fetchone()[0] == 1


def test_closed_manifest_rejects_escape_duplicate_and_nonregular_entries():
    good = [ManifestEntry("100644", "blob", "a" * 40, "safe/file.py")]
    assert validate_manifest(good, expected=good).ok
    assert not validate_manifest(good + [ManifestEntry("100644", "blob", "b" * 40, "safe/file.py")], expected=good).ok
    assert not validate_manifest([ManifestEntry("100644", "blob", "a" * 40, "../escape")], expected=good).ok
    assert not validate_manifest([ManifestEntry("120000", "blob", "a" * 40, "safe/link")], expected=good).ok
    assert not validate_manifest([ManifestEntry("100644", "tree", "a" * 40, "safe/tree")], expected=good).ok


def test_static_audit_uses_only_pinned_blobs():
    result = static_audit()
    assert result["tree"] == "be2448b3f6c9f281167302d10cd9b49ccd36034a"
    assert result["commit"] == "3ae196102a84aed24f7daa9dc3fed037522e1f20"
    assert result["manifest_count"] == 27
    assert result["object_integrity"] is True
    assert result["config_sha256"] == "be381d4c92df735012601050f88a051d5a24e60894359b97097a5b6086b2e46f"
    assert result["adapters_sha256"] == "c03caa84ccaae0a3a4780ccad89251b382957eb7afcfb532ebc3ec69ed796567"
    assert result["slow_line"] == 166


def test_guarded_child_reports_zero_forbidden_counters():
    result = guarded_child_report()
    assert result["runtime_counters"]
    assert all(value == 0 for value in result["runtime_counters"].values())
    assert result["preflight_counts"] == result["member_counts"]
    assert result["alias_fingerprint"] == result["runtime_alias_fingerprint"]
    assert result["restored_lifo"] is True
    assert result["preflight_attempts"]
    assert result["sentinel_self_test"]["raised"] == result["member_counts"]


def test_graph_checkpoint_contract_classifies_valid_and_invalid_cases():
    hashes = {0: "a" * 64, 1: "b" * 64}
    assert classify_graph_checkpoint([0, 1], hashes)["classification"] == "resume"
    assert classify_graph_checkpoint([0, 1, 2, 4], {**hashes, 2: "c" * 64, 4: "d" * 64}, skip_evidence=True)["classification"] == "resume_with_authenticated_skip"
    rejected = classify_graph_checkpoint([0, 1, 4], {**hashes, 4: "d" * 64})
    assert rejected["classification"] == "reject"
    assert rejected["reason"] == "missing_required_stage:2"
    assert rejected["mutation"] is False


def test_canonical_stage_row_serialization_is_type_preserving():
    expected, _ = _external_v15()
    row = _v15_row()
    encoded = canonical_stage_row(row)
    decoded = encoded.decode("utf-8")
    assert len(row) == len(CANONICAL_COLUMNS) == 21
    assert "columns" in decoded and "values" in decoded
    assert validate_stage_domains(row) is True
    assert struct.pack(">d", row["cost_usd"]).hex() == "3ff0000000000000"
    assert struct.pack(">d", row["latency_s"]).hex() == "0000000000000000"
    oracle = canonical_oracle_facts(row)
    assert encoded == expected
    assert oracle["length"] == 1079
    assert oracle["sha256"] == "1e76c5de38228e4d3c20009e0302f14ffd6613b0614ddba994d99b922ea17cfb"
    with pytest.raises(ValueError):
        validate_stage_domains({**row, "fallback": True})
    with pytest.raises(ValueError):
        validate_stage_domains({**row, "latency_s": -0.0})
    with pytest.raises(ValueError):
        validate_stage_domains({**row, "cost_usd": math.inf})


    assert validate_stage_domains({**row, "idx": 2**63 - 1}) is True
    with pytest.raises(ValueError):
        validate_stage_domains({**row, "idx": 2**63})
    class IntSubclass(int):
        pass
    with pytest.raises(ValueError):
        validate_stage_domains({**row, "idx": IntSubclass(1)})
    encoded_again = canonical_stage_row(row)
    with sqlite3.connect(":memory:") as db:
        db.execute("create table stages (canonical_row blob not null)")
        db.execute("insert into stages values (?)", (encoded_again,))
        retrieved = db.execute("select canonical_row from stages").fetchone()[0]
    assert retrieved == encoded_again


def test_effective_packet_substitutions_fail_closed(tmp_path, monkeypatch):
    valid = {
        "v10": pathlib.Path(os.environ["T02_V10"]),
        "v12": pathlib.Path(os.environ["T02_V12"]),
        "sol": pathlib.Path(os.environ["T02_SOL"]),
        "final": pathlib.Path(os.environ["T02_FINAL"]),
    }
    for name in ("v12", "sol", "final"):
        replacement = tmp_path / f"bogus-{name}.md"
        replacement.write_text("bogus", encoding="utf-8")
        candidate = dict(valid)
        candidate[name] = replacement
        with pytest.raises(ValueError):
            verify_effective_packets(candidate)
def test_phase2_store_recovery_failure_cuts():
    expected, _ = _external_v15()
    journal = Phase2Journal()
    journal.claim("run-1", 0, owner="old", fence=7, expires=0)
    takeover = journal.reclaim_expired("run-1", 0, now=1, owner="recovery-a")
    assert takeover["state"] == "aborting"
    assert takeover["fence"] == 8
    assert takeover["lease_expires_monotonic_ns"] - takeover["lease_issued_monotonic_ns"] == 30_000_000_000
    assert journal.stale_update("run-1", 0, owner="old", fence=7) == 0
    assert journal.cleanup("run-1", 0, owner="recovery-a", fence=8) is True
    successor = journal.finalize_with_successor("run-1", 0, owner="recovery-a", fence=8)
    assert successor["generation"] == 1
    assert journal.stale_update("run-1", 0, owner="recovery-a", fence=8) == 0
    assert journal.reclaim_expired("run-1", 0, now=2, owner="recovery-b")["state"] == "claimed"
    assert all(journal.crash_cut(cut, "run-1", 0) in {"claimed", "aborting", "aborted+successor"} for cut in ("before_takeover_commit", "after_takeover_commit", "during_cleanup", "after_cleanup_before_final_transaction", "during_final_transaction", "after_final_commit"))

    prepared = Phase2Journal()
    row = _v15_row()
    _claim_for(prepared, row)
    _prepare_v15(prepared, row, expected, now=1, temp_relpath="tmp/r/x/s/0/g/0/f/1/o/owner.part", final_relpath="artifacts/r/x/s/0/a/" + row["artifact_hash"] + ".json")
    assert prepared._find(row["run_id"], row["idx"])["state"] == "prepared"
    assert _commit_v15(prepared, row, expected, temp_relpath="tmp/r/x/s/0/g/0/f/1/o/owner.part", final_relpath="artifacts/r/x/s/0/a/" + row["artifact_hash"] + ".json") == 1
    with pytest.raises(RuntimeError, match="publication_corrupt_committed"):
        prepared.corrupt_committed(row["run_id"], row["idx"])

    anomalous = Phase2Journal()
    anomalous.claim("run-3", 0, owner="owner", fence=1, expires=30_000_000_000, issued=10)
    with pytest.raises(RuntimeError, match="lease_clock_anomaly"):
        anomalous.renew("run-3", 0, "owner", 1, 9)
    with pytest.raises(ValueError):
        anomalous.state_shape({})


def test_real_fake_slow_interruption_and_fresh_resume():
    result = run_authenticated_probe()
    assert result["handshake"]["completed"] == [0, 1]
    assert result["handshake"]["run_id"] == "run-t02-oracle-001"
    assert result["handshake"]["call_ordinal"] == 3
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in result["handshake"]["artifact_hashes"].values())
    assert result["handshake"]["third_call_interrupted"] is True
    assert result["reaped"] is True
    assert result["fresh_resume"]["completed"] == [0, 1, 2, 4]
    assert result["fresh_resume"]["checkpoint_consumed"] is True
    assert result["fresh_resume"]["executed"] == [2, 4]
    assert result["fresh_resume"]["skipped"] == [3]
    assert result["fresh_resume"]["classification"] == "resume_with_authenticated_skip"
    assert result["fresh_resume"]["mutation"] is False
    assert result["egress"]["sentinel_scope"] == "actual-worker-fake-execution"
    assert result["egress"]["fake_calls_observed"] == 2
    assert result["egress"]["forbidden_attempts"] == []
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in result["fresh_resume"]["artifact_hashes"].values())
    assert all(value == 0 for value in result["runtime_counters"].values())
    assert result["provider_calls"] == result["network_calls"] == 0
    assert {name: case["outcome"] for name, case in result["failure_cases"].items()} == {"timeout": "timeout", "eof": "eof", "malformed": "malformed_json", "auth-failure": "checkpoint_auth_failure", "later-exception": "later_exception"}
    assert all(case["reap"]["reaped"] for case in result["failure_cases"].values())


def test_v15d_b1_rejects_correlated_prepared_snapshot_tamper_before_stage_insert():
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal()
    _claim_for(journal, row)
    prepared = _prepare_v15(journal, row, expected, temp_relpath="tmp/v15d.part", final_relpath="final/v15d.json")
    key = f"{row['run_id']}\0{row['idx']}\0{prepared['generation']}"
    before_journal = journal.connection.execute("select key, snapshot_json from journal_state order by key").fetchall()
    before_stage = journal.connection.execute("select * from stage_rows order by key").fetchall()
    tampered = dict(prepared)
    tampered_payload = canonical_stage_row({**row, "retries": row["retries"] + 1})
    tampered.update({"canonical_row_bytes": tampered_payload, "canonical_row_sha256": hashlib.sha256(tampered_payload).hexdigest()})
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        journal.connection.execute("update journal_state set snapshot_json=? where key=?", (journal._json_row(tampered), key))
    assert journal.connection.execute("select key, snapshot_json from journal_state order by key").fetchall() == before_journal
    assert journal.connection.execute("select * from stage_rows order by key").fetchall() == before_stage == []
    assert _commit_v15(journal, row, expected, temp_relpath="tmp/v15d.part", final_relpath="final/v15d.json") == 1
    assert _commit_v15(journal, row, expected, temp_relpath="tmp/v15d.part", final_relpath="final/v15d.json") == 0


def test_v15d_b1_rejects_malformed_prepared_shape_without_mutation():
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal()
    _claim_for(journal, row)
    prepared = _prepare_v15(journal, row, expected, temp_relpath="tmp/v15d-shape.part", final_relpath="final/v15d-shape.json")
    key = f"{row['run_id']}\0{row['idx']}\0{prepared['generation']}"
    before_stage = journal.connection.execute("select * from stage_rows order by key").fetchall()
    malformed = dict(prepared, temp_relpath="../escape", artifact_size=-1)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        journal.connection.execute("update journal_state set snapshot_json=? where key=?", (journal._json_row(malformed), key))
    assert journal.connection.execute("select * from stage_rows order by key").fetchall() == before_stage == []
    assert _commit_v15(journal, row, expected, temp_relpath="tmp/v15d-shape.part", final_relpath="final/v15d-shape.json") == 1


def test_v15d_b3_stage_is_decoded_typed_sqlite_roundtrip():
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal()
    _claim_for(journal, row)
    _prepare_v15(journal, row, expected, temp_relpath="tmp/v15d-types.part", final_relpath="final/v15d-types.json")
    assert _commit_v15(journal, row, expected, temp_relpath="tmp/v15d-types.part", final_relpath="final/v15d-types.json") == 1
    columns = [item[1] for item in journal.connection.execute("pragma table_info(stage_rows)").fetchall()]
    assert set(CANONICAL_COLUMNS).issubset(columns)
    values = journal.connection.execute("select " + ",".join(CANONICAL_COLUMNS) + " from stage_rows").fetchone()
    assert values is not None
    assert dict(zip(CANONICAL_COLUMNS, values)) == row
    assert journal.decode_prepared(journal._find(row["run_id"], row["idx"])) == expected


def test_v15d_b3_direct_decoder_negative_matrix():
    expected, obj = _external_v15()
    malformed = []
    duplicate = dict(obj, columns=list(obj["columns"]) + [obj["columns"][0]])
    malformed.append(json.dumps(duplicate, separators=(",", ":")).encode("utf-8"))
    reordered = dict(obj, columns=list(reversed(obj["columns"])))
    malformed.append(json.dumps(reordered, separators=(",", ":")).encode("utf-8"))
    bad_type = json.loads(expected.decode("utf-8"))
    bad_type["values"] = list(bad_type["values"])
    bad_type["values"][0] = ["bytes", bad_type["values"][0][1]]
    malformed.append(json.dumps(bad_type, separators=(",", ":")).encode("utf-8"))
    malformed.extend([b"bnot-json-canonical", expected + b"\n", expected[:-1]])
    for payload in malformed:
        with pytest.raises(ValueError):
            decode_canonical_stage_row(payload)


def test_v15d_b4_durable_sqlite_recovery_uses_fresh_connection(tmp_path):
    db = tmp_path / "phase2.sqlite3"
    first = Phase2Journal(database_path=str(db))
    first.claim("durable-run", 0, owner="old", fence=7, expires=0)
    second = Phase2Journal(database_path=str(db))
    assert second._find("durable-run", 0)["state"] == "claimed"
    takeover = second.reclaim_expired("durable-run", 0, now=1, owner="recovery")
    assert takeover["state"] == "aborting"
    third = Phase2Journal(database_path=str(db))
    assert third._find("durable-run", 0)["state"] == "aborting"


def test_v15d_b4_concurrent_reclaim_and_exact_successor_identity(tmp_path):
    db = tmp_path / "phase2-concurrent.sqlite3"
    first = Phase2Journal(database_path=str(db))
    first.claim("successor-run", 2, owner="old", fence=3, expires=0, input_hash="1" * 64, prompt_hash="2" * 64, config_hash="3" * 64, model_id="m")
    winner = Phase2Journal(database_path=str(db))
    racer = Phase2Journal(database_path=str(db))
    recovered = winner.reclaim_expired("successor-run", 2, now=1, owner="winner")
    assert recovered["state"] == "aborting"
    with pytest.raises(RuntimeError, match="CAS"):
        racer.reclaim_expired("successor-run", 2, now=1, owner="racer")
    predecessor_identity = {field: recovered[field] for field in ("run_id", "stage_idx", "stage_graph_hash", "stage_definition_hash", "stage_identity_json", "input_hash", "prompt_hash", "config_hash", "model_id", "policy_hash")}
    assert winner.cleanup("successor-run", 2, owner="winner", fence=recovered["fence"]) is True
    successor = winner.finalize_with_successor("successor-run", 2, owner="winner", fence=recovered["fence"])
    assert successor["generation"] == recovered["generation"] + 1
    assert {field: successor[field] for field in predecessor_identity} == predecessor_identity
    fresh = Phase2Journal(database_path=str(db))
    assert fresh._find("successor-run", 2, 0)["state"] == "aborted"
    assert fresh._find("successor-run", 2, 1)["state"] == "claimed"
    assert fresh.crash_cut("after_final_commit", "successor-run", 2) == "aborted+successor"


def test_v15d_b2_parent_binding_and_observed_surface_counters():
    result = run_authenticated_probe()
    assert result["parent_binding"]["root_bound"] is True
    assert re.fullmatch(r"[0-9a-f]{64}", result["parent_binding"]["expected_digest"])
    assert set(("cfg.env", "provider", "DNS", "socket", "asyncio", "httpx")).issubset(set(result["egress"]["observed_surface_names"]))
    assert result["egress"]["observed_event_count"] == sum(result["egress"]["observed_surface_counts"].values())
    assert result["egress"]["observed_event_count"] >= 1
    assert all(case["reap"]["tree_reaped"] for case in result["failure_cases"].values())
    assert result["fresh_resume"]["observed_checkpoint_hashes"] == result["handshake"]["artifact_hashes"]
    assert all(case["reap"]["descendants_reaped"] for case in result["failure_cases"].values())


def test_v15d_b2_checkpoint_replacement_escape_and_cross_field_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("LUNA_ROOT", str(tmp_path))
    result = run_authenticated_probe()
    original = pathlib.Path(result["handshake"]["checkpoint_path"])
    envelope = json.loads(original.read_text(encoding="utf-8"))
    root = original.parent.resolve()
    binding = {"checkpoint_path": str(original.resolve()), "checkpoint_integrity": envelope["integrity_sha256"], "handshake_identity": envelope["body"]["handshake_identity"], "adapter_git_blob": envelope["body"]["adapter_git_blob"], "adapter_sha256": envelope["body"]["adapter_sha256"], "root": str(root)}
    binding["expected_digest"] = hashlib.sha256(json.dumps({key: binding[key] for key in binding if key != "expected_digest"}, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(original.read_bytes())
    with pytest.raises(ValueError, match="parent checkpoint binding"):
        _authenticate_checkpoint(replacement, root, binding)
    with pytest.raises(ValueError, match="escapes evidence root"):
        _authenticate_checkpoint(root.parent / "not-a-checkpoint.json", root)
    cross = tmp_path / "cross-field.json"
    tampered_body = dict(envelope["body"], handshake_identity="0" * 64)
    tampered = {"body": tampered_body, "integrity_sha256": hashlib.sha256(json.dumps(tampered_body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}
    cross.write_bytes(json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
    with pytest.raises(ValueError, match="authentication"):
        _authenticate_checkpoint(cross, root, binding)


def test_v15e_b1_external_anchor_rejects_correlated_fresh_reopen_tamper(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    db = tmp_path / "v15e-b1.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    temp_relpath, final_relpath = _v15_paths(row)
    anchor = _v15e_external_anchor(journal, row, expected, temp_relpath=temp_relpath, final_relpath=final_relpath)
    prepared = journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, expected, row["artifact_hash"], len(expected), temp_relpath, final_relpath, external_anchor=anchor)
    key = f"{row['run_id']}\0{row['idx']}\0{prepared['generation']}"
    journal.connection.close()
    mutator = Phase2Journal(root=tmp_path, database_path=str(db))
    db_row = mutator._from_json_row(mutator.connection.execute("select snapshot_json from journal_state where key=?", (key,)).fetchone()[0])
    tampered_payload = canonical_stage_row({**row, "retries": row["retries"] + 1})
    db_row.update({"canonical_row_bytes": tampered_payload, "canonical_row_sha256": hashlib.sha256(tampered_payload).hexdigest()})
    tampered_json = mutator._json_row(db_row)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        mutator.connection.execute("update journal_state set snapshot_json=? where key=?", (tampered_json, key))
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        mutator.connection.execute("update prepared_snapshots set snapshot_json=?, snapshot_sha256=? where key=?", (tampered_json, hashlib.sha256(tampered_json.encode("utf-8")).hexdigest(), key))
    mutator.connection.commit()
    mutator.connection.close()
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    before = {"journal": reopened.connection.execute("select key, snapshot_json from journal_state order by key").fetchall(), "prepared": reopened.connection.execute("select key, snapshot_json, snapshot_sha256 from prepared_snapshots order by key").fetchall(), "stage": reopened.connection.execute("select * from stage_rows order by key").fetchall()}
    assert before["stage"] == []
    assert reopened.commit(row["run_id"], row["idx"], "owner", 1, 3, external_anchor=anchor) == 1
    after = {"journal": reopened.connection.execute("select key, snapshot_json from journal_state order by key").fetchall(), "prepared": reopened.connection.execute("select key, snapshot_json, snapshot_sha256 from prepared_snapshots order by key").fetchall(), "stage": reopened.connection.execute("select * from stage_rows order by key").fetchall()}
    assert after["stage"] != before["stage"]
    assert reopened.commit(row["run_id"], row["idx"], "owner", 1, 3, external_anchor=anchor) == 0


def test_v15e_b2_success_path_installs_and_exercises_every_surface(tmp_path, monkeypatch):
    monkeypatch.setenv("LUNA_ROOT", str(tmp_path))
    result = run_authenticated_probe()
    required = {"cfg.env", "provider", "DNS", "socket", "asyncio", "httpx"}
    assert required.issubset(set(result["egress"]["installed_surface_names"]))
    assert required.issubset(set(result["egress"]["exercised_surface_names"]))
    assert result["fresh_resume"]["reap"]["tree_reaped"] is True
    assert result["fresh_resume"]["reap"]["descendants_reaped"] is True


def test_v15e_b3_scalar_reconstruction_is_authoritative_over_blob(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal(root=tmp_path)
    _claim_for(journal, row)
    temp_relpath, final_relpath = _v15_paths(row)
    anchor = _v15e_external_anchor(journal, row, expected, temp_relpath=temp_relpath, final_relpath=final_relpath)
    journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, expected, row["artifact_hash"], len(expected), temp_relpath, final_relpath, external_anchor=anchor)
    assert journal.commit(row["run_id"], row["idx"], "owner", 1, 3, external_anchor=anchor) == 1
    key = f"{row['run_id']}\0{row['idx']}\0{0}"
    with pytest.raises(sqlite3.IntegrityError, match="immutable|protocol|stage"):
        journal.connection.execute("update stage_rows set canonical_row_bytes=?, canonical_row_sha256=? where key=?", (b"not-authoritative", hashlib.sha256(b"not-authoritative").hexdigest(), key))
    reconstructed = journal.reconstruct_stage_row(key)
    assert reconstructed["row"] == row
    assert reconstructed["canonical_row_bytes"] == expected
    assert reconstructed["canonical_row_sha256"] == hashlib.sha256(expected).hexdigest()


def test_v15e_b3_full_canonical_negative_matrix():
    expected, obj = _external_v15()
    cases = [
        b"bnot-json-canonical", b"\xef\xbb\xbf" + expected, expected.replace(b'"columns"', b'"wrong"', 1), expected + b"\r\n",
        json.dumps({"values": obj["values"], "columns": obj["columns"]}, separators=(",", ":")).encode("utf-8"),
        json.dumps({"columns": obj["columns"], "values": obj["values"][:-1]}, separators=(",", ":")).encode("utf-8"),
    ]
    bad_text = json.loads(expected.decode("utf-8")); bad_text["values"] = list(bad_text["values"]); bad_text["values"][2] = ["text", "%%%"]
    cases.append(json.dumps(bad_text, separators=(",", ":")).encode("utf-8"))
    bad_int = json.loads(expected.decode("utf-8")); bad_int["values"] = list(bad_int["values"]); bad_int["values"][1] = ["int", "True"]
    cases.append(json.dumps(bad_int, separators=(",", ":")).encode("utf-8"))
    for index, payload in enumerate(cases):
        try:
            decode_canonical_stage_row(payload)
        except ValueError:
            continue
        pytest.fail(f"decoder accepted negative case {index}")


def test_v15e_b4_successor_identity_and_fresh_crash_actor(tmp_path):
    db = tmp_path / "v15e-b4.sqlite3"
    first = Phase2Journal(root=tmp_path, database_path=str(db))
    predecessor = first.claim("v15e-run", 0, owner="old", fence=7, expires=0, publication_id="publication-original")
    winner = Phase2Journal(root=tmp_path, database_path=str(db))
    recovered = winner.reclaim_expired("v15e-run", 0, now=1, owner="recovery")
    assert winner.cleanup("v15e-run", 0, owner="recovery", fence=recovered["fence"]) is True
    successor = winner.finalize_with_successor("v15e-run", 0, owner="recovery", fence=recovered["fence"])
    assert successor["publication_id"] == predecessor["publication_id"]
    assert successor["generation"] == predecessor["generation"] + 1
    assert winner.crash_cut("after_final_commit", "v15e-run", 0, close_after=True) == "aborted+successor"
    fresh = Phase2Journal(root=tmp_path, database_path=str(db))
    assert fresh._find("v15e-run", 0, 0)["state"] == "aborted"
    assert fresh._find("v15e-run", 0, 1)["publication_id"] == predecessor["publication_id"]


def test_v15e_b4_crash_cut_closes_initiator_and_uses_fresh_actor(tmp_path):
    db = tmp_path / "v15e-crash.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    journal.claim("v15e-crash", 0, owner="old", fence=1, expires=0)
    assert journal.crash_cut("before_takeover_commit", "v15e-crash", 0, close_after=True) == "aborted+successor"


def test_v15f_red_b1_forged_tampered_authority_is_not_accepted(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    db = tmp_path / "v15f-red-b1.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    temp_relpath, final_relpath = _v15_paths(row)
    anchor = _v15e_external_anchor(journal, row, expected, temp_relpath=temp_relpath, final_relpath=final_relpath)
    prepared = journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, expected, row["artifact_hash"], len(expected), temp_relpath, final_relpath, external_anchor=anchor)
    key = f"{row['run_id']}\0{row['idx']}\0{prepared['generation']}"
    journal.connection.close()
    mutator = Phase2Journal(root=tmp_path, database_path=str(db))
    db_row = mutator._from_json_row(mutator.connection.execute("select snapshot_json from journal_state where key=?", (key,)).fetchone()[0])
    tampered_payload = canonical_stage_row({**row, "retries": row["retries"] + 1})
    tampered_decoded = decode_canonical_stage_row(tampered_payload)
    db_row.update({"canonical_row_bytes": tampered_payload, "canonical_row_sha256": hashlib.sha256(tampered_payload).hexdigest()})
    tampered_json = mutator._json_row(db_row)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        mutator.connection.execute("update journal_state set snapshot_json=? where key=?", (tampered_json, key))
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        mutator.connection.execute("update prepared_snapshots set snapshot_json=?, snapshot_sha256=? where key=?", (tampered_json, hashlib.sha256(tampered_json.encode("utf-8")).hexdigest(), key))
    mutator.connection.commit()
    mutator.connection.close()
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    assert reopened.commit(row["run_id"], row["idx"], "owner", 1, 3, external_anchor=anchor) == 1


def test_v15f_red_b2_target_restoration_fails_closed():
    sentinels = _ForbiddenActionSentinels()
    sentinels.__enter__()
    try:
        original = next(original for target, attr, original in sentinels.records if target is os and attr == "getenv")
        os.getenv = original
        with pytest.raises(ValueError, match="target integrity"):
            sentinels.assert_target_integrity()
    finally:
        for target, attr, original in reversed(sentinels.records):
            setattr(target, attr, original)


def test_v15f_red_b3_scalar_mutation_requires_v15_authority(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal(root=tmp_path)
    _claim_for(journal, row)
    temp_relpath, final_relpath = _v15_paths(row)
    anchor = _v15e_external_anchor(journal, row, expected, temp_relpath=temp_relpath, final_relpath=final_relpath)
    journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, expected, row["artifact_hash"], len(expected), temp_relpath, final_relpath, external_anchor=anchor)
    assert journal.commit(row["run_id"], row["idx"], "owner", 1, 3, external_anchor=anchor) == 1
    key = f"{row['run_id']}\0{row['idx']}\0{0}"
    with pytest.raises(sqlite3.IntegrityError, match="immutable stage scalar|protocol"):
        journal.connection.execute("update stage_rows set retries=? where key=?", (row["retries"] + 1, key))
    assert journal.reconstruct_stage_row(key)["row"]["retries"] == row["retries"]


def test_v15f_red_b4_is_real_process_and_fresh_recovery(tmp_path):
    db = tmp_path / "v15f-red-b4.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    journal.claim("v15f-crash", 0, owner="old", fence=1, expires=0)
    assert journal.crash_cut("before_takeover_commit", "v15f-crash", 0, close_after=True) == "aborted+successor"
    observation = journal.last_crash_observation
    assert observation["initiator_process"] is True
    assert observation["fresh_recovery_actor"] is True
    assert observation["initiator_connection_closed"] is True
    assert observation["tree_reaped"] is True


def test_v15g_red_b2_direct_provider_bypass_fails_closed():
    fake = lambda seat, body: {"seat_id": seat["seat_id"], "body": body}
    with pytest.raises((RuntimeError, ValueError), match="provider|guard|wrapper"):
        _fake_provider_dispatch(fake, {"seat_id": "direct"}, {"model": "fake"})


def test_v15g_red_b2_reset_and_standalone_provider_exercise_are_rejected():
    sentinels = _ForbiddenActionSentinels()
    with sentinels:
        sentinels.invoke_surface("provider")
        assert sentinels.intercepted_counters["provider"] > 0
        with pytest.raises(TypeError):
            sentinels.intercepted_counters["provider"] = 0
        assert sentinels.intercepted_counters["provider"] > 0


def test_v15g_red_b3_negative_zero_and_real_bits_are_immutable(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15g-b3.sqlite3"))
    _claim_for(journal, row)
    _prepare_v15(journal, row, expected, temp_relpath="tmp/v15g-b3.part", final_relpath="final/v15g-b3.json")
    assert _commit_v15(journal, row, expected, temp_relpath="tmp/v15g-b3.part", final_relpath="final/v15g-b3.json") == 1
    key = f"{row['run_id']}\0{row['idx']}\0{0}"
    bits = journal.connection.execute("select cost_usd_bits, latency_s_bits from stage_rows where key=?", (key,)).fetchone()
    assert bits == ("3ff0000000000000", "0000000000000000")
    with pytest.raises(sqlite3.DatabaseError, match="immutable|trigger|authority"):
        journal.connection.execute("update stage_rows set latency_s=? where key=?", (-0.0, key))
    with pytest.raises(sqlite3.DatabaseError, match="immutable|trigger|authority"):
        journal.connection.execute("update stage_rows set latency_s_bits=? where key=?", ("8000000000000000", key))


def test_v15g_red_b4_each_child_cut_has_distinct_durable_outcome(tmp_path):
    cuts = {
        "before_takeover_commit": "aborted+successor",
        "after_takeover_commit": "aborted+successor",
        "during_cleanup": "aborted+successor",
        "after_cleanup_before_final_transaction": "aborted+successor",
        "during_final_transaction": "aborted+successor",
        "after_final_commit": "aborted+successor",
    }
    for index, (cut, expected_outcome) in enumerate(cuts.items()):
        db = tmp_path / f"v15g-b4-{index}.sqlite3"
        journal = Phase2Journal(root=tmp_path, database_path=str(db))
        journal.claim(f"v15g-cut-{index}", 0, owner="old", fence=1, expires=0)
        result = journal.crash_cut(cut, f"v15g-cut-{index}", 0, close_after=True)
        assert journal.last_crash_observation["durable_state_transition"] == expected_outcome
        if cut not in {"before_takeover_commit", "during_final_transaction"}:
            assert journal.last_crash_observation["initiator_pid"] == journal.last_crash_observation["event_pid"]
        if cut == "during_final_transaction":
            assert journal.last_crash_observation["rollback_only"] is True
            assert journal.last_crash_observation["event_pid"] is None
        assert result == expected_outcome


def test_v15h_red_b4_missing_cuts_require_a_distinct_fresh_recovery_actor(tmp_path):
    for index, cut in enumerate(("before_takeover_commit", "after_cleanup_before_final_transaction", "during_final_transaction")):
        db = tmp_path / f"v15h-red-b4-{index}.sqlite3"
        journal = Phase2Journal(root=tmp_path, database_path=str(db))
        journal.claim(f"v15h-red-{index}", 0, owner="old", fence=1, expires=0)
        journal.crash_cut(cut, f"v15h-red-{index}", 0, close_after=True)
        observation = journal.last_crash_observation
        assert observation["recovery_actor_pid"] != observation["initiator_pid"]
        assert observation["recovery_operations"]
        assert observation["recovery_connection_closed"] is True
        assert observation["recovery_operations"][-1]["public_method"] in {"finalize_with_successor", "verify_finalized"}


def test_v15h_b4_fresh_actor_recovery_has_raw_cas_and_successor_proof(tmp_path):
    cuts = {
        "before_takeover_commit": "claimed",
        "after_takeover_commit": "aborting",
        "during_cleanup": "aborting",
        "after_cleanup_before_final_transaction": "aborting",
        "during_final_transaction": "aborting",
        "after_final_commit": "aborted",
    }
    immutable = ("run_id", "stage_idx", "publication_id", "stage_graph_hash", "stage_definition_hash", "stage_identity_json", "input_hash", "prompt_hash", "config_hash", "model_id", "policy_hash")
    for index, (cut, child_state) in enumerate(cuts.items()):
        db = tmp_path / f"v15h-b4-{index}.sqlite3"
        journal = Phase2Journal(root=tmp_path, database_path=str(db))
        run_id = f"v15h-proof-{index}"
        journal.claim(run_id, 0, owner="old", fence=1, expires=0)
        result = journal.crash_cut(cut, run_id, 0, close_after=True)
        observation = journal.last_crash_observation
        assert observation["initiator_pid"] != observation["recovery_actor_pid"]
        assert observation["initiator_connection_closed"] is True
        assert observation["recovery_connection_closed"] is True
        assert observation["recovery_exit_code"] == 0
        assert observation["recovery_before"]["target"]["state"] == child_state
        operations = observation["recovery_operations"]
        assert operations[0]["public_method"] == "stale_update"
        assert operations[0]["cas_rowcount"] == 0
        assert all(op["actor_pid"] == observation["recovery_actor_pid"] for op in operations)
        if cut == "after_final_commit":
            assert operations[-1]["public_method"] == "verify_finalized"
            assert all(op["public_method"] != "finalize_with_successor" for op in operations)
        else:
            assert operations[-1]["public_method"] == "finalize_with_successor"
            assert operations[-1]["cas_rowcount"] == 1
            assert operations[-1]["insert_rowcount"] == 1
            assert any(op["public_method"] == "cleanup" and op["cleanup_rowcount"] == 1 for op in operations)
        rows = sorted((item[1] for item in observation["recovery_after"]["journal_rows"]), key=lambda item: item["generation"])
        assert len(rows) == 2
        predecessor, successor = rows
        assert predecessor["state"] == "aborted"
        assert successor["state"] == "claimed"
        assert successor["generation"] == predecessor["generation"] + 1
        assert all(predecessor[field] == successor[field] for field in immutable)
        assert observation["recovery_after"]["owned_path_exists"] is False
        assert result == "aborted+successor"


def test_v15i_red_no_anchor_correlated_prepared_paths_are_rejected_before_stage_insert(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    db = tmp_path / "v15i-b1-red.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    temp_relpath, final_relpath = _v15_paths(row)
    journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, expected, row["artifact_hash"], len(expected), temp_relpath, final_relpath)
    key = f'{row["run_id"]}\0{row["idx"]}\0{0}'
    journal.connection.close()
    mutator = Phase2Journal(root=tmp_path, database_path=str(db))
    db_row = mutator._from_json_row(mutator.connection.execute("select snapshot_json from journal_state where key=?", (key,)).fetchone()[0])
    db_row.update({"temp_relpath": temp_relpath.replace("owner.part", "tampered-owner.part"), "final_relpath": final_relpath.replace(row["artifact_hash"], "0" * 64)})
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        mutator.connection.execute("update journal_state set snapshot_json=? where key=?", (mutator._json_row(db_row), key))
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        mutator.connection.execute("update prepared_snapshots set snapshot_json=?, snapshot_sha256=? where key=?", (mutator._json_row(db_row), hashlib.sha256(mutator._json_row(db_row).encode("utf-8")).hexdigest(), key))
    mutator.connection.commit()
    mutator.connection.close()
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    before = {"journal": reopened.connection.execute("select key, snapshot_json from journal_state order by key").fetchall(), "prepared": reopened.connection.execute("select key, snapshot_json, snapshot_sha256 from prepared_snapshots order by key").fetchall(), "stage": reopened.connection.execute("select * from stage_rows order by key").fetchall()}
    assert before["stage"] == []
    assert reopened.commit(row["run_id"], row["idx"], "owner", 1, 3) == 1
    after = {"journal": reopened.connection.execute("select key, snapshot_json from journal_state order by key").fetchall(), "prepared": reopened.connection.execute("select key, snapshot_json, snapshot_sha256 from prepared_snapshots order by key").fetchall(), "stage": reopened.connection.execute("select * from stage_rows order by key").fetchall()}
    assert after["stage"] != before["stage"]


def test_v15i_red_original_component_reparse_is_rejected_for_root_checkpoint_and_journal_paths(tmp_path, monkeypatch):
    target = tmp_path / "junction-target"
    target.mkdir()
    (target / "payload.bin").write_bytes(b"payload")
    junction = tmp_path / "junction"
    result = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(junction), str(target)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    monkeypatch.setenv("LUNA_ROOT", str(junction))
    with pytest.raises(ValueError, match="canonical|reparse|junction|component"):
        _validated_root()
    with pytest.raises(ValueError, match="canonical|reparse|junction|component"):
        _checkpoint_path(str(junction / "checkpoint.json"))
    with pytest.raises(ValueError, match="canonical|reparse|junction|component"):
        safe_journal_path(tmp_path, "junction\\payload.bin")
    nested_target = tmp_path / "nested-target"
    nested_target.mkdir()
    (nested_target / "payload.bin").write_bytes(b"nested")
    nested_junction = tmp_path / "nested-junction"
    nested_result = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(nested_junction), str(nested_target)], capture_output=True, text=True)
    assert nested_result.returncode == 0, nested_result.stderr
    with pytest.raises(ValueError, match="canonical|reparse|junction|component"):
        _checkpoint_path(str(nested_junction / "checkpoint.json"))
    with pytest.raises(ValueError, match="canonical|reparse|junction|component"):
        safe_journal_path(tmp_path, "nested-junction\\payload.bin")
    journal = Phase2Journal(root=tmp_path)
    claimed = journal.claim("v15i-cleanup-junction", 0, owner="old", fence=1, expires=0)
    aborting = journal.reclaim_expired("v15i-cleanup-junction", 0, now=1, owner="recovery")
    tampered = dict(aborting, temp_relpath="nested-junction/payload.bin")
    key = "v15i-cleanup-junction\0\0\00"
    journal.rows[("v15i-cleanup-junction", 0, 0)] = tampered
    with pytest.raises(ValueError, match="canonical|reparse|junction|component"):
        journal.cleanup("v15i-cleanup-junction", 0, owner="recovery", fence=aborting["fence"], path=nested_junction / "payload.bin")


def test_v15i_red_ordinary_row_dml_cannot_mutate_committed_journal_or_delete_stage(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    for operation in ("journal_update", "journal_delete", "stage_delete"):
        journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / f"v15i-b3-red-{operation}.sqlite3"))
        _claim_for(journal, row)
        _prepare_v15(journal, row, expected, temp_relpath=f"tmp/v15i-{operation}.part", final_relpath=f"final/v15i-{operation}.json")
        assert _commit_v15(journal, row, expected, temp_relpath=f"tmp/v15i-{operation}.part", final_relpath=f"final/v15i-{operation}.json") == 1
        key = f'{row["run_id"]}\0{row["idx"]}\0{0}'
        if operation == "journal_update":
            with pytest.raises(sqlite3.IntegrityError, match="immutable|committed|invalid"):
                journal.connection.execute("update journal_state set snapshot_json=? where key=?", ("{}", key))
        elif operation == "journal_delete":
            with pytest.raises(sqlite3.IntegrityError, match="immutable|committed"):
                journal.connection.execute("delete from journal_state where key=?", (key,))
        else:
            with pytest.raises(sqlite3.IntegrityError, match="immutable|committed"):
                journal.connection.execute("delete from stage_rows where key=?", (key,))


def test_v15i_red_direct_decoder_rejects_full_nul_control_and_domain_matrix():
    expected, obj = _external_v15()
    def encode(value):
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    def with_value(index, value):
        mutated = {"columns": list(obj["columns"]), "values": list(obj["values"])}
        mutated["values"][index] = value
        return encode(mutated)
    cases = [
        expected[:-1] + b',"columns":[]}',
        b"\xff" + expected,
        b"\xef\xbb\xbf" + expected,
        expected + b" ",
        expected + b"\n",
        json.dumps({"values": obj["values"], "columns": obj["columns"]}, ensure_ascii=True, separators=(",", ":")).encode("utf-8"),
        encode({"columns": list(obj["columns"][:-1]), "values": obj["values"]}),
        with_value(0, ["text"]),
        with_value(0, ["wrong", obj["values"][0][1]]),
        with_value(5, ["text", "A==="]),
        with_value(5, ["text", base64.b64encode(b"x").decode("ascii")]),
        with_value(5, ["text", base64.b64encode(b"\xff\xfe").decode("ascii")]),
        with_value(5, ["text", base64.b64encode(b"hash\x00").decode("ascii")]),
        with_value(1, ["int", "01"]),
        with_value(1, ["int", "-0"]),
        with_value(1, ["int", str(2**63)]),
        with_value(1, ["int", str(-(2**63) - 1)]),
        with_value(17, ["real", base64.b64encode(struct.pack(">d", math.nan)).decode("ascii")]),
        with_value(18, ["real", base64.b64encode(struct.pack(">d", -0.0)).decode("ascii")]),
    ]
    nul = json.loads(expected.decode("utf-8"))
    nul["values"] = list(nul["values"])
    nul["values"][2] = ["text", base64.b64encode(b"seat\x00id").decode("ascii")]
    cases.append(encode(nul))
    control = json.loads(expected.decode("utf-8"))
    control["values"] = list(control["values"])
    control["values"][2] = ["text", base64.b64encode(b"seat\x01id").decode("ascii")]
    cases.append(encode(control))
    for index, payload in enumerate(cases):
        try:
            decode_canonical_stage_row(payload)
        except ValueError:
            continue
        pytest.fail(f"decoder accepted negative case {index}")


def test_v15j_red_no_anchor_correlated_owner_fence_copy_mutation_is_rejected(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    db = tmp_path / "v15j-b1-red.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    temp_relpath, final_relpath = _v15_paths(row)
    journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, expected, row["artifact_hash"], len(expected), temp_relpath, final_relpath)
    key = f'{row["run_id"]}\0{row["idx"]}\0{0}'
    journal.connection.close()
    mutator = Phase2Journal(root=tmp_path, database_path=str(db))
    prepared = mutator._from_json_row(mutator.connection.execute("select snapshot_json from journal_state where key=?", (key,)).fetchone()[0])
    forged_temp, _ = _v15_paths(row, owner="forged-owner", fence=7)
    prepared.update({"owner_token": "forged-owner", "owner": "forged-owner", "fence": 7, "temp_owner_token": "forged-owner", "temp_fence": 7, "temp_relpath": forged_temp})
    forged_json = mutator._json_row(prepared)
    mutation_errors = []
    for table, sql in (
        ("journal_state", "update journal_state set snapshot_json=? where key=?"),
        ("prepared_snapshots", "update prepared_snapshots set snapshot_json=?, snapshot_sha256=? where key=?"),
    ):
        try:
            if table == "journal_state":
                mutator.connection.execute(sql, (forged_json, key))
            else:
                mutator.connection.execute(sql, (forged_json, hashlib.sha256(forged_json.encode("utf-8")).hexdigest(), key))
        except sqlite3.IntegrityError as exc:
            mutation_errors.append(str(exc))
    assert len(mutation_errors) == 2
    before = {"journal": mutator.connection.execute("select key,snapshot_json from journal_state order by key").fetchall(), "prepared": mutator.connection.execute("select key,snapshot_json,snapshot_sha256 from prepared_snapshots order by key").fetchall(), "stage": mutator.connection.execute("select key from stage_rows order by key").fetchall()}
    assert mutator.commit(row["run_id"], row["idx"], "forged-owner", 7, 3) == 0
    after = {"journal": mutator.connection.execute("select key,snapshot_json from journal_state order by key").fetchall(), "prepared": mutator.connection.execute("select key,snapshot_json,snapshot_sha256 from prepared_snapshots order by key").fetchall(), "stage": mutator.connection.execute("select key from stage_rows order by key").fetchall()}
    assert after == before and after["stage"] == []
    assert mutator.commit(row["run_id"], row["idx"], "owner", 1, 3) == 1
    assert mutator.commit(row["run_id"], row["idx"], "owner", 1, 3) == 0


def test_v15j_red_public_cli_rejects_root_junction_before_preflight_or_static_output(tmp_path, monkeypatch, capsys):
    target = tmp_path / "cli-target"
    target.mkdir()
    junction = tmp_path / "cli-junction"
    result = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(junction), str(target)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    common = ["--repo-root", str(repo_root), "--evidence-root", str(junction), "--v10", os.environ["T02_V10"], "--v12", os.environ["T02_V12"], "--sol", os.environ["T02_SOL"], "--final", os.environ["T02_FINAL"], "--oracle", os.environ["T02_ORACLE"], "--console-git-dir", os.environ["TORQ_CONSOLE_GIT_DIR"], "--git-exe", os.environ["TORQ_GIT_EXE"]]
    for command in ("preflight", "static-audit"):
        with pytest.raises(ValueError, match="reparse|evidence root|component"):
            main([command, *common])
        assert not (target / "tmp").exists()
    capsys.readouterr()


def test_v15j_red_safe_journal_path_rejects_noncanonical_separators(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "file.bin").write_bytes(b"x")
    assert safe_journal_path(tmp_path, "plain/file.bin") == (plain / "file.bin").resolve()
    for spelling in ("plain\\file.bin", "plain//file.bin", "./plain/file.bin", "plain/../plain/file.bin", "C:/plain/file.bin", "/plain/file.bin"):
        with pytest.raises(ValueError, match="canonical"):
            safe_journal_path(tmp_path, spelling)


def test_v15j_red_ordinary_dml_key_insert_and_committed_stage_attacks_are_rejected(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15j-b3-red.sqlite3"))
    _claim_for(journal, row)
    _prepare_v15(journal, row, expected)
    assert _commit_v15(journal, row, expected) == 1
    key = f'{row["run_id"]}\0{row["idx"]}\0{0}'
    snapshot = journal.connection.execute("select key,snapshot_json from journal_state order by key").fetchall()
    with pytest.raises(sqlite3.IntegrityError, match="immutable|key|journal"):
        journal.connection.execute("update journal_state set key=? where key=?", ("moved-key", key))
    with pytest.raises(sqlite3.IntegrityError, match="shape|snapshot|journal"):
        journal.connection.execute("insert into journal_state(key,snapshot_json) values (?,?)", ("attacker-key", "{}"))
    with pytest.raises(sqlite3.IntegrityError, match="key|identity|journal"):
        journal.connection.execute("insert into journal_state(key,snapshot_json) values (?,?)", ("wrong-key", journal.connection.execute("select snapshot_json from journal_state where key=?", (key,)).fetchone()[0]))
    with pytest.raises(sqlite3.IntegrityError, match="immutable|stage|key"):
        journal.connection.execute("update stage_rows set key=? where key=?", ("moved-stage", key))
    with pytest.raises(sqlite3.IntegrityError, match="immutable|committed|stage"):
        journal.connection.execute("delete from stage_rows where key=?", (key,))
    assert journal.connection.execute("select key,snapshot_json from journal_state order by key").fetchall() == snapshot
    fresh = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15j-b3-red.sqlite3"))
    assert fresh.reconstruct_stage_row(key)["row"] == row


def test_v15j_red_prepared_takeover_routes_to_coherent_recovery(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    db = tmp_path / "v15j-b4-red.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    temp_relpath, final_relpath = _v15_paths(row)
    journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, expected, row["artifact_hash"], len(expected), temp_relpath, final_relpath)
    taken = journal.takeover_prepared(row["run_id"], row["idx"], 30_000_000_001, "new-owner")
    assert taken["state"] == "aborting"
    assert taken["owner"] == "new-owner"
    assert taken["owner_token"] == "owner" and taken["fence"] == 2
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    assert reopened._find(row["run_id"], row["idx"])["state"] == "aborting"
    assert reopened.commit(row["run_id"], row["idx"], "new-owner", 2, 30_000_000_002) == 0
    recovered = reopened.takeover_aborting(row["run_id"], row["idx"], 60_000_000_001, "recovery")
    assert reopened.cleanup(row["run_id"], row["idx"], "recovery", recovered["fence"])
    successor = reopened.finalize_with_successor(row["run_id"], row["idx"], "recovery", recovered["fence"])
    assert successor["generation"] == 1 and successor["publication_id"] == taken["publication_id"]


def test_v15j_retained_attachment_and_payload_reference_matrix(tmp_path, monkeypatch):
    expected, obj = _external_v15()
    row = _v15_row()
    original_oracle = os.environ["T02_ORACLE"]
    attachment = pathlib.Path(original_oracle).read_bytes()
    attachment_variants = {
        "invalid_alphabet": b"!" + attachment[1:],
        "invalid_padding": attachment[:-2] + b"0\n",
        "invalid_length": attachment[:-2] + b"\n",
        "trailing_literal_data": attachment[:-1] + b"x\n",
        "non_ascii_literal_data": b"\xc3" + attachment[1:],
        "missing_terminal_newline": attachment[:-1],
        "extra_terminal_newline": attachment + b"\n",
        "altered_attachment_digest": attachment[:-2] + bytes([ord("A") if attachment[-2:] != b"A\n" else ord("B")]) + b"\n",
        "altered_length_convention": attachment + b" \n",
    }
    for category, payload in attachment_variants.items():
        candidate = tmp_path / f"attachment-{category}.b64"
        candidate.write_bytes(payload)
        monkeypatch.setenv("T02_ORACLE", str(candidate))
        try:
            canonical_oracle_facts(row)
        except ValueError:
            continue
        raise AssertionError(f"accepted attachment case {category}")
    monkeypatch.setenv("T02_ORACLE", original_oracle)
    def encode(value):
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    def replace_value(index, value):
        mutated = {"columns": list(obj["columns"]), "values": [list(item) for item in obj["values"]]}
        mutated["values"][index] = value
        return encode(mutated)
    payload_cases = {
        "invalid_utf8_bom_nul_control": [b"\xff" + expected, b"\xef\xbb\xbf" + expected, replace_value(2, ["text", base64.b64encode(b"x\x00").decode()]), replace_value(2, ["text", base64.b64encode(b"x\x01").decode()])],
        "json_whitespace_crlf_trailing_truncation": [expected + b" ", expected + b"\n", expected.replace(b"}", b"}\n", 1), expected[:-1]],
        "outer_keys_duplicate_missing_extra_swap": [json.dumps({"values": obj["values"], "columns": obj["columns"]}, ensure_ascii=True, separators=(",", ":")).encode(), encode({"columns": obj["columns"]}), encode({"columns": obj["columns"], "values": obj["values"], "extra": 1}), b'{"columns":' + json.dumps(obj["columns"]).encode() + b',"columns":' + json.dumps(obj["columns"]).encode() + b',"values":' + json.dumps(obj["values"]).encode() + b'}'],
        "values_arity_order_duplicate_missing_extra": [replace_value(0, ["text"]), replace_value(0, ["text", obj["values"][1][1], "extra"]), encode({"columns": list(reversed(obj["columns"])), "values": obj["values"]}), encode({"columns": obj["columns"][:-1], "values": obj["values"]}), encode({"columns": obj["columns"] + ["extra"], "values": obj["values"]}), encode({"columns": obj["columns"] + [obj["columns"][0]], "values": obj["values"] + [obj["values"][0]]}), encode({"columns": obj["columns"], "values": list(reversed(obj["values"]))}), encode({"columns": obj["columns"], "values": obj["values"][:-1]}), encode({"columns": obj["columns"], "values": obj["values"] + [obj["values"][0]]})],
        "tags_base64_utf8_nonstring": [replace_value(0, ["unknown", obj["values"][0][1]]), replace_value(5, ["text", "%%%"]), replace_value(5, ["text", base64.b64encode(b"\xff").decode()]), replace_value(5, ["int", "1"]), replace_value(0, ["text", 1])],
        "integer_spelling_bounds": [replace_value(index, ["int", value]) for index in (1, 11, 14, 15, 16, 19) for value in ("01", "-0", str(2**63), str(-(2**63)-1))],
        "real_nonfinite_negative_zero": [replace_value(17, ["real", base64.b64encode(struct.pack(">d", value)).decode()]) for value in (math.nan, math.inf, -math.inf, -0.0)],
    }
    for index, column in ((5, "input_hash"), (6, "prompt_hash"), (7, "config_hash"), (13, "artifact_hash")):
        original_hash = base64.b64decode(obj["values"][index][1], validate=True).decode("ascii")
        assert len(original_hash) == 64 and re.fullmatch(r"[0-9a-f]{64}", original_hash)
        uppercase_hash = original_hash.upper()
        assert len(uppercase_hash) == 64 and re.fullmatch(r"[0-9A-F]{64}", uppercase_hash)
        assert uppercase_hash.lower() == original_hash and uppercase_hash != original_hash
        payload_cases[f"hash_domain_{column}"] = [
            replace_value(index, ["text", base64.b64encode(uppercase_hash.encode("ascii")).decode("ascii")]),
            replace_value(index, ["text", base64.b64encode(("g" * 64).encode("ascii")).decode("ascii")]),
            replace_value(index, ["text", base64.b64encode(("0" * 63).encode("ascii")).decode("ascii")]),
            replace_value(index, ["text", base64.b64encode(("0" * 65).encode("ascii")).decode("ascii")]),
            replace_value(index, ["text", 1]),
        ]
    payload_cases["real_wire_width_and_noncanonical"] = [
        replace_value(index, ["real", base64.b64encode(b"short").decode("ascii")])
        for index in (17, 18)
    ] + [
        replace_value(index, ["real", base64.b64encode(b"\0" * 8).decode("ascii") + "="])
        for index in (17, 18)
    ]
    payload_cases["real_nonfinite_negative_zero"] = [
        replace_value(index, ["real", base64.b64encode(struct.pack(">d", value)).decode("ascii")])
        for index in (17, 18) for value in (math.nan, math.inf, -math.inf, -0.0)
    ]
    wrong_tag_cases = []
    for index, column in enumerate(CANONICAL_COLUMNS):
        tag = "int" if column in ("idx", "fallback", "prompt_tokens", "completion_tokens", "reasoning_tokens", "retries") else "real" if column in ("cost_usd", "latency_s") else "text"
        alternate = ["text", 1] if tag == "text" else ["text", base64.b64encode(b"0").decode("ascii")]
        wrong_tag_cases.append(replace_value(index, alternate))
    payload_cases["wrong_tag_or_payload_type_each_of_21_fields"] = wrong_tag_cases
    payload_cases["integer_bool_float_type_each_integer"] = [
        replace_value(index, ["int", value])
        for index in (1, 11, 14, 15, 16, 19) for value in (True, 1.0)
    ]
    for category, cases in payload_cases.items():
        for case_index, payload in enumerate(cases):
            try:
                decode_canonical_stage_row(payload)
            except ValueError:
                continue
            raise AssertionError(f"accepted matrix case {category}:{case_index}")
    reference_cases = [replace_value(index, ["text", base64.b64encode(("0" * 64).encode()).decode()]) for index in (5, 6, 7, 13)]
    reference_cases.extend([replace_value(index, ["text", obj["values"][source][1]]) for index, source in ((5, 6), (6, 7), (7, 13), (13, 5))])
    reference_cases.extend([replace_value(14, ["int", "1"]), replace_value(8, ["text", base64.b64encode(b"changed-model").decode()]), replace_value(17, ["real", base64.b64encode(struct.pack(">d", 1.5)).decode()]), replace_value(18, ["real", base64.b64encode(struct.pack(">d", 1.0)).decode()])])
    journal = Phase2Journal()
    _claim_for(journal, row)
    temp_relpath, final_relpath = _v15_paths(row)
    for payload in reference_cases:
        decoded = decode_canonical_stage_row(payload)
        assert canonical_stage_row(decoded) == payload and payload != expected
        with pytest.raises(ValueError, match="V15 authority|canonical claim"):
            journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, payload, row["artifact_hash"], len(expected), temp_relpath, final_relpath)


def test_v15k_red_coherent_higher_generation_prepared_insertion_cannot_mint_commit(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    db = tmp_path / "v15k-higher-generation-red.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    temp_relpath, final_relpath = _v15_paths(row)
    journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, expected, row["artifact_hash"], len(expected), temp_relpath, final_relpath)
    key0 = f'{row["run_id"]}\0{row["idx"]}\0{0}'
    prepared = journal._from_json_row(journal.connection.execute("select snapshot_json from journal_state where key=?", (key0,)).fetchone()[0])
    forged_temp, forged_final = _v15_paths(row, owner="forged-owner", fence=7, generation=1)
    forged = dict(prepared)
    forged.update({"generation": 1, "publication_id": "pub-forged", "owner_token": "forged-owner", "owner": "forged-owner", "fence": 7, "temp_owner_token": "forged-owner", "temp_fence": 7, "temp_relpath": forged_temp, "final_relpath": forged_final})
    key1 = f'{row["run_id"]}\0{row["idx"]}\0{1}'
    forged_json = journal._json_row(forged)
    errors = []
    for table in ("journal_state", "prepared_snapshots"):
        try:
            if table == "journal_state":
                journal.connection.execute("insert into journal_state(key,snapshot_json) values (?,?)", (key1, forged_json))
            else:
                journal.connection.execute("insert into prepared_snapshots(key,snapshot_json,snapshot_sha256) values (?,?,?)", (key1, forged_json, hashlib.sha256(forged_json.encode("utf-8")).hexdigest()))
        except sqlite3.IntegrityError as exc:
            errors.append(str(exc))
    if len(errors) != 2:
        anchor = {"row": forged, "decoded": dict(row), "canonical_row_bytes": expected, "canonical_row_sha256": hashlib.sha256(expected).hexdigest()}
        assert journal.commit(row["run_id"], row["idx"], "forged-owner", 7, 3) == 0
        assert journal.commit(row["run_id"], row["idx"], "forged-owner", 7, 3, external_anchor=anchor) == 0
        pytest.fail(f"ordinary DML inserted forged lifecycle rows: {errors}")
    assert journal.connection.execute("select count(*) from journal_state where key=?", (key1,)).fetchone()[0] == 0
    assert journal.connection.execute("select count(*) from prepared_snapshots where key=?", (key1,)).fetchone()[0] == 0
    assert _commit_v15(journal, row, expected) == 1
    assert journal.commit(row["run_id"], row["idx"], "owner", 1, 3) == 0


def test_v15k_red_incomplete_and_illegal_journal_shapes_fail_before_persistence(tmp_path):
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15k-shape-red.sqlite3"))
    cases = [
        ("incomplete", {"run_id": "attacker", "stage_idx": 0, "generation": 0, "state": "claimed", "publication_id": "p", "owner_token": "o", "fence": 1}),
        ("prepared-genesis", {"run_id": "prepared-genesis", "stage_idx": 0, "generation": 0, "state": "prepared", "publication_id": "p", "owner_token": "o", "fence": 1}),
        ("committed-genesis", {"run_id": "committed-genesis", "stage_idx": 0, "generation": 0, "state": "committed", "publication_id": "p", "owner_token": "o", "fence": 1}),
        ("aborting-genesis", {"run_id": "aborting-genesis", "stage_idx": 0, "generation": 0, "state": "aborting", "publication_id": "p", "owner_token": "o", "fence": 1}),
        ("aborted-genesis", {"run_id": "aborted-genesis", "stage_idx": 0, "generation": 0, "state": "aborted", "publication_id": "p", "owner_token": "o", "fence": 1}),
        ("generation-gap", {"run_id": "generation-gap", "stage_idx": 0, "generation": 2, "state": "claimed", "publication_id": "p", "owner_token": "o", "fence": 1}),
        ("duplicate-successor", {"run_id": "duplicate-successor", "stage_idx": 0, "generation": 1, "state": "claimed", "publication_id": "p", "owner_token": "o", "fence": 1}),
    ]
    for label, row in cases:
        key = f'{row["run_id"]}\0{row["stage_idx"]}\0{row["generation"]}'
        with pytest.raises(sqlite3.IntegrityError, match="journal|shape|transition|authorized|protocol"):
            journal.connection.execute("insert into journal_state(key,snapshot_json) values (?,?)", (key, json.dumps(row, sort_keys=True, separators=(",", ":"))))
        assert journal.connection.execute("select count(*) from journal_state where key=?", (key,)).fetchone()[0] == 0, label


def test_v15k_red_raw_valid_shape_dml_requires_connection_local_protocol_guard(tmp_path):
    db = tmp_path / "v15k-guard-red.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    claimed = journal.claim("guard-base", 0, owner="owner", fence=1, expires=30_000_000_000)
    forged = dict(claimed)
    forged.update({"run_id": "guard-raw", "publication_id": "pub-raw"})
    key = "guard-raw\0 0\0 0".replace(" ", "")
    raw = journal._json_row(forged)
    with pytest.raises(sqlite3.IntegrityError, match="authorized|protocol|guard"):
        journal.connection.execute("insert into journal_state(key,snapshot_json) values (?,?)", (key, raw))
    fresh = sqlite3.connect(str(db), isolation_level=None)
    try:
        forged["run_id"] = "guard-fresh"
        fresh_key = "guard-fresh\0 0\0 0".replace(" ", "")
        with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError), match="authorized|protocol|guard|function"):
            fresh.execute("insert into journal_state(key,snapshot_json) values (?,?)", (fresh_key, journal._json_row(forged)))
    finally:
        fresh.close()
    assert journal.connection.execute("select count(*) from journal_state where key like 'guard-raw%'").fetchone()[0] == 0


def test_v15k_protocol_guard_resets_after_exception(tmp_path):
    journal = Phase2Journal(root=tmp_path)
    with pytest.raises(RuntimeError, match="planned failure"):
        with journal._protocol.authorize("journal_insert", "guard\0 0\0 0".replace(" ", ""), None, "{}", lineage={"key": "guard\0 0\0 0".replace(" ", "")}):
            raise RuntimeError("planned failure")
    assert journal._protocol._context is None


def test_v15k_red_legal_prepare_persists_deterministic_primary_authority_material(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15k-authority-red.sqlite3"))
    _claim_for(journal, row)
    temp_relpath, final_relpath = _v15_paths(row)
    journal.prepare(row["run_id"], row["idx"], "owner", 1, 2, expected, row["artifact_hash"], len(expected), temp_relpath, final_relpath)
    stored = journal._from_json_row(journal.connection.execute("select snapshot_json from journal_state where key=?", (f'{row["run_id"]}\0{row["idx"]}\0{0}',)).fetchone()[0])
    assert type(stored.get("prepared_authority_material")) is str
    assert re.fullmatch(r"[0-9a-f]{64}", stored.get("prepared_authority_digest", ""))
    assert hashlib.sha256(stored["prepared_authority_material"].encode("utf-8")).hexdigest() == stored["prepared_authority_digest"]


def test_v15l_red_claim_is_genesis_only_and_successor_only(tmp_path):
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15l-claim-red.sqlite3"))
    for generation in (2, 1):
        with pytest.raises((ValueError, RuntimeError), match="generation|lineage|claim"):
            journal.claim(f"genesis-{generation}", 0, owner="owner", fence=1, expires=30_000_000_000, generation=generation)
    first = journal.claim("single-lineage", 0, owner="owner", fence=1, expires=30_000_000_000)
    before = journal.connection.execute("select key,snapshot_json from journal_state order by key").fetchall()
    for generation in (0, 1):
        with pytest.raises((ValueError, RuntimeError), match="generation|lineage|claim|successor"):
            journal.claim("single-lineage", 0, owner="other", fence=2, expires=30_000_000_000, generation=generation)
    after = journal.connection.execute("select key,snapshot_json from journal_state order by key").fetchall()
    assert after == before
    assert journal.snapshot(first)["generation"] == 0


def test_v15l_red_generic_public_snapshot_mutation_is_not_a_lifecycle_route(tmp_path):
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15l-generic-red.sqlite3"))
    row = journal.claim("generic-route", 0, owner="owner", fence=1, expires=30_000_000_000)
    snapshot = journal.snapshot(row)
    before = journal.connection.execute("select key,snapshot_json from journal_state order by key").fetchall()
    with pytest.raises((AttributeError, RuntimeError, TypeError), match="public|lifecycle|authorized|generic|snapshot|mutation|route"):
        journal.update("generic-route", 0, 0, {"owner_token": "forged", "owner": "forged", "fence": 9})
    with pytest.raises((AttributeError, RuntimeError, TypeError), match="public|lifecycle|authorized|generic|snapshot|mutation|route"):
        journal.full_snapshot_cas("generic-route", 0, 0, snapshot, {"owner_token": "forged", "owner": "forged", "fence": 9})
    after = journal.connection.execute("select key,snapshot_json from journal_state order by key").fetchall()
    assert after == before
    assert journal._find("generic-route", 0)["owner_token"] == "owner"


def test_v15l_generic_forged_rewrite_cannot_arm_prepare_or_commit(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15l-forged-followup.sqlite3"))
    claimed = _claim_for(journal, row)
    original = journal.snapshot(journal._find(row["run_id"], row["idx"]))
    with pytest.raises(RuntimeError, match="generic public"):
        journal.update(row["run_id"], row["idx"], 0, {"owner_token": "forged", "owner": "forged", "fence": 9})
    with pytest.raises(RuntimeError, match="generic public"):
        journal.full_snapshot_cas(row["run_id"], row["idx"], 0, original, {"owner_token": "forged", "owner": "forged", "fence": 9})
    temp_relpath, final_relpath = _v15_paths(row)
    with pytest.raises(RuntimeError, match="prepare CAS"):
        journal.prepare(row["run_id"], row["idx"], "forged", 9, 2, expected, row["artifact_hash"], len(expected), temp_relpath, final_relpath)
    assert journal._find(row["run_id"], row["idx"])["owner_token"] == original["owner_token"]
    _prepare_v15(journal, row, expected)
    assert _commit_v15(journal, row, expected) == 1


def test_v15l_red_guard_active_wrong_transition_still_fails_sql_predicate(tmp_path):
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15l-trigger-red.sqlite3"))
    claimed = journal.claim("trigger-route", 0, owner="owner", fence=1, expires=30_000_000_000)
    key = "trigger-route\0 0\0 0".replace(" ", "")
    old_json = journal._json_row(claimed)
    forged = dict(claimed)
    forged["state"] = "committed"
    forged["error_code"] = None
    new_json = journal._json_row(forged)
    with pytest.raises(sqlite3.IntegrityError, match="shape|transition|journal|protocol"):
        with journal._protocol.authorize("journal_update", key, old_json, new_json, lineage={"key": key, "generation": 0, "predecessor_state": "claimed", "successor_state": "committed"}):
            journal.connection.execute("update journal_state set snapshot_json=? where key=?", (new_json, key))
    assert journal.connection.execute("select snapshot_json from journal_state where key=?", (key,)).fetchone()[0] == old_json


def test_v15l_red_uppercase_hash_fixture_is_actual_64_character_text(tmp_path):
    _expected, obj = _external_v15()
    for index in (5, 6, 7, 13):
        original = base64.b64decode(obj["values"][index][1], validate=True).decode("ascii")
        upper = original.upper()
        assert len(original) == 64 and re.fullmatch(r"[0-9a-f]{64}", original)
        assert len(upper) == 64 and re.fullmatch(r"[0-9A-F]{64}", upper)
        assert upper.lower() == original and upper != original
        replacement = base64.b64encode(upper.encode("ascii")).decode("ascii")
        assert base64.b64decode(replacement, validate=True).decode("ascii") == upper
        assert len(replacement) == 88
        assert base64.b64decode(replacement, validate=True).decode("ascii") == upper


def test_v15m_red_guarded_journal_hash_and_successor_predicates_are_sql_visible(tmp_path):
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15m-journal-red.sqlite3"))
    claimed = journal._new_identity("v15m-red", 0, 0, "pub-0")
    claimed.update({"state": "claimed", "owner_token": "owner", "fence": 1, "boot_epoch_id": journal.boot.boot_epoch_id,
                    "lease_issued_monotonic_ns": 0, "lease_expires_monotonic_ns": 30_000_000_000,
                    "owner": "owner", "expires": 30_000_000_000, "error_code": None,
                    **{field: None for field in OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS}})
    claimed["stage_graph_hash"] = "NOT-A-SHA256"
    key = "v15m-red\0 0\0 0".replace(" ", "")
    payload = journal._json_row(claimed)
    with journal._protocol.authorize("journal_insert", key, None, payload, lineage={"key": key, "predecessor_state": None}):
        with pytest.raises(sqlite3.IntegrityError, match="journal|protocol|transition|shape"):
            journal.connection.execute("INSERT INTO journal_state(key, snapshot_json) VALUES (?, ?)", (key, payload))
    assert journal.connection.execute("SELECT count(*) FROM journal_state").fetchone()[0] == 0

    successor = dict(claimed)
    successor.update({"generation": 1, "publication_id": "pub-1"})
    successor_key = "v15m-red\0 0\0 1".replace(" ", "")
    successor_payload = journal._json_row(successor)
    with journal._protocol.authorize("journal_insert", successor_key, None, successor_payload,
                                    lineage={"key": successor_key, "operation": "finalize_with_successor",
                                             "predecessor_state": "aborted", "predecessor_generation": 0,
                                             "successor_key": successor_key}):
        with pytest.raises(sqlite3.IntegrityError, match="journal|protocol|transition|shape"):
            journal.connection.execute("INSERT INTO journal_state(key, snapshot_json) VALUES (?, ?)", (successor_key, successor_payload))
    assert journal.connection.execute("SELECT count(*) FROM journal_state").fetchone()[0] == 0


def test_v15m_red_stage_sql_scalar_is_bound_and_prepared_copy_digest_is_bound(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15m-stage-red.sqlite3"))
    _claim_for(journal, row)
    prepared = _prepare_v15(journal, row, expected)
    key = f"{row['run_id']}\0{row['idx']}\0{0}"
    decoded = decode_canonical_stage_row(expected)
    values = [decoded[column] for column in CANONICAL_COLUMNS]
    values[CANONICAL_COLUMNS.index("seat_id")] = "WRONG-SQL-SCALAR"
    columns = ", ".join(f'"{column}"' for column in CANONICAL_COLUMNS + ("cost_usd_bits", "latency_s_bits"))
    placeholders = ", ".join("?" for _ in CANONICAL_COLUMNS + ("cost_usd_bits", "latency_s_bits"))
    bits = [struct.pack(">d", decoded[column]).hex() for column in ("cost_usd", "latency_s")]
    sql = f"INSERT INTO stage_rows(key, {columns}, canonical_row_bytes, canonical_row_sha256) VALUES (?, {placeholders}, ?, ?)"
    with journal._protocol.authorize("stage_insert", key, None, hashlib.sha256(expected).hexdigest(),
                                    lineage={"key": key, "generation": 0, "prepared_authority_digest": prepared["prepared_authority_digest"]}):
        with pytest.raises(sqlite3.IntegrityError, match="stage|protocol|scalar"):
            journal.connection.execute(sql, [key, *values, *bits, expected, hashlib.sha256(expected).hexdigest()])
    assert journal.connection.execute("SELECT count(*) FROM stage_rows").fetchone()[0] == 0

    source_json = journal._json_row(prepared)
    copy_db = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15m-copy-red.sqlite3"))
    copy_key = key
    with copy_db._protocol.authorize("prepared_insert", copy_key, None, source_json,
                                    lineage={"key": copy_key, "generation": 0, "predecessor_state": "claimed", "successor_state": "prepared", "prepared_authority_digest": prepared["prepared_authority_digest"]}):
        with pytest.raises(sqlite3.IntegrityError, match="prepared|protocol|digest"):
            copy_db.connection.execute("INSERT INTO prepared_snapshots(key, snapshot_json, snapshot_sha256) VALUES (?, ?, ?)",
                                       (copy_key, source_json, "0" * 64))
    assert copy_db.connection.execute("SELECT count(*) FROM prepared_snapshots").fetchone()[0] == 0


@pytest.mark.parametrize("column", CANONICAL_COLUMNS)
def test_v15m_red_every_stage_scalar_is_sql_bound(tmp_path, column):
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / f"v15m-scalar-{CANONICAL_COLUMNS.index(column)}.sqlite3"))
    _claim_for(journal, row)
    prepared = _prepare_v15(journal, row, expected)
    key = f"{row['run_id']}\0{row['idx']}\0{0}"
    decoded = decode_canonical_stage_row(expected)
    values = [decoded[name] for name in CANONICAL_COLUMNS]
    position = CANONICAL_COLUMNS.index(column)
    values[position] = 2.0 if isinstance(values[position], float) else (99 if isinstance(values[position], int) else "WRONG-SQL-SCALAR")
    columns = ", ".join(f'"{name}"' for name in CANONICAL_COLUMNS + ("cost_usd_bits", "latency_s_bits"))
    placeholders = ", ".join("?" for _ in CANONICAL_COLUMNS + ("cost_usd_bits", "latency_s_bits"))
    bits = [struct.pack(">d", decoded[name]).hex() for name in ("cost_usd", "latency_s")]
    sql = f"INSERT INTO stage_rows(key, {columns}, canonical_row_bytes, canonical_row_sha256) VALUES (?, {placeholders}, ?, ?)"
    with journal._protocol.authorize("stage_insert", key, None, hashlib.sha256(expected).hexdigest(),
                                    lineage={"key": key, "generation": 0, "prepared_authority_digest": prepared["prepared_authority_digest"]}):
        with pytest.raises(sqlite3.IntegrityError, match="stage|protocol|scalar"):
            journal.connection.execute(sql, [key, *values, *bits, expected, hashlib.sha256(expected).hexdigest()])
    assert journal.connection.execute("SELECT count(*) FROM stage_rows").fetchone()[0] == 0


def test_v15m_green_journal_domain_transition_and_prepared_copy_matrix(tmp_path):
    invalid_claims = {
        "stage_graph_hash": "G" * 64,
        "stage_definition_hash": "A" * 64,
        "input_hash": "x" * 64,
        "prompt_hash": None,
        "config_hash": "c" * 63,
        "policy_hash": "f" * 65,
        "stage_identity_json": "{ }",
        "state": "unlisted",
        "stage_idx": -1,
        "generation": -1,
        "fence": -1,
        "lease_issued_monotonic_ns": -1,
        "lease_expires_monotonic_ns": -1,
        "expires": -1,
    }
    for field, value in invalid_claims.items():
        db = tmp_path / f"domain-{field}.sqlite3"
        journal = Phase2Journal(root=tmp_path, database_path=str(db))
        candidate = journal._new_identity(f"v15m-domain-{field}", 0, 0, "pub-0")
        candidate.update({"state": "claimed", "owner_token": "owner", "fence": 1, "boot_epoch_id": journal.boot.boot_epoch_id,
                          "lease_issued_monotonic_ns": 0, "lease_expires_monotonic_ns": 30_000_000_000,
                          "owner": "owner", "expires": 30_000_000_000, "error_code": None,
                          **{name: None for name in OUTPUT_FIELDS + PREPARED_AUTHORITY_FIELDS}})
        candidate[field] = value
        key = f"{candidate['run_id']}\0{candidate['stage_idx']}\0{candidate['generation']}"
        payload = journal._json_row(candidate)
        with journal._protocol.authorize("journal_insert", key, None, payload, lineage={"key": key, "predecessor_state": None}):
            with pytest.raises(sqlite3.IntegrityError, match="journal|protocol|transition|shape"):
                journal.connection.execute("INSERT INTO journal_state(key, snapshot_json) VALUES (?, ?)", (key, payload))
        assert journal.connection.execute("SELECT count(*) FROM journal_state").fetchone()[0] == 0
        assert journal._protocol._context is None
        assert journal.claim(candidate["run_id"], 0, owner="owner", fence=1, expires=30_000_000_000)["generation"] == 0

    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "transition.sqlite3"))
    _claim_for(journal, row)
    old = journal._find(row["run_id"], row["idx"])
    forged = dict(old)
    forged.update({"state": "prepared", "fence": 2})
    forged_json = journal._json_row(forged)
    key = f"{row['run_id']}\0{row['idx']}\0{0}"
    with journal._protocol.authorize("journal_update", key, journal._json_row(old), forged_json,
                                    lineage={"key": key, "predecessor_state": "claimed", "successor_state": "prepared"}):
        with pytest.raises(sqlite3.IntegrityError, match="journal|protocol|transition|shape"):
            journal.connection.execute("UPDATE journal_state SET snapshot_json=? WHERE key=?", (forged_json, key))
    assert journal._from_json_row(journal.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (key,)).fetchone()[0]) == old
    _prepare_v15(journal, row, expected)
    assert _commit_v15(journal, row, expected) == 1

    source_json = journal._json_row(journal._find(row["run_id"], row["idx"]))
    source_prepared = dict(journal._from_json_row(source_json))
    source_prepared["state"] = "prepared"
    source_prepared["temp_relpath"] = _v15_paths(row)[0]
    source_prepared["temp_owner_token"] = "owner"
    source_prepared["temp_fence"] = 1
    source_prepared["canonical_row_bytes"] = expected
    source_prepared["canonical_row_sha256"] = hashlib.sha256(expected).hexdigest()
    source_json = journal._json_row(source_prepared)
    for label, db, copy_json in (
        ("orphan", tmp_path / "copy-orphan.sqlite3", source_json),
        ("nonprepared", tmp_path / "copy-nonprepared.sqlite3", journal._json_row(old)),
    ):
        target = Phase2Journal(root=tmp_path, database_path=str(db))
        copy_key = key
        digest = hashlib.sha256(copy_json.encode("utf-8")).hexdigest()
        with target._protocol.authorize("prepared_insert", copy_key, None, copy_json,
                                        lineage={"key": copy_key, "generation": 0, "predecessor_state": "claimed", "successor_state": "prepared"}):
            with pytest.raises(sqlite3.IntegrityError, match="prepared|protocol|digest"):
                target.connection.execute("INSERT INTO prepared_snapshots(key, snapshot_json, snapshot_sha256) VALUES (?, ?, ?)", (copy_key, copy_json, digest))
        assert target.connection.execute("SELECT count(*) FROM prepared_snapshots").fetchone()[0] == 0


@pytest.mark.parametrize("attack", ("unexpired", "wrong_temp_owner", "wrong_temp_fence", "wrong_path", "wrong_boot", "wrong_lease"))
def test_v15n_red_claimed_to_aborting_requires_complete_sql_relation(tmp_path, attack):
    db = tmp_path / f"v15n-claimed-aborting-{attack}.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    old = journal.claim(f"v15n-{attack}", 0, owner="old-owner", fence=7, expires=30_000_000_000)
    key = f"{old['run_id']}\0{old['stage_idx']}\0{old['generation']}"
    old_json = journal._json_row(old)
    old_expiry = old["lease_expires_monotonic_ns"]
    issue = 1 if attack == "unexpired" else old_expiry + 1
    new = dict(old)
    new.update({
        "state": "aborting",
        "error_code": "claimed_lease_expired",
        "owner_token": "recovery-owner",
        "owner": "recovery-owner",
        "fence": old["fence"] + 1,
        "boot_epoch_id": journal.boot.boot_epoch_id,
        "lease_issued_monotonic_ns": issue,
        "lease_expires_monotonic_ns": issue + 30_000_000_000,
        "expires": issue + 30_000_000_000,
        "temp_owner_token": old["owner_token"],
        "temp_fence": old["fence"],
        "temp_relpath": f"tmp/r/{hashlib.sha256(old['run_id'].encode('utf-8')).hexdigest()}/s/0/g/0/f/7/o/old-owner.part",
    })
    if attack == "wrong_temp_owner":
        new["temp_owner_token"] = "WRONG-TEMP-OWNER"
    elif attack == "wrong_temp_fence":
        new["temp_fence"] = 99
    elif attack == "wrong_path":
        new["temp_relpath"] = "tmp/not-derived.part"
    elif attack == "wrong_boot":
        new["boot_epoch_id"] = "foreign-boot"
    elif attack == "wrong_lease":
        new["lease_expires_monotonic_ns"] = issue
        new["expires"] = issue
    new_json = journal._json_row(new)
    with pytest.raises(sqlite3.IntegrityError, match="journal|protocol|transition|shape|lease|temporary"):
        with journal._protocol.authorize("journal_update", key, old_json, new_json,
                                         lineage={"key": key, "generation": 0,
                                                  "predecessor_state": "claimed", "successor_state": "aborting"}):
            journal.connection.execute("UPDATE journal_state SET snapshot_json=? WHERE key=?", (new_json, key))
    assert journal.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (key,)).fetchone()[0] == old_json
    assert journal._protocol._context is None
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    assert reopened._find(old["run_id"], old["stage_idx"]) == old
    recovered = reopened.reclaim_expired(old["run_id"], old["stage_idx"], old_expiry + 1, "recovery-owner")
    assert recovered["state"] == "aborting"


def test_v15n_red_prepared_to_committed_requires_one_matching_stage_row(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    db = tmp_path / "v15n-prepared-commit-no-stage.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    prepared = _prepare_v15(journal, row, expected)
    key = f"{row['run_id']}\0{row['idx']}\0{0}"
    old_json = journal._json_row(prepared)
    committed = dict(prepared)
    committed.update({"state": "committed", "temp_relpath": None, "temp_owner_token": None, "temp_fence": None})
    new_json = journal._json_row(committed)
    with pytest.raises(sqlite3.IntegrityError, match="journal|protocol|transition|stage|shape"):
        with journal._protocol.authorize("journal_update", key, old_json, new_json,
                                         lineage={"key": key, "generation": 0,
                                                  "predecessor_state": "prepared", "successor_state": "committed"}):
            journal.connection.execute("UPDATE journal_state SET snapshot_json=? WHERE key=?", (new_json, key))
    assert journal.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (key,)).fetchone()[0] == old_json
    assert journal.connection.execute("SELECT count(*) FROM stage_rows").fetchone()[0] == 0
    assert journal._protocol._context is None
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    assert reopened._find(row["run_id"], row["idx"])["state"] == "prepared"
    assert _commit_v15(reopened, row, expected) == 1


def test_v15n_red_public_file_backed_repeated_generation_two_is_contiguous(tmp_path):
    db = tmp_path / "v15n-generation-two.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    run_id = "v15n-repeated-generation"
    first = journal.claim(run_id, 0, owner="owner-0", fence=1, expires=0)
    aborted_zero = journal.reclaim_expired(run_id, 0, 1, "recovery-0")
    journal.cleanup(run_id, 0, "recovery-0", aborted_zero["fence"])
    claimed_one = journal.finalize_with_successor(run_id, 0, "recovery-0", aborted_zero["fence"])
    assert claimed_one["generation"] == 1
    aborted_one = journal.reclaim_expired(run_id, 0, claimed_one["lease_expires_monotonic_ns"] + 1, "recovery-1")
    journal.cleanup(run_id, 0, "recovery-1", aborted_one["fence"])
    claimed_two = journal.finalize_with_successor(run_id, 0, "recovery-1", aborted_one["fence"])
    assert claimed_two["generation"] == 2
    rows = journal.connection.execute("SELECT key, snapshot_json FROM journal_state ORDER BY key").fetchall()
    assert [journal._from_json_row(snapshot)["generation"] for _, snapshot in rows] == [0, 1, 2]
    assert [journal._from_json_row(snapshot)["state"] for _, snapshot in rows] == ["aborted", "aborted", "claimed"]
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    assert reopened._find(run_id, 0)["generation"] == 2


@pytest.mark.parametrize("field", (
    "owner_token", "owner", "boot_epoch_id", "lease_issued_monotonic_ns",
    "lease_expires_monotonic_ns", "expires", "temp_owner_token", "temp_fence", "temp_relpath",
))
def test_v15n_red_claimed_to_aborting_relation_field_matrix(tmp_path, field):
    db = tmp_path / f"v15n-field-{field}.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    old = journal.claim(f"v15n-field-{field}", 0, owner="old-owner", fence=7, expires=30_000_000_000)
    key = f"{old['run_id']}\0{old['stage_idx']}\0{old['generation']}"
    old_json = journal._json_row(old)
    issue = old["lease_expires_monotonic_ns"] + 1
    new = dict(old)
    new.update({
        "state": "aborting", "error_code": "claimed_lease_expired", "owner_token": "recovery-owner",
        "owner": "recovery-owner", "fence": old["fence"] + 1, "boot_epoch_id": journal.boot.boot_epoch_id,
        "lease_issued_monotonic_ns": issue, "lease_expires_monotonic_ns": issue + 30_000_000_000,
        "expires": issue + 30_000_000_000, "temp_owner_token": old["owner_token"], "temp_fence": old["fence"],
        "temp_relpath": f"tmp/r/{hashlib.sha256(old['run_id'].encode('utf-8')).hexdigest()}/s/0/g/0/f/7/o/old-owner.part",
    })
    replacements = {
        "owner_token": "mismatched-token", "owner": "mismatched-owner", "boot_epoch_id": "foreign-boot",
        "lease_issued_monotonic_ns": old["lease_expires_monotonic_ns"] - 1,
        "lease_expires_monotonic_ns": issue + 29_000_000_000, "expires": issue + 29_000_000_000,
        "temp_owner_token": "mismatched-temp-owner", "temp_fence": 99, "temp_relpath": "tmp/not-derived.part",
    }
    new[field] = replacements[field]
    new_json = journal._json_row(new)
    with pytest.raises(sqlite3.IntegrityError, match="journal|protocol|transition|shape|lease|temporary"):
        with journal._protocol.authorize("journal_update", key, old_json, new_json,
                                         lineage={"key": key, "generation": 0,
                                                  "predecessor_state": "claimed", "successor_state": "aborting"}):
            journal.connection.execute("UPDATE journal_state SET snapshot_json=? WHERE key=?", (new_json, key))
    assert journal.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (key,)).fetchone()[0] == old_json
    assert journal._protocol._context is None


def _v15_raw_prepared_candidate(journal, row, expected):
    """Build the independently decoded V15 prepared claim for a SQL attack."""
    old = journal._find(row["run_id"], row["idx"])
    temp_relpath, final_relpath = _v15_paths(row)
    candidate = dict(old)
    candidate.update({
        "state": "prepared",
        "temp_relpath": temp_relpath,
        "temp_owner_token": old["owner_token"],
        "temp_fence": old["fence"],
        "final_relpath": final_relpath,
        "artifact_sha256": row["artifact_hash"],
        "artifact_size": len(expected),
        "canonical_row_bytes": bytes(expected),
        "canonical_row_sha256": hashlib.sha256(expected).hexdigest(),
    })
    candidate.update(journal._prepared_authority_fields(candidate, journal._json_row(old), journal._v15_authority()))
    return old, candidate


def test_v15o_red_guard_active_claimed_to_prepared_requires_atomic_copy(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    db = tmp_path / "v15o-red-claimed-prepared-no-copy.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    old, candidate = _v15_raw_prepared_candidate(journal, row, expected)
    key = f"{row['run_id']}\0{row['idx']}\0{old['generation']}"
    old_json = journal._json_row(old)
    new_json = journal._json_row(candidate)
    with journal._protocol.authorize(
        "journal_update", key, old_json, new_json,
        prepared_authority_digest=candidate["prepared_authority_digest"],
        lineage={"key": key, "generation": old["generation"], "predecessor_state": "claimed", "successor_state": "prepared"},
    ):
        with pytest.raises(sqlite3.IntegrityError, match="journal|protocol|prepared|copy"):
            journal.connection.execute("UPDATE journal_state SET snapshot_json=? WHERE key=?", (new_json, key))
    assert journal.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (key,)).fetchone()[0] == old_json
    assert journal.connection.execute("SELECT count(*) FROM prepared_snapshots").fetchone()[0] == 0
    assert journal._protocol._context is None
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    assert reopened._find(row["run_id"], row["idx"])["state"] == "claimed"
    prepared = _prepare_v15(reopened, row, expected)
    assert reopened.connection.execute("SELECT count(*) FROM prepared_snapshots").fetchone()[0] == 1
    assert prepared["state"] == "prepared"


@pytest.mark.parametrize("column", ("latency_s", "cost_usd"))
def test_v15o_red_guard_active_stage_rejects_real_bit_mismatch(tmp_path, column):
    expected, _ = _external_v15()
    row = _v15_row()
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / f"v15o-red-real-{column}.sqlite3"))
    _claim_for(journal, row)
    prepared = _prepare_v15(journal, row, expected)
    key = f"{row['run_id']}\0{row['idx']}\0{0}"
    decoded = decode_canonical_stage_row(expected)
    values = [decoded[name] for name in CANONICAL_COLUMNS]
    position = CANONICAL_COLUMNS.index(column)
    values[position] = -0.0 if column == "latency_s" else float(decoded[column])
    bits = [struct.pack(">d", decoded[name]).hex() for name in ("cost_usd", "latency_s")]
    bits[0 if column == "cost_usd" else 1] = "0000000000000000" if column == "cost_usd" else "0000000000000000"
    if column == "cost_usd":
        bits[0] = "bff0000000000000"
    columns = ", ".join(f'"{name}"' for name in CANONICAL_COLUMNS + ("cost_usd_bits", "latency_s_bits"))
    placeholders = ", ".join("?" for _ in CANONICAL_COLUMNS + ("cost_usd_bits", "latency_s_bits"))
    sql = f"INSERT INTO stage_rows(key, {columns}, canonical_row_bytes, canonical_row_sha256) VALUES (?, {placeholders}, ?, ?)"
    with journal._protocol.authorize(
        "stage_insert", key, None, hashlib.sha256(expected).hexdigest(),
        lineage={"key": key, "generation": 0, "prepared_authority_digest": prepared["prepared_authority_digest"]},
    ):
        with pytest.raises(sqlite3.IntegrityError, match="stage|protocol|real|bit|scalar"):
            journal.connection.execute(sql, [key, *values, *bits, expected, hashlib.sha256(expected).hexdigest()])
    assert journal.connection.execute("SELECT count(*) FROM stage_rows").fetchone()[0] == 0
    assert journal._protocol._context is None


def test_v15o_red_takeover_prepared_binds_recovery_lease_actor(tmp_path):
    expected, _ = _external_v15()
    row = _v15_row()
    db = tmp_path / "v15o-red-takeover-prepared-owner.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row, owner="execution-owner", fence=9, expires=30_000_000_000)
    temp_relpath, final_relpath = _v15_paths(row, owner="execution-owner", fence=9)
    anchor = _v15e_external_anchor(
        journal, row, expected, owner="execution-owner", fence=9,
        temp_relpath=temp_relpath, final_relpath=final_relpath,
    )
    prepared = journal.prepare(
        row["run_id"], row["idx"], "execution-owner", 9, 2, expected,
        row["artifact_hash"], len(expected), temp_relpath, final_relpath,
        external_anchor=anchor,
    )
    taken = journal.takeover_prepared(row["run_id"], row["idx"], 30_000_000_001, "recovery-owner")
    assert taken["state"] == "aborting"
    assert taken["owner"] == "recovery-owner"
    assert taken["owner_token"] == "execution-owner"
    assert taken["fence"] == prepared["fence"] + 1
    assert taken["boot_epoch_id"] == journal.boot.boot_epoch_id
    assert taken["lease_issued_monotonic_ns"] == 30_000_000_001
    assert taken["expires"] == taken["lease_expires_monotonic_ns"]


@pytest.mark.parametrize(
    ("cost_usd", "latency_s"),
    [
        (1, 0),
        ("1.0", "0.0"),
        ("1.0", -0.0),
    ],
    ids=["integer-affinity", "text-affinity", "negative-zero-affinity"],
)
def test_v15p_red_alternate_stage_spellings_persist_and_poison_retry(tmp_path, cost_usd, latency_s):
    """V15O RED: alternate ordinary DML bypasses the raw REAL boundary."""
    row = _v15_row()
    expected = canonical_stage_row(row)
    db = tmp_path / "v15p-red-affinity.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    prepared = _prepare_v15(journal, row, expected)
    key = f'{row["run_id"]}\0{row["idx"]}\0{0}'
    values = [row[column] for column in CANONICAL_COLUMNS]
    values[CANONICAL_COLUMNS.index("cost_usd")] = cost_usd
    values[CANONICAL_COLUMNS.index("latency_s")] = latency_s
    bits = ["3ff0000000000000", "0000000000000000"]
    columns = ", ".join(f'"{column}"' for column in ("key", *CANONICAL_COLUMNS, "cost_usd_bits", "latency_s_bits"))
    placeholders = ", ".join("?" for _ in ("key", *CANONICAL_COLUMNS, "cost_usd_bits", "latency_s_bits"))
    sql = f'INSERT OR ABORT INTO "stage_rows" ({columns}, canonical_row_bytes, canonical_row_sha256) VALUES ({placeholders}, ?, ?)'
    with journal._protocol.authorize(
        "stage_insert",
        key,
        None,
        hashlib.sha256(expected).hexdigest(),
        prepared_authority_digest=prepared["prepared_authority_digest"],
        lineage={"key": key, "generation": "0", "prepared_authority_digest": prepared["prepared_authority_digest"]},
    ):
        with pytest.raises(sqlite3.DatabaseError):
            journal.connection.execute(sql, [key, *values, *bits, expected, hashlib.sha256(expected).hexdigest()])
    assert journal.connection.execute("SELECT count(*) FROM stage_rows WHERE key=?", (key,)).fetchone()[0] == 0
    assert journal._protocol._context is None
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    assert reopened.connection.execute("SELECT count(*) FROM stage_rows WHERE key=?", (key,)).fetchone()[0] == 0
    assert _commit_v15(reopened, row, expected) == 1
    assert reopened.connection.execute("SELECT count(*) FROM stage_rows WHERE key=?", (key,)).fetchone()[0] == 1


def test_v15p_prepared_finalize_retains_primary_material_and_copy_parity(tmp_path):
    """V15P GREEN: prepared-derived finalization retains immutable material parity."""
    row = _v15_row()
    expected = canonical_stage_row(row)
    db = tmp_path / "v15p-red-finalize-parity.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row, expires=30_000_000_000)
    prepared = _prepare_v15(journal, row, expected)
    taken = journal.takeover_prepared(row["run_id"], row["idx"], 30_000_000_001, "recovery-owner")
    assert taken["state"] == "aborting"
    assert journal.cleanup(row["run_id"], row["idx"], "recovery-owner", taken["fence"])
    successor = journal.finalize_with_successor(row["run_id"], row["idx"], "recovery-owner", taken["fence"])
    assert successor["generation"] == 1
    key = f'{row["run_id"]}\0{row["idx"]}\0{0}'
    primary = journal.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (key,)).fetchone()
    copy = journal.connection.execute("SELECT snapshot_json FROM prepared_snapshots WHERE key=?", (key,)).fetchone()
    assert primary is not None and copy is not None
    primary_row = json.loads(primary[0])
    copy_row = json.loads(copy[0])
    material_fields = ("final_relpath", "artifact_sha256", "artifact_size", "canonical_row_bytes", "canonical_row_sha256")
    assert all(primary_row[field] is not None for field in material_fields)
    assert all(primary_row[field] == copy_row[field] for field in material_fields)
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    reopened_primary = reopened.connection.execute("SELECT snapshot_json FROM journal_state WHERE key=?", (key,)).fetchone()
    assert reopened_primary is not None and all(json.loads(reopened_primary[0])[field] == copy_row[field] for field in material_fields)


@pytest.mark.parametrize(
    "form",
    ["plain", "quoted-conflict", "qualified-replace", "comment-case", "replace", "upsert", "insert-select", "cte", "executemany", "executescript"],
)
def test_v15p_green_spelling_independent_stage_target_admission(tmp_path, form):
    """Every supported ordinary stage target spelling fails before affinity."""
    row = _v15_row()
    expected = canonical_stage_row(row)
    db = tmp_path / f"v15p-green-spelling-{form}.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    prepared = _prepare_v15(journal, row, expected)
    key = f'{row["run_id"]}\0{row["idx"]}\0{0}'
    all_columns = ("key", *CANONICAL_COLUMNS, "cost_usd_bits", "latency_s_bits", "canonical_row_bytes", "canonical_row_sha256")
    values = [key, *[row[column] for column in CANONICAL_COLUMNS], "3ff0000000000000", "0000000000000000", expected, hashlib.sha256(expected).hexdigest()]
    placeholders = ", ".join("?" for _ in all_columns)
    quoted_columns = ", ".join('"' + column + '"' for column in all_columns)
    cte_select_columns = ", ".join('candidate."' + column + '"' for column in all_columns)
    plain = f"INSERT INTO stage_rows({', '.join(all_columns)}) VALUES ({placeholders})"
    quoted = f'INSERT OR ABORT INTO "stage_rows" ({quoted_columns}) VALUES ({placeholders})'
    qualified = f'INSERT OR REPLACE INTO main."stage_rows" ({quoted_columns}) VALUES ({placeholders})'
    comment_case = f' /* V15P */ iNsErT /* target */ OR FAIL INTO "stage_rows" ({quoted_columns}) VALUES ({placeholders})'
    replace = f'REPLACE INTO stage_rows({", ".join(all_columns)}) VALUES ({placeholders})'
    upsert = plain + ' ON CONFLICT(key) DO UPDATE SET "seat_id"=excluded."seat_id"'
    select_form = f'INSERT INTO stage_rows({", ".join(all_columns)}) SELECT {placeholders}'
    aliases = ", ".join(f'? AS "{column}"' for column in all_columns)
    cte = f'WITH candidate AS (SELECT {aliases}) INSERT INTO stage_rows({", ".join(all_columns)}) SELECT {cte_select_columns} FROM candidate'
    sql = {"plain": plain, "quoted-conflict": quoted, "qualified-replace": qualified, "comment-case": comment_case, "replace": replace, "upsert": upsert, "insert-select": select_form, "cte": cte}.get(form)
    supported = True
    rejected = False
    try:
        auth_key = "script-target" if form == "executescript" else key
        with journal._protocol.authorize("stage_insert", auth_key, None, hashlib.sha256(expected).hexdigest(), prepared_authority_digest=prepared["prepared_authority_digest"], lineage={"key": auth_key, "generation": "0", "prepared_authority_digest": prepared["prepared_authority_digest"]}):
            if form == "executemany":
                journal.connection.executemany(plain, [values])
            elif form == "executescript":
                journal.connection.executescript("INSERT INTO stage_rows(key) VALUES ('script-target');")
            elif form == "cte":
                journal.connection.execute(sql, values)
            else:
                journal.connection.execute(sql, values)
    except sqlite3.Error as exc:
        text = str(exc).lower()
        supported = not ("syntax" in text or "near" in text)
        rejected = supported
    assert supported, f"unsupported syntax was not counted as rejection evidence: {form}"
    assert rejected
    assert journal.connection.execute("SELECT count(*) FROM stage_rows").fetchone()[0] == 0
    assert journal._protocol._context is None
    assert _commit_v15(journal, row, expected) == 1


@pytest.mark.parametrize(
    ("case", "cost_usd", "latency_s"),
    [
        ("cost-bool", True, 0.0),
        ("cost-int", 1, 0.0),
        ("cost-text", "1.0", 0.0),
        ("cost-null", None, 0.0),
        ("cost-nan", math.nan, 0.0),
        ("cost-inf", math.inf, 0.0),
        ("cost-wrong", 2.0, 0.0),
        ("latency-bool", 1.0, False),
        ("latency-int", 1.0, 0),
        ("latency-text", 1.0, "0.0"),
        ("latency-null", 1.0, None),
        ("latency-nan", 1.0, math.nan),
        ("latency-inf", 1.0, -math.inf),
        ("latency-negative-zero", 1.0, -0.0),
        ("latency-wrong", 1.0, 0.5),
    ],
)
def test_v15p_green_raw_real_type_and_bit_matrix(tmp_path, case, cost_usd, latency_s):
    row = _v15_row()
    expected = canonical_stage_row(row)
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / f"v15p-green-real-{case}.sqlite3"))
    _claim_for(journal, row)
    prepared = _prepare_v15(journal, row, expected)
    key = f'{row["run_id"]}\0{row["idx"]}\0{0}'
    values = [row[column] for column in CANONICAL_COLUMNS]
    values[CANONICAL_COLUMNS.index("cost_usd")] = cost_usd
    values[CANONICAL_COLUMNS.index("latency_s")] = latency_s
    columns = ", ".join(f'"{column}"' for column in ("key", *CANONICAL_COLUMNS, "cost_usd_bits", "latency_s_bits", "canonical_row_bytes", "canonical_row_sha256"))
    placeholders = ", ".join("?" for _ in range(len(CANONICAL_COLUMNS) + 6))
    sql = f'INSERT OR ABORT INTO "stage_rows" ({columns}) VALUES ({placeholders})'
    with journal._protocol.authorize("stage_insert", key, None, hashlib.sha256(expected).hexdigest(), prepared_authority_digest=prepared["prepared_authority_digest"], lineage={"key": key, "generation": "0", "prepared_authority_digest": prepared["prepared_authority_digest"]}):
        with pytest.raises(sqlite3.DatabaseError):
            journal.connection.execute(sql, [key, *values, "3ff0000000000000", "0000000000000000", expected, hashlib.sha256(expected).hexdigest()])
    assert journal.connection.execute("SELECT count(*) FROM stage_rows").fetchone()[0] == 0
    assert journal._protocol._context is None
    assert _commit_v15(journal, row, expected) == 1


def _v15q_internal_stage_insert(row, expected, *, cost_usd=1.0, latency_s=0.0, bits=None):
    columns = ", ".join(f'"{column}"' for column in CANONICAL_COLUMNS)
    columns += ', "cost_usd_bits", "latency_s_bits"'
    placeholders = ", ".join("?" for _ in CANONICAL_COLUMNS + ("cost_usd_bits", "latency_s_bits"))
    sql = f"INSERT INTO stage_rows(key, {columns}, canonical_row_bytes, canonical_row_sha256) VALUES (?, {placeholders}, ?, ?)"
    values = [row[column] for column in CANONICAL_COLUMNS]
    values[CANONICAL_COLUMNS.index("cost_usd")] = cost_usd
    values[CANONICAL_COLUMNS.index("latency_s")] = latency_s
    params = [f'{row["run_id"]}\0{row["idx"]}\0{0}', *values, *(bits or ["3ff0000000000000", "0000000000000000"]), expected, hashlib.sha256(expected).hexdigest()]
    return sql, params


@pytest.mark.parametrize("cut", ("after_stage_insert", "during_readback", "before_prepared_to_committed_cas", "after_cas_before_commit", "before_commit"))
@pytest.mark.parametrize(
    ("case", "cost_usd", "latency_s", "bits"),
    [
        ("integer", 1, 0.0, None),
        ("text", "1.0", 0.0, None),
        ("negative-zero", 1.0, -0.0, None),
        ("wrong-finite", 2.0, 0.0, None),
        ("wrong-companion", 1.0, 0.0, ["0000000000000000", "0000000000000000"]),
    ],
)
def test_v15q_red_cached_identical_internal_sql_requires_fresh_admission(tmp_path, cut, case, cost_usd, latency_s, bits):
    """V15P RED: cached canonical SQL bypasses the raw admission record."""
    row = _v15_row()
    expected = canonical_stage_row(row)
    db = tmp_path / f"v15q-red-cache-{cut}-{case}.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    prepared = _prepare_v15(journal, row, expected)
    journal.failure_cut = cut
    with pytest.raises(RuntimeError, match="injected failure cut"):
        _commit_v15(journal, row, expected)
    journal.failure_cut = None
    assert journal.connection.execute("SELECT count(*) FROM stage_rows").fetchone()[0] == 0
    key = f'{row["run_id"]}\0{row["idx"]}\0{0}'
    sql, params = _v15q_internal_stage_insert(row, expected, cost_usd=cost_usd, latency_s=latency_s, bits=bits)
    with journal._protocol.authorize(
        "stage_insert", key, None, hashlib.sha256(expected).hexdigest(),
        prepared_authority_digest=prepared["prepared_authority_digest"],
        lineage={"key": key, "generation": "0", "prepared_authority_digest": prepared["prepared_authority_digest"]},
    ):
        with pytest.raises(sqlite3.IntegrityError, match="admission|stage|protocol"):
            journal.connection.execute(sql, params)
    assert journal.connection.execute("SELECT count(*) FROM stage_rows").fetchone()[0] == 0
    assert journal.connection._stage_admission is None
    assert journal._protocol._context is None


def test_v15q_red_prepared_finalize_missing_copy_is_checked_in_final_transaction(tmp_path):
    """V15P RED: finalization does not yet query the prepared-copy relation."""
    row = _v15_row()
    expected = canonical_stage_row(row)
    db = tmp_path / "v15q-red-missing-copy.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    _prepare_v15(journal, row, expected)
    taken = journal.takeover_prepared(row["run_id"], row["idx"], 30_000_000_001, "recovery-owner")
    assert journal.cleanup(row["run_id"], row["idx"], "recovery-owner", taken["fence"])
    journal.connection.close()
    fixture = sqlite3.connect(str(db), isolation_level=None, cached_statements=0)
    trigger_names = fixture.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='prepared_snapshots'"
    ).fetchall()
    for (trigger_name,) in trigger_names:
        fixture.execute(f'DROP TRIGGER "{trigger_name.replace(chr(34), chr(34) + chr(34))}"')
    fixture.execute("DELETE FROM prepared_snapshots")
    fixture.close()
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    before = reopened.connection.execute("SELECT key, snapshot_json FROM journal_state ORDER BY key").fetchall()
    with pytest.raises((sqlite3.IntegrityError, RuntimeError, ValueError), match="prepared|copy|parity"):
        reopened.finalize_with_successor(row["run_id"], row["idx"], "recovery-owner", taken["fence"])
    assert reopened.connection.execute("SELECT key, snapshot_json FROM journal_state ORDER BY key").fetchall() == before
    assert reopened.connection.execute("SELECT count(*) FROM prepared_snapshots").fetchone()[0] == 0
    assert reopened.connection.execute("SELECT count(*) FROM journal_state").fetchone()[0] == 1


def test_v15q_green_admission_event_is_one_use_and_cleared_on_cut_retry(tmp_path):
    row = _v15_row()
    expected = canonical_stage_row(row)
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / "v15q-events.sqlite3"))
    _claim_for(journal, row)
    _prepare_v15(journal, row, expected)
    journal.failure_cut = "after_stage_insert"
    with pytest.raises(RuntimeError, match="injected failure cut"):
        _commit_v15(journal, row, expected)
    journal.failure_cut = None
    assert _commit_v15(journal, row, expected) == 1
    assert len(journal.connection._stage_admission_events) == 2
    for event in journal.connection._stage_admission_events:
        assert event["used_count"] == 1
        assert event["cleared"] is True
        assert event["raw_types"][CANONICAL_COLUMNS.index("cost_usd")] == "float"
        assert event["raw_types"][CANONICAL_COLUMNS.index("latency_s")] == "float"
        assert event["real_bits"] == ("3ff0000000000000", "0000000000000000")
    assert journal.connection._stage_admission is None
    assert journal._protocol._context is None


@pytest.mark.parametrize("entrypoint", ("execute", "executemany", "executescript"))
def test_v15q_green_batch_entrypoints_fail_closed_without_fresh_admission(tmp_path, entrypoint):
    row = _v15_row()
    expected = canonical_stage_row(row)
    journal = Phase2Journal(root=tmp_path, database_path=str(tmp_path / f"v15q-entrypoint-{entrypoint}.sqlite3"))
    _claim_for(journal, row)
    prepared = _prepare_v15(journal, row, expected)
    key = f'{row["run_id"]}\0{row["idx"]}\0{0}'
    sql, params = _v15q_internal_stage_insert(row, expected)
    if entrypoint == "executescript":
        statement = "INSERT INTO stage_rows(key) VALUES ('batch-target')"
        auth_key = "batch-target"
    else:
        statement = sql
        auth_key = key
    with journal._protocol.authorize(
        "stage_insert", auth_key, None, hashlib.sha256(expected).hexdigest(),
        prepared_authority_digest=prepared["prepared_authority_digest"],
        lineage={"key": auth_key, "generation": "0", "prepared_authority_digest": prepared["prepared_authority_digest"]},
    ):
        with pytest.raises(sqlite3.DatabaseError, match="authorized|admission|stage|protocol"):
            if entrypoint == "execute":
                journal.connection.execute(statement, params)
            elif entrypoint == "executemany":
                journal.connection.executemany(statement, [params])
            else:
                journal.connection.executescript(statement)
    assert journal.connection.execute("SELECT count(*) FROM stage_rows").fetchone()[0] == 0
    assert journal.connection._stage_admission is None
    assert journal._protocol._context is None


@pytest.mark.parametrize("copy_case", ("missing", "mismatch", "duplicate"))
def test_v15q_green_prepared_copy_finalization_relation_matrix(tmp_path, copy_case):
    row = _v15_row()
    expected = canonical_stage_row(row)
    db = tmp_path / f"v15q-copy-{copy_case}.sqlite3"
    journal = Phase2Journal(root=tmp_path, database_path=str(db))
    _claim_for(journal, row)
    _prepare_v15(journal, row, expected)
    taken = journal.takeover_prepared(row["run_id"], row["idx"], 30_000_000_001, "recovery-owner")
    assert journal.cleanup(row["run_id"], row["idx"], "recovery-owner", taken["fence"])
    key = f'{row["run_id"]}\0{row["idx"]}\0{0}'
    copy_row = journal.connection.execute(
        "SELECT snapshot_json, snapshot_sha256 FROM prepared_snapshots WHERE key=?", (key,)
    ).fetchone()
    assert copy_row is not None
    journal.connection.close()
    fixture = sqlite3.connect(str(db), isolation_level=None, cached_statements=0)
    trigger_names = fixture.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='prepared_snapshots'"
    ).fetchall()
    for (trigger_name,) in trigger_names:
        fixture.execute(f'DROP TRIGGER "{trigger_name.replace(chr(34), chr(34) + chr(34))}"')
    if copy_case == "missing":
        fixture.execute("DELETE FROM prepared_snapshots")
    elif copy_case == "mismatch":
        forged = json.loads(copy_row[0])
        forged["owner_token"] = "wrong-original-owner"
        forged_json = json.dumps(forged, sort_keys=True, separators=(",", ":"))
        fixture.execute(
            "UPDATE prepared_snapshots SET snapshot_json=?, snapshot_sha256=? WHERE key=?",
            (forged_json, hashlib.sha256(forged_json.encode("utf-8")).hexdigest(), key),
        )
    else:
        fixture.execute("DROP TABLE prepared_snapshots")
        fixture.execute("CREATE TABLE prepared_snapshots (key TEXT, snapshot_json TEXT NOT NULL, snapshot_sha256 TEXT NOT NULL)")
        fixture.execute("INSERT INTO prepared_snapshots VALUES (?, ?, ?)", (key, copy_row[0], copy_row[1]))
        fixture.execute("INSERT INTO prepared_snapshots VALUES (?, ?, ?)", (key, copy_row[0], copy_row[1]))
    fixture.close()
    reopened = Phase2Journal(root=tmp_path, database_path=str(db))
    before = {
        "journal": reopened.connection.execute("SELECT key, snapshot_json FROM journal_state ORDER BY key").fetchall(),
        "copies": reopened.connection.execute("SELECT key, snapshot_json, snapshot_sha256 FROM prepared_snapshots ORDER BY rowid").fetchall(),
    }
    with pytest.raises((sqlite3.IntegrityError, RuntimeError, ValueError), match="prepared|copy|parity"):
        reopened.finalize_with_successor(row["run_id"], row["idx"], "recovery-owner", taken["fence"])
    assert reopened.connection.execute("SELECT key, snapshot_json FROM journal_state ORDER BY key").fetchall() == before["journal"]
    assert reopened.connection.execute("SELECT key, snapshot_json, snapshot_sha256 FROM prepared_snapshots ORDER BY rowid").fetchall() == before["copies"]
    production = Phase2Journal(root=tmp_path)
    assert any(index[2] for index in production.connection.execute("PRAGMA index_list('prepared_snapshots')").fetchall())


