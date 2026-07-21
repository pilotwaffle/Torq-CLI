# T-02 Extraction Viability Audit — Gate 1 Builder Draft

Status: audit draft only; implementation and correction evidence is external and remains subject to fresh independent verification. This file records static and synthetic evidence for the pinned Console commit. It does not define a production interface, store, migration, entrypoint, or runtime change.

## Controlling basis

All conclusions are limited to Console commit `3ae196102a84aed24f7daa9dc3fed037522e1f20`, tree `be2448b3f6c9f281167302d10cd9b49ccd36034a`, the exact 27 Git blobs below, the hash-verified V10/V12 packet, and controlled synthetic evidence under the external Luna evidence root. The Console worktree, untracked Console state, providers, network, credentials, `.env*`, `.torq/**`, wrappers, logs, Console pytest, and product runtime are outside this audit.

## Closed 27-object export

The closed manifest is exactly 27 unique lowercase SHA-1 blob/path pairs; every object is `100644 blob`, with no traversal, absolute path, duplicate, case-fold collision, symlink, reparse point, or operator content:

```text
b09716304fa6792ff67e29d7eb784f6d2d21d9f1 LICENSE
f2fceb022ee76bba7438822f4669085b9cd5d4fd torq_mmh/requirements.txt
e29c455d2c06c46e1f202c62427c4d66fe36a966 torq_mmh/config/pipelines.yaml
3dd54ce141491b0347b87429d718ad035e8cd780 torq_mmh/config/seats.yaml
4ffaa2682e31d6af2a6f3bca1d7691ff36646c64 torq_mmh/prompts/track_a_draft.md
2bf6e8e843ec2e10a9b08d8ba1f4e6d02d15b099 torq_mmh/prompts/track_a_audit.md
9addead77546c947a0942bb947ab48cca52ab36f torq_mmh/prompts/track_a_revise.md
c5acb3cab0702dd1729d00ee0975f292714362db torq_mmh/prompts/track_a_judge.md
e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 torq_mmh/router/__init__.py
965928c9c3a4044066a8fcb89803897fb82ee1db torq_mmh/router/config.py
d2c73db0e92075e52ca7c83c7bbea4c57c87d004 torq_mmh/router/adapters.py
9072242e13637e1bfd82dba423d12c6a89b8d61f torq_mmh/router/redaction.py
aac9a5526211416cc9583a32af991906f9fdfff1 torq_mmh/router/telemetry.py
a88b5b08109a1d66eff3f1cec0574396af5ffd5d torq_mmh/router/engine.py
d74b2ca7d58191a9d79af65ba23508258d956be2 torq_console/conductor/compile.py
a5e844203cf344c599891da4b2b1b14db66838e4 torq_console/conductor/strategies.py
e92aa9cf63e696d240638f3135426640181abf73 torq_console/conductor/policy.py
0221422e7fb06d77ff78bf39622d37cec6b21711 torq_console/conductor/persist_preflight.py
448557938017714fd8d4a7a81ae5332466c64cc0 torq_console/conductor/receipt_emitter.py
c221c7be23d719d47258458be55040cd741307b0 torq_console/conductor/execute_writer.py
8c139e59ee89742b616526075b3c2563bdea1899 torq_console/conductor/manifest_writer.py
e75f00f49ca12bbc4c85e4a49d80fae2079114ac torq_console/conductor/observe_writer.py
6f36b020d9b3874ee4135a29942f7ad7492be9b5 torq_console/conductor/policy_writer.py
28fda2b83c7461018afba161a6bc6c7f8debcf0b torq_console/conductor/validation_writer.py
efd0104d93db799e035cd8752c69ffacbd477846 torq_console/conductor/runner/__main__.py
30755e23790e0eb590edf457fefef40b4be61069 torq_console/conductor/runner/invoker.py
d5a095167c573262147263af6fd2e52aa8815da8 torq_console/conductor/runner/paths.py
```

Pinned anchors: pipelines `722e72e55dfc85778348d44df0a74f5e8c45b13232fc975de0ad4c650826543b`; seats `d842298f0255225f65425802716249475242683dd32f0b55178e65e0cdb53ea1`; seats concatenated with pipelines `be381d4c92df735012601050f88a051d5a24e60894359b97097a5b6086b2e46f`; adapters `c03caa84ccaae0a3a4780ccad89251b382957eb7afcfb532ebc3ec69ed796567`. The pinned slow branch invokes `time.sleep(2)` at line 166.

## V12 synthetic fixture and canonical row

The fixture is extracted only from the unique `text` fence in the hash-verified V10 report: compact ASCII length 2496, compact SHA-256 `1a8ba5487ce9a819626fe8f0aa30d9ec8ecb69515d50624002796f39f036e70c`, strict RFC 4648 decode length 1872, decoded SHA-256 `018622b2037db1b267d89e7bf1c141126454cdd91ad0c2a397877b1c4b2dda11`, strict UTF-8, no BOM/CR, final LF. Its ordered fake seats are `kimi, flash, v4pro, glm, qwen_r`; the correct key is `allow_provider_fallback: false`; the V11 typo and V11 fixture are prohibited.

The V15 canonical stage record is exactly `columns` plus 21 aligned typed `values`, serialized with `ensure_ascii=True`, `allow_nan=False`, sorted keys, and compact separators. INTEGER domains are exact `int`, signed 64-bit, and nonnegative except fallback in `{0,1}`; REAL domains are finite exact `float`, bit-round-trippable, and reject negative zero; TEXT domains are exact strings. V12 REAL controls remain `cost_usd=1.0` (`3ff0000000000000`) and `latency_s=+0.0` (`0000000000000000`). The verified V15 attachment is 1441 bytes with SHA-256 `df11e7980c25e3eb09ae0f28bd5eb475fb54bf0f4ff316ec17be644213789488`; trimming only its terminal LF yields a 1440-byte strict Base64 literal with SHA-256 `fa35124d352b915f650236cb877a207a90b8fa43822349135b6faf5ff020bc74`, decoding to the 1079-byte canonical oracle with SHA-256 `1e76c5de38228e4d3c20009e0302f14ffd6613b0614ddba994d99b922ea17cfb`. Earlier 627-byte and malformed V13/V14 diagnostics are superseded and prohibited.

## Present findings and future-only reference model

Current compatibility functions remain `new_run`, `update_run`, `get_run`, `save_stage`, `get_stages`, and `load_stage_artifact`. Current evidence is audit-only: MMH orchestration, telemetry, receipts, shared resume, and conductor execution require `REBUILD`; adapters, redaction, and policy require `WRAP`; conductor compiler/strategy is `REUSE`. Current interruption, resume, tamper, missing-artifact, checkpoint, and historical SQLite behavior remain defects/evidence, not corrected production behavior.

The future-only Phase 2 packages are exactly: execution controller; migration-managed run/stage store; hardened shared resume controller; hash-chained evidence/receipt store. The reference journal models claimed/prepared/committed/aborting/aborted state shapes, explicit NULL checks, immutable identity, prepared canonical bytes, committed immutability, safe contained paths, original-component reparse hard stops before any path resolution, boot identity and leases, same-generation fencing, stale-owner rejection, owned cleanup, full-snapshot expired-claimed CAS, aborting takeover with `fence + 1`, atomic predecessor abort plus exactly one successor, rollback recovery, and the complete crash matrix. Ordinary row-DML enforcement is modeled within the audit schema; schema-owner DDL and hostile filesystem races remain outside scope. It is not production crash-consistency proof.

## Boundaries, tests, and residuals

Only the four Gate 1 files are in scope. The implementation uses one parent plus one worker, sequential phases, 90-second worker, 30-second handshake, 128 MiB retained evidence, and 32 MiB artifact/checkpoint limits. The seven exact nodes are the required manifest, pinned static, sentinel, graph, canonical, future-journal, and authenticated interruption/resume nodes. All checks use absolute `-I -S -B`, external roots, disabled plugins, empty pytest config/options, and no `src/torq_cli` import.

Accepted residuals: fake execution does not prove real providers; Console pytest remains unexecuted with allowlist `[]`; the future journal is not production proof; historical SQLite compatibility is unavailable; T-05/T-07 retain licensing/SBOM authority; conductor conclusions are static. This draft does not approve implementation and does not create a product contract.
