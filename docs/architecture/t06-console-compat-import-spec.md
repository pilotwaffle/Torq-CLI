# T-06C Console V5 compatibility import

`torq config import-v5-console --config ABSOLUTE_PATH` is a bounded, offline, read-only
source adapter. It reads only the explicitly supplied sanitized YAML path, never discovers a
default, opens a source metadata path, contacts a provider, resolves credentials, persists
state, or changes runtime routing.

The command rejects `--output` before registry, oracle, or config I/O. It authenticates the
packaged registry and normalized V5 oracle, reads the config once through the existing protected
bounded final-handle reader, preflights YAML events and nodes, constructs through `SafeLoader`,
scans secrets, validates the closed raw schema, compares all six raw records with the normalized
oracle, and validates the immutable registry target projection.

## Closed raw grammar

The root keys are exactly `version`, `created`, `supersedes`, `agents`, `state_machine`,
`rejection_routing`, `cost_guardrails`, and `success_criteria`. The YAML stream is strict UTF-8,
BOM-free, at most 65,536 bytes, at most 1,024 meaningful events, depth eight inclusive, and one
non-empty mapping-root document. Anchors, aliases, tags, merge keys, complex/non-string keys,
NFC-equivalent duplicate keys, and wrong-path scalar tags are parser-policy failures. The raw
role literals and exact role field bindings are pinned in the Gate-1 T06C design packet.

`reads` and `writes` accept only the eight exact ASCII artifact paths. They are validated as
untouched source metadata and are never opened, normalized as filesystem paths, logged, emitted,
or used for routing. Costs, notes, state-machine values, rejection routing, and success criteria
are similarly validated and discarded.

## Secret handling

Mapping keys are normalized by NFC, casefold, and hyphen-to-underscore. The closed denied-key
catalog and the ordered value detector reject private-key markers, authorization values, API-token
prefixes, header/cookie assignments, structurally valid JWTs, and malformed or signed HTTP(S)
query candidates. The HTTP(S) detector is local and deterministic; it does not import a network
URL client or perform decoding beyond one strict percent-decoding pass. Findings contain no
captured key, value, match class, source path, or source text.

## Output and registry envelope

Success is compact sorted JSON with a final LF and empty stderr. Its snapshot is source-path-free,
its `runtime_effective` value is `false`, and its canonical target is the immutable 1,029-byte
`torq-v5-repo-compat` projection with SHA-256
`63ffadbe88e6b04ac732d5a282e27e0af1a2bbd80f89412ad1a4364e01a3650e`.

Handled failures emit `data: {}`, compact final-LF JSON, empty stderr, and source-free snapshots.
Registry findings retain the existing `/registry` paths and precedence: invalid findings exit 2;
an eligibility-only `binding_ineligible` result exits 3; and a mixed result remains invalid/2.
The T06A and T06B importers and their registry/snapshot contracts remain unchanged.
