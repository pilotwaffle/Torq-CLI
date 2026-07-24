# TORQ CLI Foundation Slice

TORQ CLI is a standalone Python 3.11+ command-line validator for immutable governance profiles and non-secret configuration.

```text
torq profile validate --config PATH
torq status --offline --config PATH [--require-effective]
torq config import-v5-normalized --config ABSOLUTE_PATH
```

The Foundation Slice reads only the explicitly supplied configuration and immutable packaged resources. It has no provider or agent invocation, credential resolution, environment discovery, network, subprocess, Git or `.git` access, persistence, telemetry, sandbox runtime, receipt handling, apply path, or repository mutation. A `credential_ref` is syntax-only and is never resolved or emitted.

The T-06A import command reads only the authenticated normalized V5 fixture shape and emits a fixed registry-authoritative stdout projection. It does not read raw Console configuration, write files, resolve credentials, access providers, or claim T-06/Phase 1 completion.

`status --offline` is intentionally `offline_unattested`; `--require-effective` exits 4. Local quality commands are defined in `docs/architecture/foundation-task-status.md`. Passing local commands does not prove the four external CI jobs, branch protection, provider effectiveness, or release readiness.
