# File-level license evidence

The `scancode` driver uses an operator-installed, SHA-256-pinned ScanCode Toolkit 32.5.0 executable. It collects detected file licenses, package declarations, copyrights, unknowns, and conflicts separately. Its SPDX-expression policy is an explicit operator allow/deny decision, not a legal-obligation or certification engine.

## Configure a required check

Add this to an existing configuration, replacing the executable path and pin:

```toml
[scanners.licenses]
program = "/opt/scancode/scancode"
program_sha256 = "<lowercase-sha256-of-executable>"
version = "32.5.0"
timeout_seconds = 300
[scanners.licenses.driver]
kind = "scancode"
[scanners.licenses.driver.policy]
allowed = ["MIT", "Apache-2.0", "BSD-3-Clause"]
denied = ["AGPL-3.0-only"]
allow_unknown = false
```

Require `licenses` through global, repository, or [scoped policy](policies.md). Configuring a scanner alone does not require it; the bootstrap policy remains inventory/archive safety only. The driver constructs its arguments/environment; custom values are rejected.

Executable hashing covers the launcher. Python modules, plugins, rule data, and native dependencies must also be provisioned in a controlled immutable installation/image. Pin and verify the complete distribution artifact during deployment. A pinned parser does not provide OS process isolation.

## Evidence and coverage

The driver validates the bounded inventory, then materializes archive leaves under unique flat directories preserving original basenames. Unsafe paths, links, unsupported compression, excessive nesting/expansion, or disagreement with inventory hashes are rejected. Package code is never executed.

Reports must identify the qualified tool/version, scan options, expected input directory, completed execution, file counts, and error-free coverage. Every expected leaf needs an unambiguous path, matching size/hash information, and license/copyright/package fields. Input SHA-256 hashes are checked after scanning. Partial, substituted, malformed, failed, timed-out, or oversized scans cannot approve a required check.

Findings preserve logical paths/digests, detected expressions, declarations, unknown/conflict flags, copyrights, raw detections, report digest, policy, and tool/data-version information. Declarations or imported SBOMs cannot substitute for file observations.

## Expression policy

Allow/deny entries are atomic SPDX requirements; expressions belong in observed findings:

- `AND` requires all selected terms to be acceptable.
- `OR` permits an acceptable alternative and records an acceptable branch alongside the original expression. This is a policy evaluation, not a legal election.
- `WITH` exceptions match as complete atomic requirements. Allowing `GPL-2.0-only WITH Classpath-exception-2.0` does not allow bare `GPL-2.0-only`.
- Custom `LicenseRef` terms require explicit entries. `allow_unknown` does not authorize arbitrary custom terms.
- Unknown files remain inconclusive by default. Explicit `allow_unknown=true` permits absent detections and records the uncertainty; it does not establish coverage.

Typical packages contain files without individual license headers. This driver does not infer cross-file license inheritance, determine linking/distribution obligations, establish a complete dependency graph, or generate reviewed notice/source bundles. Such packages can remain pending under strict policy. Complete license-compliance workflows remain planned work.
