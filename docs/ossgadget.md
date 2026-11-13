# Microsoft rule observations

Packweir 0.7.0 adds a bounded driver for the Microsoft Application Inspector engine distributed with OSSGadget. It supports characteristic rules, OSSGadget backdoor rules, and an operator-pinned custom rule file. Findings remain attributable heuristic observations; they do not establish maliciousness, publisher trust, provenance, or complete binary/dependency coverage.

The qualified toolchain is `0.2.49-helper1`: official `Microsoft.CST.OSSGadget.CLI` 0.2.49, source revision `4063457b40211c25b41d56465d41783f2d42c5c1`, Application Inspector 1.9.55, and the repository's version-1 [.NET helper](../tools/ossgadget-helper/README.md). The helper runs the actual Microsoft API. It disables archive crawling and retains upstream file-completion states, which the unified OSSGadget CLI discards. The CLI's successful empty SARIF can hide incomplete work and is not accepted as proof of a completed scan.

## Provisioning and configuration

Provision and build the helper using its [installation instructions](../tools/ossgadget-helper/README.md). Installation needs Python, .NET SDK 10, and verified upstream inputs. Scanning requires a separately installed .NET 10 runtime and never downloads packages or rules. The upstream package SHA-256 is `0f139a32ecf35538d44cf0be7781be6194a395bc331d4084240f77f1c5b8aded`. Provisioning also pins the upstream backdoor rules individually because the official package omits them.

Pin the generated deployment manifest and the installed .NET host:

```toml
[scanners.characteristics]
program = "/usr/share/dotnet/dotnet"
program_sha256 = "<lowercase-sha256-of-dotnet-host>"
version = "0.2.49-helper1"
timeout_seconds = 180

[scanners.characteristics.driver]
kind = "ossgadget"
deployment_root = "/opt/packweir/ossgadget"
manifest = "deployment"
mode = "backdoor"
deny_rules = []

[scanners.characteristics.resources.deployment]
path = "/opt/packweir/ossgadget/deployment-manifest.json"
sha256 = "<lowercase-sha256-of-deployment-manifest>"
```

Modes are `characteristic`, `backdoor`, and `custom`. Custom mode additionally requires `custom_rules = "rules"` in the driver and a separate pinned resource:

```toml
[scanners.characteristics.resources.rules]
path = "/etc/packweir/rules/custom.json"
sha256 = "<lowercase-sha256-of-custom-rule-file>"
```

Other modes reject custom-rule configuration. The driver constructs its own arguments and environment, requires the qualified version, and cannot be mislabeled as an agent, provenance verifier, or required-signature verifier. The .NET host/framework remains operator-controlled; pinning the host executable does not pin the installed shared runtime. Deploy it immutably and isolate scanner processes.

Before launching .NET, Packweir verifies and stages every manifest-listed helper, loader configuration, dependency, and rule file into a private job directory. Bounds are 512 files, 8 MiB per file, and 64 MiB combined. Unsafe or aliased paths, links/reparse points, and missing or changed pins fail closed. This includes `.deps.json` and `.runtimeconfig.json`, which the loader reads before helper code. The helper separately verifies its embedded upstream file pins before loading Microsoft assemblies.

## Coverage and policy

Packweir materializes archive leaves using its bounded inspector and checks their hashes against the observed inventory. Qualified helper inputs are at most 256 leaves, 4 MiB per leaf, and 32 MiB combined. The helper snapshots explicit files, checks hashes, and disables its own archive extraction. It does not execute package code, lifecycle hooks, deobfuscators, or binaries.

The report must match the expected toolchain, mode, rule pin, exact input file set, sizes, hashes, counts, and upstream completion states. Packweir verifies staged input hashes after execution and independently prevents known binary or unsupported text coverage from receiving a complete pass. Native binaries, invalid text, skipped files, incomplete results, unsupported coverage, timeout, changed dependencies, malformed rules, and malformed reports cannot produce approval.

- A complete supported-text scan with no rule matches produces `pass` for that selected rule set.
- Findings ordinarily produce `inconclusive`, retaining file digests, rule IDs, locations, tags, severity, confidence, and the bounded report. They can [trigger agent investigation](agent-escalation.md).
- `deny_rules` explicitly selects rule IDs whose matches produce `fail`. Add the check to `required` or `deny_on_failure` to enforce that denial; selecting a heuristic rule is an operator policy choice.
- Partial/binary coverage remains `inconclusive`. A completed text scan does not imply complete package or native-binary analysis.
- Execution and invalid-input/report failures produce `error` evidence. Missing required coverage continues to hold delivery.

Use explicit policies for these observations. A required unsupported OSSGadget check keeps delivery pending; another scanner cannot silently waive that requirement. Optional [Ghidra binary observations and bounded transformations](binary-analysis.md) provide a separate analysis category and output provenance. Broader deobfuscation, additional Assemblyline services, remaining OSSGadget tools, and production malware classification need further work.

## Qualification

Run `python3 tests/ossgadget/run.py` on Linux, or use its documented Windows/WSL Docker option. The runner provisions pinned inputs, builds offline after provisioning, runs as an unprivileged container user with network disabled, and records the exact source, deployment, tool, and image identities. It requires both 14 actual helper cases and 11 actual Rust-driver cases; protocol fixtures alone cannot satisfy this gate. See [qualification instructions](../tests/ossgadget/README.md) and the CI `ossgadget` job.

The selected APIs and upstream behavior are documented in the [OSSGadget release](https://github.com/microsoft/OSSGadget/releases/tag/v0.2.49), [characteristic implementation](https://github.com/microsoft/OSSGadget/blob/4063457b40211c25b41d56465d41783f2d42c5c1/src/Shared.CLI/Tools/CharacteristicTool.cs), and [Application Inspector analysis code](https://github.com/microsoft/ApplicationInspector/blob/0b8c96ee0b5498c1738b834b3e6472053c4f01ea/AppInspector/Commands/AnalyzeCommand.cs).
