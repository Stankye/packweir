This helper runs Microsoft's actual Application Inspector API distributed inside
`Microsoft.CST.OSSGadget.CLI` 0.2.49. Its engine is Application Inspector 1.9.55.
It supplies the default characteristic rules, the upstream OSSGadget backdoor
rules, or a caller-pinned custom rule file. It does not call the legacy OSSGadget
CLI: that interface discards file-completion metadata and can return successful
empty SARIF after an analysis failure.

The helper sets `DisableCrawlArchives=true`, snapshots only explicitly requested
files, and returns upstream per-file status. It never invokes a package manager,
downloader, shell, package lifecycle hook, decompiler, or build script. Findings
remain rule observations; a completed scan with no matches does not establish
that an artifact is safe. Package-wide coverage must be supplied by the caller.

Provision and build
-------------------

Provisioning requires Python's standard library and network access **at install
time**. `provision.lock.json` pins the official NuGet package and each backdoor
rule to upstream commit `4063457b40211c25b41d56465d41783f2d42c5c1`.
The rules are acquired separately because this official nupkg omits its
`Resources/BackdoorRules` directory. Existing verified downloads can be supplied
using `--package` and `--rules-directory`; this path requires no network.

```sh
python tools/ossgadget-helper/provision.py target/ossgadget-helper/upstream
dotnet publish tools/ossgadget-helper/Packweir.OssGadget.Helper.csproj \
  -c Release -p:OssgadgetRoot=/absolute/path/target/ossgadget-helper/upstream \
  --configfile tools/ossgadget-helper/NuGet.Config \
  -o target/ossgadget-helper/publish
python tools/ossgadget-helper/deployment_manifest.py target/ossgadget-helper/publish
```

Building needs .NET SDK 10. `NuGet.Config` clears all sources: after provisioning,
restore/build uses SDK framework references and direct local DLL references,
without acquiring packages. The published helper requires a .NET 10 runtime.
The complete output is about 61 MB. The Microsoft MIT license accompanies the
NuGet package; Microsoft's repository license is available at
https://github.com/microsoft/OSSGadget/blob/4063457b40211c25b41d56465d41783f2d42c5c1/LICENSE.txt.

`deployment-manifest.json` has this schema:

```json
{"protocol_version":1,"entrypoint":"packweir-ossgadget-helper.dll","files":{"relative/path":"lowercase-sha256"}}
```

It includes the helper DLL, apphost, `.deps.json`, `.runtimeconfig.json`, and every
upstream dependency and rule, excluding the manifest itself. The writer rejects
links and enforces 512 files, 8 MiB per file, and 64 MiB combined. An operator pins
the manifest's own SHA-256. Before launching .NET, the caller verifies and stages
every listed file into its private job directory. This protects files consumed
by the .NET loader before helper code runs. The .NET host/framework is separately
operator-controlled and the host executable should be pinned by the caller.

The helper also embeds all 171 upstream file digests in its own assembly and
verifies the exact `upstream/` directory before resolving Microsoft assemblies.
An additional or changed file causes an error. These embedded upstream pins do
not replace the caller's verification of the entire deployment before launch.

Invocation and request
----------------------

Use a private staged deployment and provide exactly one JSON request on stdin:

```sh
dotnet exec --runtimeconfig STAGE/packweir-ossgadget-helper.runtimeconfig.json \
  --depsfile STAGE/packweir-ossgadget-helper.deps.json \
  STAGE/packweir-ossgadget-helper.dll
```

```json
{
  "protocol_version": 1,
  "mode": "backdoor",
  "root": "/absolute/engine-owned-input-directory",
  "files": [{"path":"package/module.py","sha256":"lowercase-sha256"}]
}
```

Modes are `characteristic`, `backdoor`, and `custom`. Custom mode additionally
requires `rules_path` (an absolute path to a file beneath `root`) and
`rules_sha256`. The helper copies and verifies that file before loading it. Other
modes reject custom-rule fields. Default and backdoor rules are pinned by the
deployment. Input paths use relative forward-slash paths and must name regular
files; traversal, duplicate paths, and symlinks are rejected.

Limits are 256 KiB of request JSON, 256 files, 4 MiB per file, 32 MiB combined
input, 1 MiB custom rules, 2,000 returned findings, and 1 MiB output. The caller
must impose its existing hard process timeout and output limit, and run the
helper in its isolated scanner environment with network denied. The upstream
regex engine prefers nonbacktracking patterns; upstream rule modifiers may
permit backtracking, so an external hard process deadline remains necessary.

Archives, binary data, invalid UTF-8, NUL-containing text, and text exceeding
Application Inspector's control-character threshold are reported as skipped.
ZIPs disguised with a source extension are also rejected. A supported text leaf
from a bounded caller-owned package extractor can be scanned normally; raw
package archives are never recursively inspected by this helper. Backdoor mode
uses all pinned upstream backdoor rules on the explicit text list, including
documentation if requested, rather than reproducing the CLI's exclusions.

Response and completion
-----------------------

Stdout contains one JSON object. Exit 0 means a complete or partial report was
produced; exit 2 means an error. No warnings or progress output are written on
successful operation. `--version` prints the helper and Microsoft tool versions.

The response includes `protocol_version`, `helper_version`, `engine`,
`package_sha256`, `source_revision`, `mode`, `status`, `complete`,
`archive_crawling:false`, `rules_sha256`, `engine_result_code`,
`engine_result_name`, `files`, `findings`, `totals`, and `diagnostics`.

Each file contains its request `path`, verified `sha256`, `size`, normalized
`status`, `upstream_status`, and optional `reason`. Normalized statuses are
`analyzed`, `affected`, `skipped`, `error`, or `not_analyzed`. A finding contains
`path`, `rule_id`, `description`, `tags`, `severity`, `confidence`,
`severity_value`, `confidence_value`, line/column coordinates, and `language`.
Source snippets are omitted to keep evidence compact.

`complete:true` requires exactly one upstream file record for every requested
file, all states `Analyzed` or `Affected`, no skipped or errored input, no upstream
timeout, and upstream result `Success` or `NoMatches`. An empty result can
therefore attest a completed rule scan of the **explicit text files**. It does
not attest package completeness or the absence of unknown malicious behavior.
Skipped files produce `status:"partial"` and `complete:false`. Invalid rules,
missing/mismatched completion records, digest mismatches, unsafe requests,
unexpected deployment bytes, or output limits produce errors.

Real-engine qualification
-------------------------

```sh
python tools/ossgadget-helper/qualify.py \
  --inputs target/ossgadget-helper/fixtures \
  --scan-root /absolute/path/target/ossgadget-helper/fixtures \
  --command dotnet target/ossgadget-helper/publish/packweir-ossgadget-helper.dll
```

`--command` consumes the remaining arguments. It can launch an isolated container;
`--scan-root` then names the fixture directory as visible inside that container.
The qualification uses real upstream assemblies, not scanner-response fixtures.
It covers benign no-match completion, actual backdoor signatures, actual default
characteristic rules, custom matches/no-matches, binary and partial coverage,
ZIP and disguised-ZIP exclusion, malformed rules, digest mismatch, traversal, and
duplicate inputs, and output-limit enforcement. The qualification passed all 14 cases with networking
disabled in `mcr.microsoft.com/dotnet/sdk:10.0`.
