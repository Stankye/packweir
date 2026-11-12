# Conditional agent investigation

Packweir 0.7.0 can require an operator-provided agent after selected ordinary check outcomes. All ordinary scanners finish first. The agent receives their findings in its evidence bundle and runs at most once in the same leased job. Packweir does not include a model provider, grant agent tools, or automatically authorize data sharing.

Upgrade gateways and workers together. Version 0.7.0 changes the engine fingerprint, so previous approvals require fresh analysis under the new configuration. Existing publication receipts remain historical records and do not bypass current delivery checks.

Configure the adapter through the existing [scanner protocol](scanners.md), then add a conditional policy:

```toml
[policy]
revision = "investigation-v1"
required = ["inventory", "archive_safety", "vulnerabilities"]
trust_agent = true

[policy.agent_escalation]
when_any = [
  { check = "characteristics", outcomes = ["fail", "inconclusive", "unsupported", "error"] }
]

[scanners.agent]
program = "/opt/packweir/adapters/investigation"
program_sha256 = "<lowercase-sha256-of-adapter>"
version = "<model-prompt-toolset-and-adapter-revision>"
timeout_seconds = 180
```

The example also needs a configured `characteristics` scanner and a qualified vulnerability driver. [Microsoft rule observations](ossgadget.md) are one possible investigation input. Required scanners that are absent or unsupported keep delivery pending.

Each condition names an ordinary configured scanner or `inventory`, `archive_safety`, or `package_identity`, with explicit outcomes. Conditions cannot reference `agent` or `skipped`. Duplicate, empty, unknown, or excessive conditions are rejected. Conditional policies require global `trust_agent=true` and a configured agent adapter.

Repository and package/namespace policy layers can also supply `agent_escalation.when_any`. Their conditions combine with the global rules; a narrower policy cannot remove a broader condition or requirement. For example:

```toml
[repositories.maven-private.policy]
revision = "private-investigation-v1"
required = []

[repositories.maven-private.policy.agent_escalation]
when_any = [{ check = "source_posture", outcomes = ["inconclusive", "unsupported", "error"] }]
```

## Invocation and delivery decisions

- Any matching current condition makes `agent` a required check for that delivery.
- Every condition needs a current input. A missing, expired, future-dated, skipped, or conflicting latest input leaves the condition unresolved and delivery pending. A newer expired input cannot expose an older passing observation.
- If no condition matches, the engine records `agent: skipped` with `condition_not_triggered`. This is an execution decision, not an agent pass.
- Once conditional scheduling is configured anywhere, scopes without a matching policy rule skip the agent with `scope_not_selected`. They do not inherit the old behavior of invoking every configured agent.
- An explicit effective `required = ["agent", ...]` still invokes and requires the agent regardless of whether conditions matched. Without any conditional configuration, a configured agent retains its prior always-run behavior, after ordinary scanners.
- Rejected archives never enter deeper scanners or the agent. Their agent record is skipped with `unsafe_archive`, and the hard failure still denies delivery.

Conditional investigation adds a requirement. It cannot replace a required vulnerability, signature, provenance, license, identity, or other check. An inconclusive required upstream check remains pending after an agent pass. Applicable integrity, archive-safety, and required-signature failures remain non-overridable. Explicit denial checks retain their own policy behavior.

## Attributable input and freshness

The agent's bundle extends the ordinary bundle with `subject`, `configuration`, `context_revision`, `findings`, and the computed `escalation` state. `findings` contains the actual preceding evidence records, including errors, unsupported coverage, details, references, and expiry. Inputs retain the 8 MiB bundle limit; excess data fails the invocation rather than being silently truncated.

Passing agent reports require nonempty `model`, `prompt_digest`, `toolset_digest`, `evidence_digest`, and `trace_digest` bindings. The declared evidence digest must equal the augmented bundle's digest. These remain attributable reports from a trusted operator adapter, rather than cryptographic proof that a model used particular reasoning or tools.

The worker reserves `details.packweir_inputs` for its own versioned map of supplied finding fingerprints. An adapter cannot choose or override this map. Fingerprints normalize engine timestamps to PostgreSQL's microsecond precision; database timestamp columns control applicability, even if stored report JSON advertises a later expiry. Conditional approval requires these bindings to match the latest supplied findings; changing a source result invalidates reuse of an older investigation even when its TTL has not elapsed. Investigations also expire no later than any supplied finding. A newer expired agent verdict cannot revive an older pass.

The job commits findings together through the existing context, configuration, artifact identity, and lease checks. A document change, replaced artifact, or lost lease cannot commit a usable stale investigation. Proxy delivery, hosted promotion/copy, and explanations use bounded policy inputs retaining current records and the latest invalid records/ties. More than 1,024 selected records or 32 MiB is an operational error and cannot approve delivery.

`packweir explain` and the administrative artifact API expose triggered, untriggered, and unresolved conditions, contributing checks, dynamic agent requirements, and skipped execution separately from passing evidence. Operational snapshots and Prometheus include a distinct `skipped` outcome.

Operator adapters remain responsible for provider credentials, prompt and model revision pins, tool allowlists, token/cost/step limits, trace retention, and disclosure policy. Package text, documents, and earlier tool output are untrusted input. Run execution and deep parsers behind appropriate process/network isolation; the command runner is not an OS sandbox. Test fixtures qualify the scheduling and protocol, not any model's security judgments.
