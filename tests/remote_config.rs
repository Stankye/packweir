use packweir::{
    assemblyline_http::RemoteScanner,
    config::{CommandScanner, Config},
    model::Outcome,
    policy::{AgentEscalation, OutcomeCondition},
};
use serde_json::{Value, json};
use std::path::Path;

fn profile() -> Value {
    json!({"kind":"assemblyline","endpoint":"https://analysis.example/","server_version":"4.7.4.stable11",
        "user_env":"PACKWEIR_AL_USER","api_key_env":"PACKWEIR_AL_KEY","allow_upload":true,
        "classification":"TLP:CLEAR","retention_days":7,"profile_revision":"qualified-service-profile-v1",
        "policy":{"required_services":{"YARA":{"version":"4.8.0.stable0","tool_version":"rules-2026-11-11","configuration_key":"profile123"}}}})
}
fn configured(value: Value) -> Config {
    let mut config = Config::load(Path::new("packweir.toml")).unwrap();
    config.remote_scanners.insert(
        "binary_analysis".into(),
        serde_json::from_value(value).unwrap(),
    );
    config
}

#[test]
fn explicit_remote_profile_validates_without_resolving_credentials_or_contacting_services() {
    let config = configured(profile());
    config.validate().unwrap();
    let serialized = toml::to_string(&config).unwrap();
    let reparsed: Config = toml::from_str(&serialized).unwrap();
    reparsed.validate().unwrap();
    assert_eq!(config.fingerprint(), reparsed.fingerprint());
    let baseline = config.fingerprint();
    for (field, replacement) in [
        ("server_version", json!("4.7.4.stable12")),
        ("profile_revision", json!("profile-v2")),
        ("classification", json!("TLP:AMBER")),
        ("retention_days", json!(3)),
        ("endpoint", json!("https://other.example/")),
    ] {
        let mut changed = profile();
        changed[field] = replacement;
        let changed = configured(changed);
        changed.validate().unwrap();
        assert_ne!(
            baseline,
            changed.fingerprint(),
            "{field} changes delivery identity"
        );
    }
}

#[test]
fn unsafe_network_disclosure_authentication_and_scheduling_settings_are_rejected() {
    for (field, replacement) in [
        ("allow_upload", json!(false)),
        ("endpoint", json!("http://analysis.example/")),
        ("endpoint", json!("https://user:secret@analysis.example/")),
        (
            "endpoint",
            json!("https://analysis.example/redirect?target=x"),
        ),
        ("user_env", json!("BAD\nHEADER")),
        ("api_key_env", json!("PACKWEIR_AL_USER")),
        ("classification", json!("")),
        ("server_version", json!("5.0")),
        ("profile_revision", json!("")),
        ("retention_days", json!(0)),
        ("retention_days", json!(31)),
        ("request_timeout_seconds", json!(61)),
        ("analysis_timeout_seconds", json!(86401)),
        ("poll_interval_seconds", json!(301)),
        ("max_poll_failures", json!(0)),
        ("service_spec", json!({"UnselectedExternalService":{}})),
    ] {
        let mut changed = profile();
        changed[field] = replacement;
        assert!(
            configured(changed).validate().is_err(),
            "must reject {field}"
        );
    }
    let mut explicit_http = profile();
    explicit_http["endpoint"] = json!("http://127.0.0.1:9999/");
    explicit_http["allow_insecure_http"] = json!(true);
    explicit_http["allow_private_network"] = json!(true);
    configured(explicit_http).validate().unwrap();
}

#[test]
fn remote_checks_cannot_impersonate_verifiers_agents_builtins_or_local_checks() {
    let remote: RemoteScanner = serde_json::from_value(profile()).unwrap();
    for name in [
        "inventory",
        "archive_safety",
        "integrity",
        "package_identity",
        "agent",
        "provenance",
        "required_signature",
        "bad/name",
    ] {
        let mut config = Config::load(Path::new("packweir.toml")).unwrap();
        config.remote_scanners.insert(name.into(), remote.clone());
        assert!(config.validate().is_err(), "{name}");
    }
    let mut config = configured(profile());
    let command: CommandScanner = serde_json::from_value(
        json!({"program":std::env::current_exe().unwrap(),"version":"fixture"}),
    )
    .unwrap();
    config
        .scanners
        .insert("binary_analysis".into(), command.clone());
    assert!(config.validate().is_err());
    config.scanners.remove("binary_analysis");
    config.scanners.insert("agent".into(), command);
    config.policy.trust_agent = true;
    config.policy.agent_escalation = Some(AgentEscalation {
        when_any: vec![OutcomeCondition {
            check: "binary_analysis".into(),
            outcomes: vec![Outcome::Inconclusive, Outcome::Error],
        }],
    });
    config.validate().unwrap();
}

#[test]
fn binary_observation_profiles_require_an_exact_selected_producer_and_bound_policy() {
    let identity = packweir::model::sha256(b"controlled binary producer, no real tool execution");
    let mut value = profile();
    value["policy"]["required_services"]["YARA"]["tool_version"] =
        json!(format!("ghidra/12.2.identity/{identity}"));
    value["binary_analysis"] = json!({"service":"YARA","identity_sha256":identity,
        "required_capabilities":["decompile","pcode","decode_xor"],"candidate_kinds":["elf","pe"]});
    let baseline = configured(value.clone());
    baseline.validate().unwrap();
    let reparsed: Config = toml::from_str(&toml::to_string(&baseline).unwrap()).unwrap();
    reparsed.validate().unwrap();
    assert_eq!(baseline.fingerprint(), reparsed.fingerprint());
    for (pointer, replacement) in [
        ("/binary_analysis/service", json!("unselected-service")),
        ("/binary_analysis/identity_sha256", json!("0".repeat(64))),
        ("/binary_analysis/required_capabilities", json!([])),
        ("/binary_analysis/candidate_kinds", json!(["unknown-kind"])),
        ("/policy/required_services/YARA/tool_version", Value::Null),
        (
            "/policy/required_services/YARA/tool_version",
            json!("unbound engine revision"),
        ),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            configured(changed).validate().is_err(),
            "must reject {pointer}"
        );
    }
    for (field, replacement) in [
        ("candidate_kinds", json!(["elf"])),
        ("required_capabilities", json!(["decompile"])),
        (
            "informational_warnings",
            json!(["exact reviewed tool diagnostic"]),
        ),
    ] {
        let mut changed = value.clone();
        changed["binary_analysis"][field] = replacement;
        let changed = configured(changed);
        changed.validate().unwrap();
        assert_ne!(
            baseline.fingerprint(),
            changed.fingerprint(),
            "{field} changes delivery identity"
        );
    }
}
