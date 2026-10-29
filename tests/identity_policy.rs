use chrono::{Duration, Utc};
use packweir::{
    config::Config,
    explain,
    identity::{self, DeliveryScope},
    model::{Decision, Evidence, Outcome},
    policy::{PolicyRequirements, PolicyScope},
};

fn config() -> Config {
    Config::load(std::path::Path::new("packweir.toml")).unwrap()
}
fn observe(repo: &str, url: &str, route: &str) -> Option<identity::PackageIdentity> {
    identity::observe(&config().repositories[repo], &url.parse().unwrap(), route)
}
fn scope() -> DeliveryScope {
    DeliveryScope {
        repository: "npm".into(),
        origin: "https://registry.npmjs.org/@acme/widget/-/widget-1.0.0.tgz".into(),
        filename: "widget-1.0.0.tgz".into(),
        package: observe(
            "npm",
            "https://registry.npmjs.org/@acme/widget/-/widget-1.0.0.tgz",
            "",
        ),
    }
}
fn requirements(check: &str) -> PolicyRequirements {
    PolicyRequirements {
        revision: "test-v1".into(),
        required: vec![check.into()],
        deny_on_failure: vec![],
    }
}

#[test]
fn native_registry_paths_produce_canonical_coordinates_and_purls() {
    for (repo, url, route, name, version, purl) in [
        (
            "npm",
            "https://registry.npmjs.org/@acme/widget/-/widget-1.2.3.tgz",
            "",
            "@acme/widget",
            "1.2.3",
            "pkg:npm/%40acme/widget@1.2.3",
        ),
        (
            "npm",
            "https://registry.npmjs.org/widget/-/widget-1.2.3.tgz",
            "",
            "widget",
            "1.2.3",
            "pkg:npm/widget@1.2.3",
        ),
        (
            "pypi",
            "https://files.pythonhosted.org/pkg/My_Package-1.0+local-py3-none-any.whl",
            "",
            "my-package",
            "1.0+local",
            "pkg:pypi/my-package@1.0%2Blocal",
        ),
        (
            "pypi",
            "https://files.pythonhosted.org/pkg/my-package-1.0.tar.gz",
            "",
            "my-package",
            "1.0",
            "pkg:pypi/my-package@1.0",
        ),
        (
            "cargo",
            "https://static.crates.io/any",
            "_cargo/fixture-crate/1.0.0/download",
            "fixture-crate",
            "1.0.0",
            "pkg:cargo/fixture-crate@1.0.0",
        ),
        (
            "maven",
            "https://repo.maven.apache.org/maven2/dev/acme/widget/1.0/widget-1.0-sources.jar",
            "",
            "dev.acme:widget",
            "1.0",
            "pkg:maven/dev.acme/widget@1.0",
        ),
        (
            "nuget",
            "https://api.nuget.org/v3-flatcontainer/My.Package/1.0.0/my.package.1.0.0.nupkg",
            "",
            "my.package",
            "1.0.0",
            "pkg:nuget/my.package@1.0.0",
        ),
    ] {
        let identity = observe(repo, url, route).unwrap_or_else(|| panic!("unidentified {url}"));
        assert_eq!(
            (
                identity.name.as_str(),
                identity.version.as_str(),
                identity.purl.as_str()
            ),
            (name, version, purl)
        );
        assert_eq!(identity.basis, "registry_path_observed");
    }
    for url in [
        "https://registry.npmjs.org/file.tgz",
        "https://registry.npmjs.org/@acme/widget/-/nested/widget-1.0.tgz",
        "https://registry.npmjs.org/@acme%2fother/widget/-/widget-1.0.tgz",
    ] {
        assert!(observe("npm", url, "").is_none());
    }
    assert!(observe("nuget", "https://api.nuget.org/flat/a/1.0/b.1.0.nupkg", "").is_none());
    assert!(observe("cargo", "https://static.crates.io/file.crate", "").is_none());
}

#[test]
fn scoped_requirements_are_additive_exact_and_fail_closed_for_unknown_coordinates() {
    let mut settings = config();
    settings.repositories.get_mut("npm").unwrap().policy = Some(requirements("vulnerabilities"));
    settings.policy_scopes.push(PolicyScope {
        name: "acme-signing".into(),
        repository: "npm".into(),
        namespace: Some("@acme".into()),
        package: None,
        policy: requirements("required_signature"),
    });
    settings.validate().unwrap();
    let context = scope();
    let effective = settings.effective_policy(&context).unwrap();
    for check in [
        "inventory",
        "archive_safety",
        "vulnerabilities",
        "required_signature",
        "package_identity",
    ] {
        assert!(effective.policy.required.contains(&check.into()));
    }
    assert_eq!(effective.layers.len(), 3);
    let mut other = context.clone();
    other.package = observe(
        "npm",
        "https://registry.npmjs.org/@acme-evil/widget/-/widget-1.0.0.tgz",
        "",
    );
    assert!(
        !settings
            .effective_policy(&other)
            .unwrap()
            .policy
            .required
            .contains(&"required_signature".into())
    );
    other.package = None;
    let unidentified = settings.effective_policy(&other).unwrap();
    assert!(
        unidentified
            .policy
            .required
            .contains(&"package_identity".into())
    );
    assert!(matches!(
        unidentified.policy.evaluate("d", "c", &[], Utc::now()),
        Decision::Pending(_)
    ));
    assert_ne!(
        settings.delivery_fingerprint(&context).unwrap(),
        settings.delivery_fingerprint(&other).unwrap()
    );
    let mut other_repository = context.clone();
    settings
        .repositories
        .insert("npm-copy".into(), settings.repositories["npm"].clone());
    other_repository.repository = "npm-copy".into();
    assert_ne!(
        settings.delivery_fingerprint(&context).unwrap(),
        settings.delivery_fingerprint(&other_repository).unwrap()
    );
}

#[test]
fn namespace_boundaries_and_invalid_selectors_cannot_weaken_policy() {
    let cargo_rule = PolicyScope {
        name: "cargo".into(),
        repository: "cargo".into(),
        namespace: None,
        package: Some("foo-bar".into()),
        policy: requirements("review"),
    };
    let cargo_alias = observe(
        "cargo",
        "https://static.crates.io/any",
        "_cargo/foo_bar/1.0/download",
    )
    .unwrap();
    assert!(cargo_rule.matches(&cargo_alias));
    let mut settings = config();
    let rule = PolicyScope {
        name: "maven".into(),
        repository: "maven".into(),
        namespace: Some("dev.acme".into()),
        package: None,
        policy: requirements("provenance"),
    };
    settings.policy_scopes.push(rule.clone());
    settings.validate().unwrap();
    for (group, expected) in [
        ("dev.acme", true),
        ("dev.acme.sub", true),
        ("dev.acmeevil", false),
    ] {
        let package = observe(
            "maven",
            &format!(
                "https://repo.maven.apache.org/maven2/{}/widget/1.0/widget-1.0.jar",
                group.replace('.', "/")
            ),
            "",
        )
        .unwrap();
        assert_eq!(rule.matches(&package), expected);
    }
    settings.policy_scopes[0].repository = "pypi".into();
    assert!(settings.validate().is_err());
    settings.policy_scopes[0].namespace = None;
    settings.policy_scopes[0].package = Some("My_Package".into());
    assert!(settings.validate().is_err());
    settings.policy_scopes[0].package = Some("my-package".into());
    settings.validate().unwrap();
    settings
        .policy_scopes
        .push(settings.policy_scopes[0].clone());
    assert!(settings.validate().is_err());
    assert!(identity::canonical_name(packweir::model::Ecosystem::Npm, "@invalid").is_none());
}

#[test]
fn discovery_coordinates_override_tarball_names_and_unbound_paths_do_not_satisfy_scopes() {
    let mut settings = config();
    settings.policy_scopes.push(PolicyScope {
        name: "strict".into(),
        repository: "npm".into(),
        namespace: Some("@acme".into()),
        package: None,
        policy: requirements("signature"),
    });
    let mut delivery = scope();
    assert!(!settings.identity_sufficient(&delivery).unwrap());
    let repo = &settings.repositories["npm"];
    let mut metadata = serde_json::json!({"name":"@acme/widget","versions":{"1.0":{"name":"@acme/widget","version":"1.0","dist":{"tarball":"https://registry.npmjs.org/@other/widget/-/widget-1.0.tgz"}}}});
    packweir::registry::rewrite_json(&mut metadata, repo, "npm", &settings.public_url).unwrap();
    let claims = identity::json_claims(
        repo,
        &"https://registry.npmjs.org/@acme/widget".parse().unwrap(),
        &metadata,
    )
    .unwrap();
    assert_eq!(claims.len(), 1);
    assert!(claims[0].origin.contains("@other"));
    delivery.origin = claims[0].origin.clone();
    delivery.filename = "widget-1.0.tgz".into();
    delivery.package = claims[0].package.clone();
    assert!(settings.identity_sufficient(&delivery).unwrap());
    assert_eq!(delivery.package.as_ref().unwrap().name, "@acme/widget");
    assert!(
        settings
            .effective_policy(&delivery)
            .unwrap()
            .policy
            .required
            .contains(&"signature".into())
    );
    assert!(
        identity::json_claims(
            repo,
            &"https://registry.npmjs.org/@different/widget"
                .parse()
                .unwrap(),
            &metadata
        )
        .is_err()
    );
}

#[test]
fn pypi_discovery_bindings_require_the_requested_project_in_html_and_json() {
    let settings = config();
    let repo = &settings.repositories["pypi"];
    let source = "https://pypi.org/simple/protected-package/"
        .parse()
        .unwrap();
    let html = "<a href='https://files.pythonhosted.org/protected_package-1.0-py3-none-any.whl#sha256=abc'>wheel</a>";
    let claims = identity::html_claims(repo, &source, html).unwrap();
    assert_eq!(
        claims[0].package.as_ref().unwrap().name,
        "protected-package"
    );
    assert_eq!(
        claims[0].package.as_ref().unwrap().basis,
        "registry_metadata_observed"
    );
    let other =
        "<a href='https://files.pythonhosted.org/ordinary-1.0-py3-none-any.whl'>wrong project</a>";
    assert!(
        identity::html_claims(repo, &source, other).unwrap()[0]
            .package
            .is_none()
    );
    let mut metadata = serde_json::json!({"files":[{"filename":"protected_package-1.0-py3-none-any.whl","url":"https://files.pythonhosted.org/opaque-download","hashes":{"sha256":"abc"}}]});
    packweir::registry::rewrite_json(&mut metadata, repo, "pypi", &settings.public_url).unwrap();
    let claims = identity::json_claims(repo, &source, &metadata).unwrap();
    assert_eq!(
        claims[0].package.as_ref().unwrap().name,
        "protected-package"
    );
    assert!(claims[0].origin.ends_with("#sha256=abc"));
}

#[test]
fn explanations_preserve_freshness_hard_failures_and_required_outcomes() {
    let settings = config();
    let context = scope();
    let effective = settings.effective_policy(&context).unwrap();
    let now = Utc::now();
    let configuration = settings.delivery_fingerprint(&context).unwrap();
    let evidence = |check: &str, outcome, created, expires| Evidence {
        subject: "digest".into(),
        check: check.into(),
        tool_version: "fixture".into(),
        configuration: configuration.clone(),
        outcome,
        created_at: created,
        expires_at: expires,
        details: serde_json::json!({}),
        references: vec![],
    };
    let old = evidence(
        "inventory",
        Outcome::Pass,
        now - Duration::hours(2),
        now - Duration::hours(1),
    );
    let failed = evidence(
        "archive_safety",
        Outcome::Fail,
        now - Duration::minutes(2),
        now + Duration::hours(1),
    );
    let newer = evidence(
        "archive_safety",
        Outcome::Pass,
        now - Duration::minutes(1),
        now + Duration::hours(1),
    );
    let report = explain::scope(
        "digest",
        context.clone(),
        configuration.clone(),
        effective.clone(),
        &[old, failed, newer],
        now,
    );
    assert!(matches!(report.decision, Decision::Denied(_)));
    assert_eq!(
        report
            .checks
            .iter()
            .find(|c| c.check == "inventory")
            .unwrap()
            .status,
        "expired"
    );
    assert_eq!(
        report
            .checks
            .iter()
            .find(|c| c.check == "archive_safety")
            .unwrap()
            .status,
        "fail"
    );
    let missing = explain::scope("digest", context, configuration, effective, &[], now);
    assert!(
        missing
            .checks
            .iter()
            .all(|c| c.status == "missing" && !c.next_action.is_empty())
    );
    assert!(matches!(
        explain::aggregate([Decision::Approved, missing.decision.clone()].into_iter()),
        Decision::Pending(_)
    ));
    let mut dirty = missing;
    dirty.scope.origin = "https://example.test/\u{1b}[2J".into();
    assert!(!explain::render("digest", &[dirty]).contains('\u{1b}'));
}
