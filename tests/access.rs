use axum::http::{HeaderMap, HeaderValue, header};
use base64::Engine;
use chrono::{Duration, Utc};
use packweir::{
    access::{
        AccessConfig, AccessControl, Action, Grant, MavenOwnership, NugetOwnership,
        ServicePrincipal,
    },
    config::{Config, RepositoryKind},
    identity,
    model::Ecosystem,
    network, registry,
};
use std::collections::BTreeMap;

type ConfigMutation = Box<dyn Fn(&mut Config)>;

fn configuration() -> Config {
    let mut config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
    let mut hosted = config.repositories["maven"].clone();
    hosted.kind = RepositoryKind::Hosted;
    hosted.upstream = None;
    hosted.download_origins.clear();
    hosted.token_env = None;
    hosted.cargo_download_template = None;
    hosted.cache_max_age_seconds = None;
    hosted.retain = true;
    config.repositories.insert("releases".into(), hosted);
    config
}

fn grant(repository: &str, actions: Vec<Action>, namespace: Option<&str>) -> Grant {
    Grant {
        repository: repository.into(),
        actions,
        namespace: namespace.map(str::to_owned),
    }
}

fn principal(grants: Vec<Grant>) -> ServicePrincipal {
    ServicePrincipal {
        token_env: "PACKWEIR_TEST_SERVICE_TOKEN".into(),
        expires_at: None,
        grants,
    }
}

fn headers(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, value.parse().unwrap());
    headers
}

fn control(config: &Config, token: &str) -> AccessControl {
    AccessControl::from_tokens(
        config,
        &"a".repeat(32),
        &"r".repeat(32),
        &BTreeMap::from([("builder".into(), token.into())]),
    )
    .unwrap()
}

#[test]
fn legacy_configuration_and_credentials_remain_read_only() {
    let config = Config::load(std::path::Path::new("packweir.toml")).unwrap();
    assert!(
        config
            .repositories
            .values()
            .all(|repo| repo.kind == RepositoryKind::Proxy && repo.proxy_upstream().is_ok())
    );
    let access =
        AccessControl::from_tokens(&config, &"a".repeat(32), &"r".repeat(32), &BTreeMap::new())
            .unwrap();
    for value in [
        "r".repeat(32),
        format!("Bearer {}", "r".repeat(32)),
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("ignored:{}", "r".repeat(32)))
        ),
    ] {
        let identity = access.authenticate(&headers(&value)).unwrap();
        assert_eq!(identity.id, "legacy-read");
        assert!(identity.allows("maven", Action::Read, None));
        assert!(identity.allows("npm", Action::Read, None));
        assert!(!identity.allows("maven", Action::Write, None));
        assert!(!identity.allows("maven", Action::Promote, None));
    }
    for value in [
        "a".repeat(32),
        "wrong".into(),
        "Basic malformed".into(),
        "Bearer ".into(),
    ] {
        assert!(access.authenticate(&headers(&value)).is_none());
    }
    assert!(access.authenticate(&HeaderMap::new()).is_none());
    let mut multiple = headers(&"r".repeat(32));
    multiple.append(header::AUTHORIZATION, HeaderValue::from_static("another"));
    assert!(access.authenticate(&multiple).is_none());
}

#[test]
fn service_actions_and_maven_namespaces_do_not_inherit_permissions() {
    let mut config = configuration();
    config.access.principals.insert(
        "builder".into(),
        principal(vec![
            grant("maven", vec![Action::Read], Some("com.acme")),
            grant("releases", vec![Action::Write], Some("com.acme")),
        ]),
    );
    config.validate().unwrap();
    let access = control(&config, &"s".repeat(32));
    for raw in [
        "s".repeat(32),
        format!("Bearer {}", "s".repeat(32)),
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("untrusted:{}", "s".repeat(32)))
        ),
    ] {
        let identity = access.authenticate(&headers(&raw)).unwrap();
        assert_eq!(identity.id, "builder");
        assert!(identity.allows("maven", Action::Read, Some("com.acme")));
        assert!(identity.allows("maven", Action::Read, Some("com.acme.tools")));
        assert!(!identity.allows("maven", Action::Read, Some("com.acmeevil")));
        assert!(!identity.allows("maven", Action::Read, None));
        assert!(!identity.allows("npm", Action::Read, Some("com.acme")));
        assert!(identity.allows("releases", Action::Write, Some("com.acme")));
        assert!(!identity.allows("releases", Action::Read, Some("com.acme")));
        assert!(!identity.allows("releases", Action::Promote, Some("com.acme")));
        for path in [
            "com/acme/demo/1.0/demo-1.0.jar",
            "com/acme/demo/1.0/demo-1.0.pom.sha256",
            "com/acme/demo/maven-metadata.xml",
        ] {
            assert!(
                identity.allows_path("maven", &config.repositories["maven"], Action::Read, path),
                "{path}"
            );
        }
        for path in [
            "com/acmeevil/demo/1.0/demo-1.0.jar",
            "com/acme/1.0/acme-1.0.jar",
            "com/acme/demo/garbage",
            "",
            "../com/acme/demo/1.0/demo-1.0.jar",
        ] {
            assert!(
                !identity.allows_path("maven", &config.repositories["maven"], Action::Read, path),
                "{path}"
            );
        }
        assert!(!identity.allows_path(
            "npm",
            &config.repositories["npm"],
            Action::Read,
            "com/acme/demo/1.0/demo-1.0.jar"
        ));
    }
}

#[test]
fn expired_and_duplicate_credentials_fail_closed_without_exposing_secrets() {
    let mut config = configuration();
    let mut service = principal(vec![grant("releases", vec![Action::Promote], None)]);
    service.expires_at = Some(Utc::now() - Duration::seconds(1));
    config.access.principals.insert("builder".into(), service);
    config.validate().unwrap();
    assert!(
        control(&config, &"s".repeat(32))
            .authenticate(&headers(&"s".repeat(32)))
            .is_none()
    );
    config
        .access
        .principals
        .get_mut("builder")
        .unwrap()
        .expires_at = Some(Utc::now() + Duration::hours(1));
    let identity = control(&config, &"s".repeat(32))
        .authenticate(&headers(&"s".repeat(32)))
        .unwrap();
    assert!(identity.allows("releases", Action::Promote, None));
    assert!(!identity.allows("releases", Action::Write, None));
    assert!(!identity.allows("releases", Action::Read, None));
    for secret in [
        "a".repeat(32),
        "r".repeat(32),
        "sensitive-short".into(),
        " ".repeat(32),
    ] {
        let result = AccessControl::from_tokens(
            &config,
            &"a".repeat(32),
            &"r".repeat(32),
            &BTreeMap::from([("builder".into(), secret.clone())]),
        );
        assert!(result.is_err());
        assert!(!result.err().unwrap().to_string().contains(&secret));
    }
    let second = ServicePrincipal {
        token_env: "PACKWEIR_TEST_SECOND_TOKEN".into(),
        ..config.access.principals["builder"].clone()
    };
    config.access.principals.insert("other".into(), second);
    let tokens = BTreeMap::from([
        ("builder".into(), "s".repeat(32)),
        ("other".into(), "s".repeat(32)),
    ]);
    assert!(
        AccessControl::from_tokens(&config, &"a".repeat(32), &"r".repeat(32), &tokens).is_err()
    );
    assert!(
        AccessControl::from_tokens(&config, &"a".repeat(32), &"r".repeat(32), &BTreeMap::new())
            .is_err()
    );
}

#[test]
fn global_legacy_read_can_be_disabled_without_granting_admin_package_access() {
    let mut config = configuration();
    config.access.legacy_read_enabled = false;
    config.access.principals.insert(
        "builder".into(),
        principal(vec![grant(
            "releases",
            vec![Action::Read],
            Some("com.acme"),
        )]),
    );
    let access = control(&config, &"s".repeat(32));
    assert!(access.authenticate(&headers(&"r".repeat(32))).is_none());
    assert!(
        access
            .authenticate(&headers(&format!("Bearer {}", "a".repeat(32))))
            .is_none()
    );
    let identity = access.authenticate(&headers(&"s".repeat(32))).unwrap();
    assert!(identity.allows("releases", Action::Read, Some("com.acme")));
    assert!(!identity.allows("maven", Action::Read, Some("com.acme")));
    config.access.principals.clear();
    config.validate().unwrap();
    let locked =
        AccessControl::from_tokens(&config, &"a".repeat(32), &"r".repeat(32), &BTreeMap::new())
            .unwrap();
    assert!(locked.authenticate(&headers(&"r".repeat(32))).is_none());
}

#[test]
fn service_configuration_rejects_invalid_grants_and_secret_references() {
    let base = configuration();
    let mut valid = base.clone();
    valid.access.principals.insert(
        "builder".into(),
        principal(vec![grant(
            "releases",
            vec![Action::Read, Action::Write, Action::Promote],
            Some("com.acme"),
        )]),
    );
    valid.validate().unwrap();
    let mutations: Vec<ConfigMutation> = vec![
        Box::new(|c| {
            c.access.principals.get_mut("builder").unwrap().token_env = "TOKEN-NAME".into()
        }),
        Box::new(|c| {
            c.access
                .principals
                .get_mut("builder")
                .unwrap()
                .grants
                .clear()
        }),
        Box::new(|c| {
            c.access.principals.get_mut("builder").unwrap().grants[0]
                .actions
                .clear()
        }),
        Box::new(|c| {
            c.access.principals.get_mut("builder").unwrap().grants[0].actions =
                vec![Action::Read, Action::Read]
        }),
        Box::new(|c| {
            c.access.principals.get_mut("builder").unwrap().grants[0].repository = "missing".into()
        }),
        Box::new(|c| {
            c.access.principals.get_mut("builder").unwrap().grants[0].repository = "maven".into()
        }),
        Box::new(|c| {
            c.access.principals.get_mut("builder").unwrap().grants[0].namespace =
                Some("com..acme".into())
        }),
        Box::new(|c| {
            let grant = &mut c.access.principals.get_mut("builder").unwrap().grants[0];
            grant.repository = "npm".into();
            grant.actions = vec![Action::Read];
        }),
        Box::new(|c| {
            c.access.principals.get_mut("builder").unwrap().expires_at =
                Some("1969-01-01T00:00:00Z".parse().unwrap())
        }),
        Box::new(|c| {
            let service = c.access.principals["builder"].clone();
            c.access.principals.insert("admin".into(), service);
        }),
        Box::new(|c| {
            let service = c.access.principals["builder"].clone();
            c.access.principals.insert("other".into(), service);
        }),
    ];
    for mutate in mutations {
        let mut config = valid.clone();
        mutate(&mut config);
        assert!(config.validate().is_err());
    }
    assert!(
        toml::from_str::<AccessConfig>(
            "[principals.builder]\ntoken_env='TOKEN'\nexpires_at='not-a-time'\ngrants=[]"
        )
        .is_err()
    );
    assert!(
        toml::from_str::<AccessConfig>(
            "[[maven_owners]]\nnamespace='com.acme'\nrepository='releases'\nunknown=true"
        )
        .is_err()
    );
}

#[test]
fn hosted_repository_settings_are_explicit_and_cannot_fetch_upstream() {
    let base = configuration();
    base.validate().unwrap();
    let repo = &base.repositories["releases"];
    assert!(repo.proxy_upstream().is_err());
    assert!(!network::allowed(
        repo,
        &"https://repo.maven.apache.org/maven2/com/acme/a/1.0/a-1.0.jar"
            .parse()
            .unwrap()
    ));
    let mutations: Vec<ConfigMutation> = vec![
        Box::new(|c| {
            c.repositories.get_mut("releases").unwrap().upstream =
                Some("https://example.test/".parse().unwrap())
        }),
        Box::new(|c| {
            c.repositories.get_mut("releases").unwrap().download_origins =
                vec!["https://example.test/".parse().unwrap()]
        }),
        Box::new(|c| c.repositories.get_mut("releases").unwrap().token_env = Some("TOKEN".into())),
        Box::new(|c| {
            c.repositories
                .get_mut("releases")
                .unwrap()
                .cargo_download_template = Some("unused".into())
        }),
        Box::new(|c| {
            c.repositories
                .get_mut("releases")
                .unwrap()
                .cache_max_age_seconds = Some(1)
        }),
        Box::new(|c| c.repositories.get_mut("releases").unwrap().retain = false),
        Box::new(|c| c.repositories.get_mut("releases").unwrap().ecosystem = Ecosystem::Npm),
        Box::new(|c| c.repositories.get_mut("maven").unwrap().upstream = None),
    ];
    for mutate in mutations {
        let mut config = base.clone();
        mutate(&mut config);
        assert!(config.validate().is_err());
    }
    let mut package = identity::from_coordinates(Ecosystem::Maven, "com.acme:demo", "1.0").unwrap();
    package.basis = "hosted_coordinates_declared".into();
    assert!(package.is_canonical());
    package.name = "other:demo".into();
    assert!(!package.is_canonical());
}

#[test]
fn maven_source_reservations_cover_metadata_unknown_paths_and_wrapped_urls() {
    let mut config = configuration();
    config.access.maven_owners.push(MavenOwnership {
        additional_repositories: vec![],
        namespace: "com.acme".into(),
        repository: "releases".into(),
    });
    config.validate().unwrap();
    let access = &config.access;
    assert!(access.owner_allowed("releases", "com.acme"));
    assert!(access.owner_allowed("releases", "com.acme.tools"));
    assert!(!access.owner_allowed("maven", "com.acme"));
    assert!(!access.owner_allowed("maven", "com.acme.tools"));
    assert!(access.owner_allowed("maven", "com.acmeevil"));
    assert!(!access.owner_allowed("maven", "com..acme"));
    for path in [
        "com/acme/demo/1.0/demo-1.0.jar",
        "com/acme/demo/1.0/demo-1.0.jar.asc.sha256",
        "com/acme/demo/maven-metadata.xml",
        "com/acme/demo/1.0-SNAPSHOT/maven-metadata.xml",
        "com/acme/unknown-format",
        "com/acme",
        "com.acme/demo/maven-metadata.xml",
        "com/acme.tools/demo/1.0-SNAPSHOT/maven-metadata.xml",
        "com.acme/demo/1.0/demo-1.0.jar",
    ] {
        assert!(
            !access.maven_path_allowed("maven", &config.repositories["maven"], path),
            "{path}"
        );
        assert!(
            access.maven_path_allowed("releases", &config.repositories["releases"], path),
            "{path}"
        );
    }
    assert!(access.maven_path_allowed(
        "maven",
        &config.repositories["maven"],
        "com/acmeevil/demo/1.0/demo-1.0.jar"
    ));
    for path in [
        "com/%61cme/demo/1.0/demo-1.0.jar",
        "com/acme/../other",
        "com\\acme\\demo",
        "com//acme/demo",
        "/com/acme/demo",
        "com/acme/demo?override=x",
        "com/./acme/demo",
    ] {
        assert!(
            !access.maven_path_allowed("maven", &config.repositories["maven"], path),
            "{path}"
        );
    }
    let repo = &config.repositories["maven"];
    for suffix in [
        "com/acme/demo/1.0/demo-1.0.jar",
        "com/acme/demo/maven-metadata.xml",
        "com.acme/demo/maven-metadata.xml",
    ] {
        let target = repo.proxy_upstream().unwrap().join(suffix).unwrap();
        let wrapped = registry::wrap(&config.public_url, "maven", &target);
        let route = url::Url::parse(&wrapped)
            .unwrap()
            .path()
            .strip_prefix("/r/maven/")
            .unwrap()
            .to_owned();
        assert!(!access.maven_path_allowed("maven", repo, &route));
    }
    let directory = repo.proxy_upstream().unwrap().clone();
    let wrapped = registry::wrap(&config.public_url, "maven", &directory);
    let mut route = url::Url::parse(&wrapped)
        .unwrap()
        .path()
        .strip_prefix("/r/maven/")
        .unwrap()
        .to_owned();
    route.push_str("com/acme/demo/1.0/demo-1.0.jar");
    assert!(!access.maven_path_allowed("maven", repo, &route));
    for target in [
        "https://cdn.example.test/unbound.bin",
        "https://user:pass@repo.maven.apache.org/maven2/com/acme/demo/1.0/demo-1.0.jar",
    ] {
        let wrapped = registry::wrap(&config.public_url, "maven", &target.parse().unwrap());
        let route = url::Url::parse(&wrapped)
            .unwrap()
            .path()
            .strip_prefix("/r/maven/")
            .unwrap()
            .to_owned();
        assert!(!access.maven_path_allowed("maven", repo, &route));
    }
    // Source reservations are Maven-specific; other registry support is not claimed.
    assert!(access.maven_path_allowed("npm", &config.repositories["npm"], "@acme/demo"));
}

#[test]
fn ownership_conflicts_are_rejected_without_prefix_overmatching() {
    let mut config = configuration();
    config.access.maven_owners.push(MavenOwnership {
        additional_repositories: vec![],
        namespace: "com.acme".into(),
        repository: "releases".into(),
    });
    for namespace in ["com.acme", "com", "com.acme.tools"] {
        let mut conflicting = config.clone();
        conflicting.access.maven_owners.push(MavenOwnership {
            additional_repositories: vec![],
            namespace: namespace.into(),
            repository: "maven".into(),
        });
        assert!(conflicting.validate().is_err());
    }
    config.access.maven_owners.push(MavenOwnership {
        additional_repositories: vec![],
        namespace: "com.acmeevil".into(),
        repository: "maven".into(),
    });
    config.validate().unwrap();
    config.access.maven_owners.push(MavenOwnership {
        additional_repositories: vec![],
        namespace: "com.acme.tools".into(),
        repository: "releases".into(),
    });
    config.validate().unwrap();
    for (namespace, repository) in [
        ("com..bad", "releases"),
        ("com.other", "missing"),
        ("com.other", "npm"),
    ] {
        let mut invalid = config.clone();
        invalid.access.maven_owners.push(MavenOwnership {
            additional_repositories: vec![],
            namespace: namespace.into(),
            repository: repository.into(),
        });
        assert!(invalid.validate().is_err());
    }
}

#[tokio::test]
async fn redirects_cannot_bypass_global_ownership_or_service_namespace_permissions() {
    use axum::{Router, extract::OriginalUri, http::StatusCode, response::IntoResponse};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let forbidden_hits = Arc::new(AtomicUsize::new(0));
    let observed = forbidden_hits.clone();
    let app = Router::new().fallback(move |OriginalUri(uri): OriginalUri| {
        let observed = observed.clone();
        async move {
            match uri.path() {
                "/repo/start" => (
                    StatusCode::FOUND,
                    [(header::LOCATION, "/repo/com/acme/demo/1.0/demo-1.0.jar")],
                )
                    .into_response(),
                "/repo/com/allowed/demo/1.0/demo-1.0.jar" => (
                    StatusCode::FOUND,
                    [(header::LOCATION, "/repo/com/other/demo/1.0/demo-1.0.jar")],
                )
                    .into_response(),
                "/repo/com/acme/demo/1.0/demo-1.0.jar"
                | "/repo/com/other/demo/1.0/demo-1.0.jar" => {
                    observed.fetch_add(1, Ordering::SeqCst);
                    "forbidden bytes".into_response()
                }
                _ => "allowed bytes".into_response(),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base: url::Url = format!("http://{}/repo/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut config = configuration();
    let repo = config.repositories.get_mut("maven").unwrap();
    repo.upstream = Some(base.clone());
    repo.download_origins.clear();
    config.allow_private_upstreams = true;
    config.access.maven_owners.push(MavenOwnership {
        additional_repositories: vec![],
        namespace: "com.acme".into(),
        repository: "releases".into(),
    });
    config.validate().unwrap();
    let repo = &config.repositories["maven"];
    let guard = network::FetchGuard {
        access: &config.access,
        repository: "maven",
        principal: None,
    };
    assert!(
        network::fetch_guarded(repo, &base.join("start").unwrap(), None, 1024, true, &guard)
            .await
            .is_err()
    );
    assert_eq!(forbidden_hits.load(Ordering::SeqCst), 0);
    let allowed = network::fetch_guarded(
        repo,
        &base.join("unowned").unwrap(),
        None,
        1024,
        true,
        &guard,
    )
    .await
    .unwrap();
    assert_eq!(allowed.bytes.as_ref(), b"allowed bytes");

    config.access.maven_owners.clear();
    config.access.principals.insert(
        "builder".into(),
        principal(vec![grant(
            "maven",
            vec![Action::Read],
            Some("com.allowed"),
        )]),
    );
    let identity = control(&config, &"s".repeat(32))
        .authenticate(&headers(&"s".repeat(32)))
        .unwrap();
    let guard = network::FetchGuard {
        access: &config.access,
        repository: "maven",
        principal: Some(&identity),
    };
    assert!(
        network::fetch_guarded(
            &config.repositories["maven"],
            &base.join("com/allowed/demo/1.0/demo-1.0.jar").unwrap(),
            None,
            1024,
            true,
            &guard
        )
        .await
        .is_err()
    );
    assert_eq!(forbidden_hits.load(Ordering::SeqCst), 0);
    server.abort();
}

#[test]
fn explicit_authoritative_sets_admit_only_members_and_require_identical_overlap() {
    let mut config = configuration();
    config
        .repositories
        .insert("production".into(), config.repositories["releases"].clone());
    config.access.maven_owners = vec![MavenOwnership {
        namespace: "com.acme".into(),
        repository: "releases".into(),
        additional_repositories: vec!["production".into()],
    }];
    config.validate().unwrap();
    for name in ["releases", "production"] {
        assert!(config.access.owner_allowed(name, "com.acme.tools"));
        for path in [
            "com/acme/demo/1.0/demo-1.0.jar",
            "com.acme/demo/maven-metadata.xml",
            "com/acme/demo/unknown",
        ] {
            assert!(
                config
                    .access
                    .maven_path_allowed(name, &config.repositories[name], path)
            );
        }
    }
    assert!(!config.access.owner_allowed("maven", "com.acme"));
    assert!(!config.access.maven_path_allowed(
        "maven",
        &config.repositories["maven"],
        "com/acme/demo/1.0/demo-1.0.jar"
    ));
    let target = config.repositories["maven"]
        .proxy_upstream()
        .unwrap()
        .join("com/acme/demo/1.0/demo-1.0.jar")
        .unwrap();
    assert!(
        !config
            .access
            .maven_url_allowed("maven", &config.repositories["maven"], &target)
    );
    let wrapped = url::Url::parse(&registry::wrap(&config.public_url, "maven", &target)).unwrap();
    assert!(!config.access.maven_path_allowed(
        "maven",
        &config.repositories["maven"],
        wrapped.path().strip_prefix("/r/maven/").unwrap()
    ));
    config.access.maven_owners.push(MavenOwnership {
        namespace: "com.acme.tools".into(),
        repository: "production".into(),
        additional_repositories: vec!["releases".into()],
    });
    config.validate().unwrap(); // Primary spelling/order cannot alter the authoritative set.
    config.access.maven_owners[1]
        .additional_repositories
        .clear();
    assert!(config.validate().is_err());
    config.access.maven_owners.truncate(1);
    for additional in [
        vec!["releases"],
        vec!["production", "production"],
        vec!["missing"],
        vec!["maven"],
        vec!["npm"],
    ] {
        let mut invalid = config.clone();
        invalid.access.maven_owners[0].additional_repositories =
            additional.into_iter().map(str::to_owned).collect();
        assert!(invalid.validate().is_err());
    }
    let mut excessive = config.clone();
    excessive.access.maven_owners[0]
        .additional_repositories
        .clear();
    for index in 0..17 {
        let name = format!("hosted-{index}");
        excessive
            .repositories
            .insert(name.clone(), config.repositories["releases"].clone());
        excessive.access.maven_owners[0]
            .additional_repositories
            .push(name);
    }
    assert!(excessive.validate().is_err());
    // Legacy TOML requires no new field and still denotes one authoritative repository.
    let old: AccessConfig =
        toml::from_str("[[maven_owners]]\nnamespace='com.acme'\nrepository='releases'").unwrap();
    assert!(old.maven_owners[0].additional_repositories.is_empty());
}

#[test]
fn copying_requires_source_read_and_destination_write_without_promotion_inheritance() {
    let mut base = configuration();
    base.repositories
        .insert("production".into(), base.repositories["releases"].clone());
    let cases = [
        (
            vec![
                grant("releases", vec![Action::Read], Some("com.acme")),
                grant("production", vec![Action::Write], Some("com.acme")),
            ],
            true,
        ),
        (
            vec![grant("releases", vec![Action::Read], Some("com.acme"))],
            false,
        ),
        (
            vec![grant("production", vec![Action::Write], Some("com.acme"))],
            false,
        ),
        (
            vec![
                grant("releases", vec![Action::Promote], None),
                grant("production", vec![Action::Promote], None),
            ],
            false,
        ),
        (
            vec![
                grant("releases", vec![Action::Read], Some("com.other")),
                grant("production", vec![Action::Write], Some("com.acme")),
            ],
            false,
        ),
    ];
    for (grants, expected) in cases {
        let mut config = base.clone();
        config
            .access
            .principals
            .insert("builder".into(), principal(grants));
        let identity = control(&config, &"s".repeat(32))
            .authenticate(&headers(&"s".repeat(32)))
            .unwrap();
        assert_eq!(
            identity.allows_copy("releases", "production", "com.acme"),
            expected
        );
        assert_eq!(
            identity.allows_copy("releases", "production", "com.acme.tools"),
            expected
        );
        assert!(!identity.allows_copy("releases", "production", "com.acmeevil"));
        assert!(!identity.allows_copy("production", "releases", "com.acme"));
        assert!(!identity.allows_copy("releases", "releases", "com.acme"));
        assert!(!identity.allows_copy("releases", "production", "com..acme"));
        if expected {
            assert!(!identity.allows("production", Action::Promote, Some("com.acme")));
        }
    }
    let access =
        AccessControl::from_tokens(&base, &"a".repeat(32), &"r".repeat(32), &BTreeMap::new())
            .unwrap();
    assert!(
        !access
            .authenticate(&headers(&"r".repeat(32)))
            .unwrap()
            .allows_copy("releases", "production", "com.acme")
    );
}

#[test]
fn explicit_proxy_primary_does_not_enable_queries_or_unknown_download_sources() {
    let mut config = configuration();
    config.access.maven_owners.push(MavenOwnership {
        namespace: "com.acme".into(),
        repository: "maven".into(),
        additional_repositories: vec!["releases".into()],
    });
    config.validate().unwrap();
    let repo = &config.repositories["maven"];
    let mut target = repo
        .proxy_upstream()
        .unwrap()
        .join("com/acme/demo/1.0/demo-1.0.jar")
        .unwrap();
    assert!(config.access.maven_url_allowed("maven", repo, &target));
    target.set_query(Some("source=production"));
    assert!(!config.access.maven_url_allowed("maven", repo, &target));
    assert!(
        !config.access.maven_url_allowed(
            "maven",
            repo,
            &"https://unknown.example.test/com/acme/demo.jar"
                .parse()
                .unwrap()
        )
    );
    assert!(!config.access.owner_allowed("maven-other", "com.acme"));
    let public = serde_json::to_string(&config).unwrap();
    assert!(!public.contains(&"s".repeat(32)));
    let original = config.fingerprint();
    config.access.maven_owners[0]
        .additional_repositories
        .clear();
    assert_ne!(original, config.fingerprint());
}

fn nuget_configuration() -> Config {
    let mut config = configuration();
    let mut hosted = config.repositories["releases"].clone();
    hosted.ecosystem = Ecosystem::Nuget;
    config
        .repositories
        .insert("nuget-local".into(), hosted.clone());
    config.repositories.insert("nuget-prod".into(), hosted);
    config.access.nuget_owners.push(NugetOwnership {
        prefix: "packweir.private".into(),
        repository: "nuget-local".into(),
        additional_repositories: vec!["nuget-prod".into()],
    });
    config
}

#[test]
fn nuget_id_reservations_are_explicit_and_do_not_use_maven_namespaces() {
    let mut config = nuget_configuration();
    config.validate().unwrap();
    let package = packweir::nuget::Coordinate::new("Packweir.Private.Fixture", "01.0.0.0+build")
        .unwrap()
        .package();
    assert!(package.namespace.is_none());
    for repository in ["nuget-local", "nuget-prod"] {
        assert!(config.access.package_owner_allowed(repository, &package));
        assert!(
            config
                .access
                .owner_allowed_for(repository, Ecosystem::Nuget, "packweir.private")
        );
    }
    assert!(!config.access.package_owner_allowed("nuget", &package));
    assert!(
        config
            .access
            .owner_allowed_for("nuget", Ecosystem::Nuget, "packweir.privateevil")
    );
    assert!(
        !config
            .access
            .owner_allowed_for("nuget-local", Ecosystem::Nuget, "Packweir.Private")
    );
    assert!(config.access.owner_allowed("maven", "packweir.private"));
    for prefix in ["packweir", "packweir.private", "packweir.private.tools"] {
        let mut invalid = config.clone();
        invalid.access.nuget_owners.push(NugetOwnership {
            prefix: prefix.into(),
            repository: "nuget".into(),
            additional_repositories: vec![],
        });
        assert!(invalid.validate().is_err());
    }
    config.access.nuget_owners.push(NugetOwnership {
        prefix: "packweir.private.tools".into(),
        repository: "nuget-prod".into(),
        additional_repositories: vec!["nuget-local".into()],
    });
    config.validate().unwrap();
    for (prefix, repository, additional) in [
        ("Packweir.Private", "nuget-local", vec![]),
        ("packweir..private", "nuget-local", vec![]),
        ("other", "maven", vec![]),
        ("other", "nuget-local", vec!["nuget"]),
        ("other", "nuget-local", vec!["nuget-prod", "nuget-prod"]),
    ] {
        let mut invalid = config.clone();
        invalid.access.nuget_owners.push(NugetOwnership {
            prefix: prefix.into(),
            repository: repository.into(),
            additional_repositories: additional.into_iter().map(str::to_owned).collect(),
        });
        assert!(invalid.validate().is_err());
    }
    let legacy: AccessConfig = toml::from_str("legacy_read_enabled=true").unwrap();
    assert!(legacy.nuget_owners.is_empty());
    assert!(
        toml::from_str::<AccessConfig>(
            "[[nuget_owners]]\nprefix='example'\nrepository='nuget'\nunknown=true"
        )
        .is_err()
    );
}

#[test]
fn nuget_ownership_preflights_flat_registration_wrapped_and_unknown_resources() {
    let config = nuget_configuration();
    let repo = &config.repositories["nuget"];
    for path in [
        "flatcontainer/packweir.private/index.json",
        "v3-flatcontainer/Packweir.Private.Fixture/1.0.0/Packweir.Private.Fixture.1.0.0.nupkg",
        "flat/packweir.private.fixture/1.0.0/packweir.private.fixture.nuspec",
        "flat/packweir.private.fixture/1.0.0/packweir.private.fixture.1.0.0.nupkg.sha512",
        "registration5-gz-semver2/packweir.private.fixture/index.json",
        "registration5-gz-semver2/packweir.private.fixture/page/1.0.0/2.0.0.json",
    ] {
        assert!(!config.access.path_allowed("nuget", repo, path), "{path}");
        assert!(
            config
                .access
                .path_allowed("nuget-local", &config.repositories["nuget-local"], path),
            "{path}"
        );
    }
    assert!(config.access.path_allowed("nuget", repo, "index.json"));
    assert!(
        config
            .access
            .path_allowed("nuget", repo, "flat/packweir.privateevil/index.json")
    );
    for path in [
        "query",
        "query?q=packweir",
        "unknown/index.json",
        "unknown/flat/public/index.json",
        "flat/packweir.private/unknown",
        "flat/%70ackweir.private/index.json",
        "flat/packweir.private/../public/index.json",
    ] {
        assert!(!config.access.path_allowed("nuget", repo, path), "{path}");
        assert!(
            !config
                .access
                .path_allowed("nuget-local", &config.repositories["nuget-local"], path),
            "{path}"
        );
    }
    for raw in [
        "https://api.nuget.org/v3-flatcontainer/packweir.private.fixture/index.json",
        "https://api.nuget.org/v3-flatcontainer/Packweir.Private.Fixture/1.0.0/Packweir.Private.Fixture.1.0.0.nupkg",
        "https://api.nuget.org/unknown/package.bin",
        "https://api.nuget.org/unknown/flat/public/index.json",
        "https://api.nuget.org/index.json",
        "https://api.nuget.org/v3-flatcontainer/public/index.json?alternate=packweir.private",
        "https://unconfigured.example/v3-flatcontainer/public/index.json",
    ] {
        let target: url::Url = raw.parse().unwrap();
        assert!(!config.access.url_allowed("nuget", repo, &target), "{raw}");
        let wrapped =
            url::Url::parse(&registry::wrap(&config.public_url, "nuget", &target)).unwrap();
        assert!(
            !config.access.path_allowed(
                "nuget",
                repo,
                wrapped.path().strip_prefix("/r/nuget/").unwrap()
            ),
            "{raw}"
        );
    }
    assert!(config.access.url_allowed(
        "nuget",
        repo,
        &"https://api.nuget.org/v3/index.json".parse().unwrap()
    ));
    assert!(
        config.access.url_allowed(
            "nuget",
            repo,
            &"https://api.nuget.org/v3-flatcontainer/public/index.json"
                .parse()
                .unwrap()
        )
    );
}

#[test]
fn nuget_scoped_permissions_and_native_push_keys_preserve_role_boundaries() {
    let mut config = nuget_configuration();
    config.access.principals.insert(
        "builder".into(),
        principal(vec![
            grant("nuget", vec![Action::Read], Some("packweir.private")),
            grant(
                "nuget-local",
                vec![Action::Read, Action::Write],
                Some("packweir.private"),
            ),
            grant("nuget-prod", vec![Action::Write], Some("packweir.private")),
        ]),
    );
    config.validate().unwrap();
    let access = control(&config, &"s".repeat(32));
    let identity = access.authenticate(&headers(&"s".repeat(32))).unwrap();
    let package = packweir::nuget::Coordinate::new("Packweir.Private.Fixture", "1")
        .unwrap()
        .package();
    assert!(identity.allows_package("nuget-local", Action::Write, &package));
    assert!(!identity.allows_package("nuget-prod", Action::Promote, &package));
    assert!(identity.allows_package_copy("nuget-local", "nuget-prod", &package));
    assert!(!identity.allows_package_copy("nuget-prod", "nuget-local", &package));
    assert!(!identity.allows_copy("nuget-local", "nuget-prod", "packweir.private"));
    for path in [
        "index.json",
        "flat/packweir.private/index.json",
        "registration5-gz-semver2/Packweir.Private.Fixture/index.json",
    ] {
        assert!(
            identity.allows_path("nuget", &config.repositories["nuget"], Action::Read, path),
            "{path}"
        );
    }
    for path in [
        "query",
        "unknown/index.json",
        "flat/packweir.privateevil/index.json",
        "flat/packweir.other/index.json",
    ] {
        assert!(
            !identity.allows_path("nuget", &config.repositories["nuget"], Action::Read, path),
            "{path}"
        );
    }
    let mut native = HeaderMap::new();
    native.insert("X-NuGet-ApiKey", "s".repeat(32).parse().unwrap());
    assert_eq!(
        access.authenticate_nuget_push(&native).unwrap().id,
        "builder"
    );
    assert!(access.authenticate(&native).is_none());
    native.insert(header::AUTHORIZATION, "s".repeat(32).parse().unwrap());
    assert!(access.authenticate_nuget_push(&native).is_none());
    assert!(access.authenticate(&native).is_none());
    native.remove(header::AUTHORIZATION);
    native.append("x-nuget-apikey", "s".repeat(32).parse().unwrap());
    assert!(access.authenticate_nuget_push(&native).is_none());
    let mut invalid = config.clone();
    invalid.access.principals.get_mut("builder").unwrap().grants[0].namespace =
        Some("Packweir.Private".into());
    assert!(invalid.validate().is_err());
}

#[tokio::test]
async fn nuget_redirects_cannot_fetch_reserved_ids_or_leave_a_scoped_grant() {
    use axum::{Router, extract::OriginalUri, http::StatusCode, response::IntoResponse};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let hits = Arc::new(AtomicUsize::new(0));
    let observed = hits.clone();
    let app = Router::new().fallback(move |OriginalUri(uri): OriginalUri| {
        let observed = observed.clone();
        async move {
            match uri.path() {
                "/repo/flat/public/index.json" => (
                    StatusCode::FOUND,
                    [(
                        header::LOCATION,
                        "/repo/flat/Packweir.Private.Fixture/index.json",
                    )],
                )
                    .into_response(),
                "/repo/flat/public.scoped/index.json" => (
                    StatusCode::FOUND,
                    [(header::LOCATION, "/repo/flat/other/index.json")],
                )
                    .into_response(),
                "/repo/flat/public.query/index.json" => (
                    StatusCode::FOUND,
                    [(
                        header::LOCATION,
                        "/repo/flat/public/index.json?q=packweir.private",
                    )],
                )
                    .into_response(),
                "/repo/flat/Packweir.Private.Fixture/index.json"
                | "/repo/flat/other/index.json" => {
                    observed.fetch_add(1, Ordering::SeqCst);
                    "forbidden metadata".into_response()
                }
                _ => "unowned metadata".into_response(),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base: url::Url = format!("http://{}/repo/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut config = nuget_configuration();
    config.allow_private_upstreams = true;
    let repo = config.repositories.get_mut("nuget").unwrap();
    repo.upstream = Some(base.clone());
    repo.download_origins.clear();
    config.validate().unwrap();
    let guard = network::FetchGuard {
        access: &config.access,
        repository: "nuget",
        principal: None,
    };
    for path in ["flat/public/index.json", "flat/public.query/index.json"] {
        assert!(
            network::fetch_guarded(
                &config.repositories["nuget"],
                &base.join(path).unwrap(),
                None,
                1024,
                true,
                &guard
            )
            .await
            .is_err()
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let unowned = network::fetch_guarded(
        &config.repositories["nuget"],
        &base.join("flat/public.unredirected/index.json").unwrap(),
        None,
        1024,
        true,
        &guard,
    )
    .await
    .unwrap();
    assert_eq!(unowned.bytes.as_ref(), b"unowned metadata");
    config.access.nuget_owners.clear();
    config.access.principals.insert(
        "builder".into(),
        principal(vec![grant("nuget", vec![Action::Read], Some("public"))]),
    );
    let identity = control(&config, &"s".repeat(32))
        .authenticate(&headers(&"s".repeat(32)))
        .unwrap();
    let guard = network::FetchGuard {
        access: &config.access,
        repository: "nuget",
        principal: Some(&identity),
    };
    assert!(
        network::fetch_guarded(
            &config.repositories["nuget"],
            &base.join("flat/public.scoped/index.json").unwrap(),
            None,
            1024,
            true,
            &guard
        )
        .await
        .is_err()
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    server.abort();
}
