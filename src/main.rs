use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use packweir::{
    config::Config,
    gateway::{self, AppState},
    inventory, oci, scanner,
    storage::BlobStore,
    store::Store,
};
use std::{path::PathBuf, sync::Arc};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, default_value = "packweir.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// Run the authenticated gateway. Requires DATABASE_URL, PACKWEIR_ADMIN_TOKEN, PACKWEIR_READ_TOKEN.
    Serve,
    /// Run scanner adapters in a dedicated worker process. Requires DATABASE_URL.
    Worker {
        #[arg(long)]
        once: bool,
    },
    /// Validate configuration without connecting to any service.
    Validate,
    /// Probe the local gateway readiness endpoint (database and blob storage).
    Health,
    /// Inspect administrative queue, evidence, and recorded-storage statistics.
    Status,
    /// Stage, inspect, seal, promote, or revoke an immutable hosted release.
    Hosted {
        #[command(subcommand)]
        command: HostedCommands,
    },
    /// Exchange digest-bound OCI evidence archives without trusting foreign claims.
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommands,
    },
    /// Inspect remote analyses or reconcile an interrupted submission.
    Remote {
        #[command(subcommand)]
        command: RemoteCommands,
    },
    /// Inspect a local archive without executing package code.
    Inventory {
        path: PathBuf,
        #[arg(long, default_value = "inventory")]
        format: String,
    },
    /// Inspect a staged artifact through the administrative API.
    Inspect { digest: String },
    /// Explain each delivery scope, required check, evidence age, and next action.
    Explain {
        digest: String,
        #[arg(long)]
        repository: Option<String>,
        #[arg(long, requires = "repository")]
        origin: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Queue an artifact through native proxy routing (returns pending until approved).
    Prefetch { repository: String, path: String },
}

#[derive(Subcommand)]
enum HostedCommands {
    /// Reserve immutable coordinates and print a native-publisher upload URL.
    Stage {
        repository: String,
        name: String,
        version: String,
        #[arg(long)]
        id: Option<uuid::Uuid>,
    },
    /// Inspect a stage, file bindings, and a recorded promotion receipt.
    Status { id: uuid::Uuid },
    /// Upload a single repository-relative file into an open stage.
    Upload {
        id: uuid::Uuid,
        path: String,
        file: PathBuf,
    },
    /// Freeze the complete file manifest and queue security analysis.
    Seal { id: uuid::Uuid },
    /// Abandon an open stage and release its never-sealed coordinate reservation.
    Abort { id: uuid::Uuid },
    /// Copy a published release into a sealed destination with fresh destination checks.
    Copy {
        source: uuid::Uuid,
        repository: String,
        #[arg(long)]
        source_manifest: String,
        #[arg(long)]
        id: Option<uuid::Uuid>,
    },
    /// Publish exactly the reviewed manifest after all current checks pass.
    Promote {
        id: uuid::Uuid,
        #[arg(long)]
        manifest: String,
    },
    /// Withdraw a release while preserving its immutable coordinate tombstone.
    Revoke {
        id: uuid::Uuid,
        #[arg(long)]
        manifest: String,
    },
}

#[derive(Subcommand)]
enum EvidenceCommands {
    /// Capture the current local snapshot, or reexport an immutable foreign import.
    Export {
        digest: String,
        #[arg(long)]
        layout: PathBuf,
        #[arg(long)]
        import_id: Option<uuid::Uuid>,
    },
    /// Archive foreign claims; this never approves the package or queues scans.
    Import {
        digest: String,
        #[arg(long)]
        layout: PathBuf,
        #[arg(long)]
        manifest: String,
    },
    /// Validate local OCI integrity offline, without configuration or services.
    Validate {
        #[arg(long)]
        layout: PathBuf,
        #[arg(long)]
        manifest: String,
    },
    /// List immutable import receipts for an already registered package digest.
    Imports { digest: String },
}

#[derive(Subcommand)]
enum RemoteCommands {
    List {
        digest: String,
    },
    Inspect {
        digest: String,
        id: uuid::Uuid,
    },
    /// Attach an operator-recovered SID; the worker must still verify all bindings.
    Reconcile {
        digest: String,
        id: uuid::Uuid,
        #[arg(long)]
        submission: String,
    },
}

async fn remote_command(config: &Config, command: RemoteCommands) -> Result<()> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let (digest, id, submission) = match command {
        RemoteCommands::List { digest } => (digest, None, None),
        RemoteCommands::Inspect { digest, id } => (digest, Some(id), None),
        RemoteCommands::Reconcile {
            digest,
            id,
            submission,
        } => {
            packweir::assemblyline_http::validate_sid(&submission)?;
            (digest, Some(id), Some(submission))
        }
    };
    oci::validate_subject(&digest)?;
    let mut path = format!("api/v1/artifacts/{digest}/remote-analysis");
    if let Some(id) = id {
        path.push_str(&format!("/{id}"));
    }
    let request = if let Some(submission) = submission {
        path.push_str("/reconcile");
        client
            .post(config.public_url.join(&path)?)
            .json(&serde_json::json!({"submission_id":submission}))
    } else {
        client.get(config.public_url.join(&path)?)
    };
    let bytes = administrative_response(
        request.bearer_auth(std::env::var("PACKWEIR_ADMIN_TOKEN")?),
        "remote analysis",
    )
    .await?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn bundle_summary(bundle: &oci::ValidatedBundle) -> serde_json::Value {
    serde_json::json!({
        "manifest_digest":bundle.manifest_digest(),
        "subject":bundle.envelope().subject,
        "verified":false,"trust_status":"unverified","approval_effect":"none",
        "integrity":"validated",
        "documents":bundle.envelope().documents
    })
}

async fn administrative_response(request: reqwest::RequestBuilder, label: &str) -> Result<Vec<u8>> {
    let mut response = request.send().await?;
    let status = response.status();
    // Redirects are disabled on this client: admin credentials never follow a
    // registry-controlled Location, even on the same origin.
    ensure!(status.is_success(), "{label} request failed: {status}");
    let limit = oci::MAX_TRANSFER_BYTES;
    ensure!(
        response.content_length().is_none_or(|n| n <= limit as u64),
        "evidence response exceeds size limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= limit.saturating_sub(bytes.len()),
            "evidence response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn evidence_command(config: &Config, command: EvidenceCommands) -> Result<()> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(120))
        .build()?;
    let token = std::env::var("PACKWEIR_ADMIN_TOKEN")?;
    let report = match command {
        EvidenceCommands::Export {
            digest,
            layout,
            import_id,
        } => {
            oci::validate_subject(&digest)?;
            let path = match import_id {
                Some(id) => format!("api/v1/artifacts/{digest}/evidence-imports/{id}/export"),
                None => format!("api/v1/artifacts/{digest}/evidence-export"),
            };
            let bytes = administrative_response(
                client
                    .get(config.public_url.join(&path)?)
                    .bearer_auth(&token),
                "evidence",
            )
            .await?;
            let bundle = oci::parse_transfer(&bytes)?;
            ensure!(
                bundle.envelope().subject == digest,
                "exported package subject mismatch"
            );
            oci::write_layout(&layout, &bundle)?;
            bundle_summary(&bundle)
        }
        EvidenceCommands::Import {
            digest,
            layout,
            manifest,
        } => {
            oci::validate_subject(&digest)?;
            let bundle = oci::read_layout(&layout, &manifest)?;
            ensure!(
                bundle.envelope().subject == digest,
                "imported package subject mismatch"
            );
            let body = serde_json::to_vec(&bundle.transfer())?;
            ensure!(
                body.len() <= oci::MAX_TRANSFER_BYTES,
                "evidence transfer exceeds size limit"
            );
            let path = format!("api/v1/artifacts/{digest}/evidence-import");
            let bytes = administrative_response(
                client
                    .post(config.public_url.join(&path)?)
                    .bearer_auth(&token)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body),
                "evidence",
            )
            .await?;
            serde_json::from_slice(&bytes)?
        }
        EvidenceCommands::Imports { digest } => {
            oci::validate_subject(&digest)?;
            let path = format!("api/v1/artifacts/{digest}/evidence-imports");
            let bytes = administrative_response(
                client
                    .get(config.public_url.join(&path)?)
                    .bearer_auth(&token),
                "evidence",
            )
            .await?;
            serde_json::from_slice(&bytes)?
        }
        EvidenceCommands::Validate { .. } => {
            unreachable!("offline validation runs before loading config")
        }
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn hosted_command(config: &Config, command: HostedCommands) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;
    let token = std::env::var("PACKWEIR_SERVICE_TOKEN")?;
    let request = match command {
        HostedCommands::Stage {
            repository,
            name,
            version,
            id,
        } => {
            ensure!(
                !repository.is_empty()
                    && repository
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "invalid repository name"
            );
            client.post(config.public_url.join(&format!("api/v1/repositories/{repository}/staging"))?)
                .json(&serde_json::json!({"id":id.unwrap_or_else(uuid::Uuid::new_v4),"name":name,"version":version}))
        }
        HostedCommands::Status { id } => {
            client.get(config.public_url.join(&format!("api/v1/staging/{id}"))?)
        }
        HostedCommands::Upload { id, path, file } => {
            packweir::maven::validate_path(&path)?;
            let bytes = scanner::read_bounded(
                tokio::fs::File::open(file).await?,
                config.max_download_bytes.min(128 * 1024 * 1024) as u64,
            )
            .await?;
            client
                .put(
                    config
                        .public_url
                        .join(&format!("api/v1/staging/{id}/{path}"))?,
                )
                .body(bytes)
        }
        HostedCommands::Seal { id } => client.post(
            config
                .public_url
                .join(&format!("api/v1/staging/{id}/seal"))?,
        ),
        HostedCommands::Abort { id } => client.post(
            config
                .public_url
                .join(&format!("api/v1/staging/{id}/abort"))?,
        ),
        HostedCommands::Copy {source,repository,source_manifest,id} => client
            .post(config.public_url.join(&format!("api/v1/staging/{source}/copy"))?)
            .json(&serde_json::json!({"id":id.unwrap_or_else(uuid::Uuid::new_v4),"destination_repository":repository,"source_manifest_digest":source_manifest})),
        HostedCommands::Promote { id, manifest } => client
            .post(
                config
                    .public_url
                    .join(&format!("api/v1/staging/{id}/promote"))?,
            )
            .json(&serde_json::json!({"manifest_digest":manifest})),
        HostedCommands::Revoke { id, manifest } => client
            .post(
                config
                    .public_url
                    .join(&format!("api/v1/staging/{id}/revoke"))?,
            )
            .json(&serde_json::json!({"manifest_digest":manifest})),
    };
    let response = request.bearer_auth(token).send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !text.is_empty() {
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
            Err(_) => println!("{text}"),
        }
    }
    ensure!(status.is_success(), "hosted request failed: {status}");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    if let Commands::Evidence {
        command: EvidenceCommands::Validate { layout, manifest },
    } = &cli.command
    {
        let bundle = oci::read_layout(layout, manifest)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&bundle_summary(&bundle))?
        );
        return Ok(());
    }
    if let Commands::Inventory { path, format } = &cli.command {
        let metadata = std::fs::metadata(path)?;
        ensure!(
            metadata.len() <= 128 * 1024 * 1024,
            "local input exceeds 128 MiB"
        );
        let name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("missing filename"))?
            .to_string_lossy();
        let inventory =
            inventory::inspect(&name, &std::fs::read(path)?, inventory::Limits::default())?;
        let value = match format.as_str() {
            "cyclonedx" => inventory::cyclonedx(&inventory),
            "spdx" => inventory::spdx(&inventory),
            "inventory" => serde_json::to_value(inventory)?,
            _ => anyhow::bail!("unknown format"),
        };
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let config = Arc::new(Config::load(&cli.config)?);
    match cli.command {
        Commands::Validate => println!("configuration valid: {}", config.fingerprint()),
        Commands::Status => {
            let report: serde_json::Value = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()?
                .get(config.public_url.join("api/v1/operations")?)
                .bearer_auth(std::env::var("PACKWEIR_ADMIN_TOKEN")?)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::Hosted { command } => hosted_command(&config, command).await?,
        Commands::Evidence { command } => evidence_command(&config, command).await?,
        Commands::Remote { command } => remote_command(&config, command).await?,
        Commands::Health => {
            let mut address = config.listen;
            if address.ip().is_unspecified() {
                address.set_ip(if address.is_ipv4() {
                    std::net::Ipv4Addr::LOCALHOST.into()
                } else {
                    std::net::Ipv6Addr::LOCALHOST.into()
                });
            }
            reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(4))
                .build()?
                .get(format!("http://{address}/ready"))
                .send()
                .await?
                .error_for_status()?;
            println!("ready");
        }
        Commands::Inspect { digest } => {
            let url = config
                .public_url
                .join(&format!("api/v1/artifacts/{digest}"))?;
            println!(
                "{}",
                reqwest::Client::new()
                    .get(url)
                    .bearer_auth(std::env::var("PACKWEIR_ADMIN_TOKEN")?)
                    .send()
                    .await?
                    .error_for_status()?
                    .text()
                    .await?
            );
        }
        Commands::Explain {
            digest,
            repository,
            origin,
            json,
        } => {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid SHA-256 digest"
            );
            let mut url = config
                .public_url
                .join(&format!("api/v1/artifacts/{digest}"))?;
            {
                let mut query = url.query_pairs_mut();
                if let Some(repository) = repository {
                    query.append_pair("repository", &repository);
                }
                if let Some(origin) = origin {
                    query.append_pair("origin", &origin);
                }
            }
            let response = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?
                .get(url)
                .bearer_auth(std::env::var("PACKWEIR_ADMIN_TOKEN")?)
                .send()
                .await?;
            ensure!(
                response.status() != reqwest::StatusCode::NOT_FOUND,
                "artifact not registered for this scope; prefetch it first or adjust --repository/--origin"
            );
            let report: serde_json::Value = response.error_for_status()?.json().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                let scopes: Vec<packweir::explain::ScopeExplanation> =
                    serde_json::from_value(report["scopes"].clone())?;
                ensure!(
                    !scopes.is_empty(),
                    "server returned no delivery explanations"
                );
                print!("{}", packweir::explain::render(&digest, &scopes));
            }
        }
        Commands::Prefetch { repository, path } => {
            let response = reqwest::Client::new()
                .post(config.public_url.join("api/v1/prefetch")?)
                .bearer_auth(std::env::var("PACKWEIR_ADMIN_TOKEN")?)
                .json(&serde_json::json!({"repository":repository,"path":path}))
                .send()
                .await?;
            let status = response.status();
            println!("{}", response.text().await?);
            ensure!(status.is_success(), "prefetch not approved: {status}");
        }
        Commands::Serve | Commands::Worker { .. } => {
            let store = Store::connect(&std::env::var("DATABASE_URL")?).await?;
            let blobs = BlobStore::new(&config.storage)?;
            match cli.command {
                Commands::Worker { once } => scanner::worker(config, store, blobs, once).await?,
                Commands::Serve => {
                    let admin = std::env::var("PACKWEIR_ADMIN_TOKEN")?;
                    let read = std::env::var("PACKWEIR_READ_TOKEN")?;
                    ensure!(
                        admin.len() >= 32 && read.len() >= 32 && admin != read,
                        "use distinct admin/read tokens of at least 32 characters"
                    );
                    let listener = tokio::net::TcpListener::bind(config.listen).await?;
                    let app =
                        gateway::router(AppState::try_new(config, store, blobs, admin, read)?);
                    axum::serve(listener, app)
                        .with_graceful_shutdown(async {
                            let _ = tokio::signal::ctrl_c().await;
                        })
                        .await?;
                }
                _ => unreachable!(),
            }
        }
        Commands::Inventory { .. } => unreachable!(),
    }
    Ok(())
}
