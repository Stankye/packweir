use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use packweir::{
    config::Config,
    gateway::{self, AppState},
    inventory, scanner,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
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
                    let app = gateway::router(AppState::new(config, store, blobs, admin, read));
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
