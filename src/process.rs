//! Bounded execution shared by protocol adapters and built-in tool drivers.
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::Path,
    process::{ExitStatus, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
};

pub async fn read_bounded(reader: impl AsyncRead + Unpin, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    reader.take(limit + 1).read_to_end(&mut bytes).await?;
    ensure!(bytes.len() as u64 <= limit, "scanner output limit exceeded");
    Ok(bytes)
}

pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
}

pub async fn execute(
    program: &str,
    args: &[OsString],
    environment: &BTreeMap<String, String>,
    directory: &Path,
    input: &[u8],
    timeout: Duration,
) -> Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(directory)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    for name in ["SYSTEMROOT", "WINDIR"] {
        if let Ok(value) = std::env::var(name) {
            cmd.env(name, value);
        }
    }
    let mut child = cmd.spawn()?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let execution = async {
        let write = async {
            stdin.write_all(input).await?;
            stdin.shutdown().await?;
            drop(stdin);
            Ok::<_, anyhow::Error>(())
        };
        let (_, stdout, _) = tokio::try_join!(
            write,
            read_bounded(stdout, 1024 * 1024),
            read_bounded(stderr, 64 * 1024)
        )?;
        Ok::<_, anyhow::Error>(Output {
            status: child.wait().await?,
            stdout,
        })
    };
    match tokio::time::timeout(timeout, execution).await {
        Ok(Ok(output)) => Ok(output),
        other => {
            let _ = child.kill().await;
            match other {
                Ok(Err(error)) => Err(error),
                Err(_) => anyhow::bail!("scanner timed out"),
                _ => unreachable!(),
            }
        }
    }
}

pub async fn verify_executable(path: &str, expected: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    let mut file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    ensure!(
        metadata.is_file() && metadata.len() <= 256 * 1024 * 1024,
        "scanner executable exceeds limit or is not a file"
    );
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        total += count as u64;
        ensure!(
            total <= 256 * 1024 * 1024,
            "scanner executable exceeds limit"
        );
        hash.update(&buffer[..count]);
    }
    ensure!(
        hex::encode(hash.finalize()) == expected,
        "scanner executable digest mismatch"
    );
    Ok(())
}
