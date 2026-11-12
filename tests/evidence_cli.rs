use packweir::oci::{self, ValidatedBundle};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

const ADMIN_TOKEN: &str = "cli-test-secret-never-render-this-admin-token";

#[derive(Debug, Clone)]
struct Request {
    method: String,
    path: String,
    authorization: String,
    body: Vec<u8>,
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn json(value: &Value) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(value).unwrap(),
        }
    }
}

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn new(reply: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let request_copy = requests.clone();
        let stop_copy = stop.clone();
        let thread = thread::spawn(move || {
            while !stop_copy.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Windows accepted sockets inherit the listener's mode.
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let request = read_request(&mut stream);
                        let response = reply(&request);
                        request_copy.lock().unwrap().push(request);
                        let has_length = response
                            .headers
                            .iter()
                            .any(|(key, _)| key.eq_ignore_ascii_case("content-length"));
                        let mut head = format!(
                            "HTTP/1.1 {} Test\r\nConnection: close\r\nContent-Type: application/json\r\n",
                            response.status
                        );
                        for (key, value) in response.headers {
                            head.push_str(&format!("{key}: {value}\r\n"));
                        }
                        if !has_length {
                            head.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
                        }
                        head.push_str("\r\n");
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(&response.body);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("mock HTTP accept failed: {e}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let joined = self.thread.take().unwrap().join();
        assert!(
            joined.is_ok() || thread::panicking(),
            "mock HTTP thread failed"
        );
    }
}

fn read_request(stream: &mut TcpStream) -> Request {
    let mut bytes = Vec::new();
    let end = loop {
        let mut buffer = [0; 4096];
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "request ended before headers");
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        assert!(bytes.len() < 64 * 1024, "mock request headers too large");
    };
    let headers = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let mut lines = headers.lines();
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap().to_owned();
    let path = first.next().unwrap().to_owned();
    let mut length = 0usize;
    let mut authorization = String::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap();
            }
            if key.eq_ignore_ascii_case("authorization") {
                authorization = value.trim().to_owned();
            }
        }
    }
    assert!(length <= oci::MAX_TRANSFER_BYTES);
    while bytes.len() - end < length {
        let mut buffer = [0; 4096];
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "request ended before body");
        bytes.extend_from_slice(&buffer[..read]);
    }
    Request {
        method,
        path,
        authorization,
        body: bytes[end..end + length].to_vec(),
    }
}

fn subject() -> String {
    "a".repeat(64)
}

fn bundle(subject: &str) -> ValidatedBundle {
    oci::build_bundle(
        subject,
        json!({"verified":true}),
        json!({"approved":true}),
        vec![b"{ \"signature\": \"raw bytes survive\" }\r\n".to_vec()],
    )
    .unwrap()
}

fn config(directory: &Path, url: &str) -> std::path::PathBuf {
    let mut value: toml::Value = toml::from_str(include_str!("../packweir.toml")).unwrap();
    value["public_url"] = toml::Value::String(url.into());
    let path = directory.join("test.toml");
    std::fs::write(&path, toml::to_string(&value).unwrap()).unwrap();
    path
}

fn cli(directory: &Path, config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_packweir"));
    command
        .current_dir(directory)
        .arg("--config")
        .arg(config)
        .arg("evidence")
        .env("PACKWEIR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("TOKIO_WORKER_THREADS", "2")
        .env_remove("DATABASE_URL")
        .env_remove("RUST_LOG");
    command
}

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn failure(output: Output, expected: &str) {
    assert!(!output.status.success(), "CLI unexpectedly succeeded");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        rendered.contains(expected),
        "missing error {expected:?}: {rendered}"
    );
    assert!(!rendered.contains(ADMIN_TOKEN), "CLI leaked admin token");
}

#[test]
fn offline_validation_works_without_config_credentials_or_database() {
    let temp = tempfile::tempdir().unwrap();
    let bundle = bundle(&subject());
    let layout = temp.path().join("layout");
    oci::write_layout(&layout, &bundle).unwrap();
    let absent = temp.path().join("absent.toml");
    let output = cli(temp.path(), &absent)
        .arg("validate")
        .arg("--layout")
        .arg(&layout)
        .arg("--manifest")
        .arg(bundle.manifest_digest())
        .env_remove("PACKWEIR_ADMIN_TOKEN")
        .output()
        .unwrap();
    let report = success(output);
    assert_eq!(report["subject"], subject());
    assert_eq!(report["integrity"], "validated");
    assert_eq!(report["verified"], false);
    assert_eq!(report["approval_effect"], "none");
    failure(
        cli(temp.path(), &absent)
            .arg("validate")
            .arg("--layout")
            .arg(&layout)
            .arg("--manifest")
            .arg("packweir")
            .env_remove("PACKWEIR_ADMIN_TOKEN")
            .output()
            .unwrap(),
        "only sha256",
    );
}

#[test]
fn export_checks_package_subject_before_publishing_a_layout() {
    let temp = tempfile::tempdir().unwrap();
    let foreign = bundle(&"b".repeat(64));
    let wire = serde_json::to_value(foreign.transfer()).unwrap();
    let server = Server::new(move |_| Reply::json(&wire));
    let config = config(temp.path(), &server.url);
    let layout = temp.path().join("must-not-exist");
    failure(
        cli(temp.path(), &config)
            .arg("export")
            .arg(subject())
            .arg("--layout")
            .arg(&layout)
            .output()
            .unwrap(),
        "exported package subject mismatch",
    );
    assert!(!layout.exists());
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].authorization, format!("Bearer {ADMIN_TOKEN}"));
}

#[test]
fn import_binds_subject_and_manifest_before_sending_any_request() {
    let temp = tempfile::tempdir().unwrap();
    let bundle = bundle(&subject());
    let layout = temp.path().join("layout");
    oci::write_layout(&layout, &bundle).unwrap();
    let server = Server::new(|_| Reply::json(&json!({"unexpected":true})));
    let config = config(temp.path(), &server.url);
    failure(
        cli(temp.path(), &config)
            .arg("import")
            .arg("b".repeat(64))
            .arg("--layout")
            .arg(&layout)
            .arg("--manifest")
            .arg(bundle.manifest_digest())
            .output()
            .unwrap(),
        "imported package subject mismatch",
    );
    failure(
        cli(temp.path(), &config)
            .arg("import")
            .arg(subject())
            .arg("--layout")
            .arg(&layout)
            .arg("--manifest")
            .arg(format!("sha256:{}", "b".repeat(64)))
            .output()
            .unwrap(),
        "absent from OCI index",
    );
    failure(
        cli(temp.path(), &config)
            .arg("export")
            .arg("../outside")
            .arg("--layout")
            .arg(temp.path().join("other"))
            .output()
            .unwrap(),
        "lowercase package SHA-256",
    );
    assert!(server.requests().is_empty());
}

#[test]
fn export_import_and_reexport_preserve_the_exact_manifest_and_document_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let bundle = bundle(&subject());
    let wire = serde_json::to_value(bundle.transfer()).unwrap();
    let server = Server::new(move |request| {
        if request.method == "POST" {
            Reply::json(
                &json!({"verified":false,"approval_effect":"none","trust_status":"unverified"}),
            )
        } else {
            Reply::json(&wire)
        }
    });
    let config = config(temp.path(), &server.url);
    let layout = temp.path().join("layout");
    let export = success(
        cli(temp.path(), &config)
            .arg("export")
            .arg(subject())
            .arg("--layout")
            .arg(&layout)
            .output()
            .unwrap(),
    );
    assert_eq!(export["verified"], false);
    let import = success(
        cli(temp.path(), &config)
            .arg("import")
            .arg(subject())
            .arg("--layout")
            .arg(&layout)
            .arg("--manifest")
            .arg(bundle.manifest_digest())
            .output()
            .unwrap(),
    );
    assert_eq!(import["trust_status"], "unverified");
    let id = uuid::Uuid::new_v4();
    success(
        cli(temp.path(), &config)
            .arg("export")
            .arg(subject())
            .arg("--layout")
            .arg(temp.path().join("reexport"))
            .arg("--import-id")
            .arg(id.to_string())
            .output()
            .unwrap(),
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].path,
        format!("/api/v1/artifacts/{}/evidence-export", subject())
    );
    assert_eq!(
        requests[1].path,
        format!("/api/v1/artifacts/{}/evidence-import", subject())
    );
    assert_eq!(
        requests[2].path,
        format!(
            "/api/v1/artifacts/{}/evidence-imports/{id}/export",
            subject()
        )
    );
    assert!(
        requests
            .iter()
            .all(|r| r.authorization == format!("Bearer {ADMIN_TOKEN}"))
    );
    let received = oci::parse_transfer(&requests[1].body).unwrap();
    assert_eq!(received.manifest_digest(), bundle.manifest_digest());
    assert_eq!(received.manifest_bytes(), bundle.manifest_bytes());
    assert_eq!(received.document_bytes(0), bundle.document_bytes(0));
}

#[test]
fn same_and_cross_origin_redirects_never_receive_a_followup_request() {
    let temp = tempfile::tempdir().unwrap();
    let bundle = bundle(&subject());
    let layout = temp.path().join("layout");
    oci::write_layout(&layout, &bundle).unwrap();
    let destination = Server::new(|_| Reply::json(&json!({"stolen":true})));
    for (status, cross_origin, importing) in
        [(302, false, false), (307, false, true), (308, true, true)]
    {
        let location = if cross_origin {
            format!("{}stolen", destination.url)
        } else {
            "/stolen".into()
        };
        let server = Server::new(move |_| Reply {
            status,
            headers: vec![("Location".into(), location.clone())],
            body: ADMIN_TOKEN.as_bytes().to_vec(),
        });
        let config = config(temp.path(), &server.url);
        let mut command = cli(temp.path(), &config);
        command
            .arg(if importing { "import" } else { "export" })
            .arg(subject())
            .arg("--layout");
        if importing {
            command
                .arg(&layout)
                .arg("--manifest")
                .arg(bundle.manifest_digest());
        } else {
            command.arg(temp.path().join("never-published"));
        }
        failure(
            command.output().unwrap(),
            &format!("evidence request failed: {status}"),
        );
        assert_eq!(server.requests().len(), 1);
        assert!(destination.requests().is_empty());
    }
}

#[test]
fn untrusted_error_bodies_are_not_printed_and_oversized_responses_fail_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    for oversize in [false, true] {
        let server = Server::new(move |_| Reply {
            status: if oversize { 200 } else { 403 },
            headers: if oversize {
                vec![(
                    "Content-Length".into(),
                    (oci::MAX_TRANSFER_BYTES + 1).to_string(),
                )]
            } else {
                vec![]
            },
            body: ADMIN_TOKEN.as_bytes().to_vec(),
        });
        let config = config(temp.path(), &server.url);
        let layout = temp.path().join("never-published");
        failure(
            cli(temp.path(), &config)
                .arg("export")
                .arg(subject())
                .arg("--layout")
                .arg(&layout)
                .output()
                .unwrap(),
            if oversize {
                "evidence response exceeds size limit"
            } else {
                "evidence request failed: 403"
            },
        );
        assert!(!layout.exists());
    }
}
