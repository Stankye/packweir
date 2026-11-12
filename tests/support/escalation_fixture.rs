//! Test-owned scanner protocol fixture, not an LLM or external-provider qualification.
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::PathBuf,
    time::{Duration, Instant},
};

fn field<'a>(input: &'a str, key: &str) -> &'a str {
    let marker = format!("\"{key}\":\"");
    input
        .split_once(&marker)
        .unwrap_or_else(|| panic!("request is missing {key}"))
        .1
        .split('"')
        .next()
        .unwrap()
}

fn main() {
    assert!(std::env::var_os("DATABASE_URL").is_none());
    let args: Vec<_> = std::env::args().skip(1).collect();
    let name = &args[0];
    assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let bundle = std::fs::read_to_string("evidence.json").unwrap();
    assert!(
        std::fs::metadata("evidence.json")
            .unwrap()
            .permissions()
            .readonly()
    );
    assert!(
        std::fs::metadata("resource-report")
            .unwrap()
            .permissions()
            .readonly()
    );
    let capture = PathBuf::from(std::env::var_os("PACKWEIR_ESCALATION_CAPTURE").unwrap());
    std::fs::write(capture.join(format!("{name}.request.json")), &input).unwrap();
    std::fs::write(capture.join(format!("{name}.bundle.json")), &bundle).unwrap();
    writeln!(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(capture.join("calls.log"))
            .unwrap(),
        "{name}"
    )
    .unwrap();
    if args.get(1).map(String::as_str) == Some("pause") {
        std::fs::write(capture.join("agent.ready"), b"ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !capture.join("agent.release").exists() {
            assert!(
                Instant::now() < deadline,
                "test did not release paused agent"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if args.get(1).map(String::as_str) == Some("error") {
        std::process::exit(17);
    }
    let report = std::fs::read_to_string("resource-report").unwrap();
    print!(
        "{}",
        report.replace("$EVIDENCE_DIGEST", field(&input, "evidence_digest"))
    );
}
