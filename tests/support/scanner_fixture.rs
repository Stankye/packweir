// Test subprocess only. This deliberately does not implement cryptographic verification.
use std::{
    io::{Read, Write},
    path::Path,
};

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("scope-report") {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let bundle = std::fs::read_to_string("evidence.json").unwrap();
        assert_eq!(bundle.matches("\"repository\":").count(),1,"a delivery check must see exactly its own alias");
        print!("{}",std::fs::read_to_string("resource-report").unwrap());
        return;
    }
    if matches!(
        args.first().map(String::as_str),
        Some("verify-artifact" | "scan" | "check")
    ) {
        assert!(std::env::var_os("DATABASE_URL").is_none());
        match args[0].as_str() {
            "verify-artifact" => {
                assert_eq!(args.len(), 6);
                assert!(args[1].starts_with("--provenance-path="));
                assert!(args[2].starts_with("--source-uri=github.com/"));
                assert!(args[3].starts_with("--builder-id=https://github.com/"));
                assert_eq!(args[4], "--print-provenance");
                if let Ok(expected) = std::fs::read("resource-raw_expected") {
                    assert_eq!(std::fs::read(&args[1][18..]).unwrap(), expected);
                }
            }
            "scan" => {
                assert_eq!(args.len(), 11);
                for flag in [
                    "source",
                    "--offline",
                    "--all-packages",
                    "--no-resolve",
                    "--no-call-analysis=go",
                    "--no-call-analysis=rust",
                ] {
                    assert!(args.iter().any(|arg| arg == flag));
                }
                assert!(std::env::var_os("OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY").is_some());
            }
            "check" => {
                assert_eq!(args.len(), 10);
                for flag in [
                    "--target=repo",
                    "--format=debug",
                    "--color=never",
                    "--verbosity=quiet",
                ] {
                    assert!(args.iter().any(|arg| arg == flag));
                }
                assert!(args.iter().any(|arg| arg.starts_with("--policy=")));
                assert!(args.iter().any(|arg| arg.starts_with("--exec=")));
                assert!(args.iter().any(|arg| arg.starts_with("--ref=")));
            }
            _ => unreachable!(),
        }
        std::io::stdout()
            .write_all(&std::fs::read("resource-report").unwrap())
            .unwrap();
        let code = std::fs::read_to_string("resource-status")
            .unwrap_or_else(|_| "0".into())
            .trim()
            .parse::<i32>()
            .unwrap();
        std::process::exit(code);
    }
    if args.first().map(String::as_str) == Some("protocol") {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        assert!(input.contains("\"resources\""));
        assert_eq!(std::fs::read("resource-policy").unwrap(), b"policy fixture");
        assert!(
            std::fs::metadata("resource-policy")
                .unwrap()
                .permissions()
                .readonly()
        );
        assert!(
            std::fs::metadata("evidence.json")
                .unwrap()
                .permissions()
                .readonly()
        );
        println!("{{\"outcome\":\"pass\",\"details\":{{\"resource_seen\":true}}}}");
        return;
    }
    assert_eq!(args.len(), 6);
    assert_eq!(args[0], "verify-blob");
    assert!(args[1].starts_with("--bundle="));
    assert!(args[2].starts_with("--trusted-root="));
    assert_eq!(args[3], "--certificate-identity=fixture@example.test");
    assert_eq!(
        args[4],
        "--certificate-oidc-issuer=https://issuer.example.test"
    );
    assert_eq!(
        std::fs::read(&args[2][15..]).unwrap(),
        b"trusted-root fixture"
    );
    assert_eq!(std::fs::read(Path::new(&args[5])).unwrap(), b"fixture");
    let bundle = std::fs::read_to_string(&args[1][9..]).unwrap();
    if bundle.contains("\"fixture_result\":\"sleep\"") {
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    if bundle.contains("\"fixture_result\":\"slow-reject\"") {
        std::thread::sleep(std::time::Duration::from_millis(700));
    }
    if bundle.contains("\"fixture_result\":\"huge\"") {
        let _ = std::io::stdout().write_all(&vec![b'x'; 2 * 1024 * 1024]);
        return;
    }
    if !bundle.contains("\"fixture_result\":\"pass\"") {
        std::process::exit(1);
    }
}
