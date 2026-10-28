// Test subprocess only. This deliberately does not implement cryptographic verification.
use std::{
    io::{Read, Write},
    path::Path,
};

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
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
