// Test subprocess only: contract fixtures are not license detection or legal analysis.
use std::{io::Write, path::Path};
fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(args.len(), 11);
    for (index, expected) in [
        "--license",
        "--copyright",
        "--package",
        "--info",
        "--strip-root",
        "--quiet",
        "--processes",
        "1",
        "--json",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(&args[index], expected);
    }
    assert!(std::env::var_os("DATABASE_URL").is_none());
    let mode = std::fs::read_to_string("resource-mode").unwrap_or_default();
    if mode == "exit" {
        std::process::exit(2);
    }
    if mode == "sleep" {
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    if mode == "huge" {
        std::fs::File::create(&args[9])
            .unwrap()
            .write_all(&vec![b'x'; 9 * 1024 * 1024])
            .unwrap();
        return;
    }
    if mode == "mutate" {
        let path = Path::new(&args[10]).join("f00000/LICENSE");
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&path, permissions).unwrap();
        std::fs::write(path, b"changed").unwrap();
    }
    let report = std::fs::read_to_string("resource-report")
        .unwrap()
        .replace("\"__INPUT__\"", &quoted(&args[10]));
    std::fs::write(&args[9], report).unwrap();
}
