use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

pub fn fixture_program() -> &'static Path {
    static PROGRAM: OnceLock<PathBuf> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/scanner-fixture")
            .join(std::process::id().to_string());
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("scanner-fixture{}", std::env::consts::EXE_SUFFIX));
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/scanner_fixture.rs");
        let status = std::process::Command::new("rustc")
            .arg("--edition=2024")
            .arg(source)
            .arg("-o")
            .arg(&path)
            .status()
            .expect("Rust compiler required for test subprocess fixture");
        assert!(status.success());
        path
    })
}
