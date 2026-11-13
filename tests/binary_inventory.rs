use packweir::{
    inventory::{self, Limits},
    model::sha256,
};
use std::io::{Cursor, Write};

fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        zip.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

#[test]
fn binary_capture_uses_the_same_inventory_and_exact_embedded_bytes() {
    let elf = b"\x7fELFharmless parser input, never executed";
    let pe = b"MZharmless parser input, never executed";
    let data = archive(&[
        ("pkg/a.so", elf),
        ("pkg/b.dll", pe),
        ("pkg/copy.so", elf),
        ("pkg/__init__.py", b""),
        ("pkg/README", b"plain text"),
    ]);
    let plain = inventory::inspect("wheel.whl", &data, Limits::default()).unwrap();
    let (captured, files) =
        inventory::inspect_binary_inputs("wheel.whl", &data, Limits::default()).unwrap();
    assert_eq!(
        serde_json::to_value(plain).unwrap(),
        serde_json::to_value(captured).unwrap()
    );
    assert_eq!(files.len(), 2);
    assert_eq!(files[&sha256(elf)], elf);
    assert_eq!(files[&sha256(pe)], pe);
    assert!(!files.contains_key(&sha256(b"plain text")));
}

#[test]
fn binary_capture_rejects_unsafe_archives_instead_of_extracting_an_alternate_view() {
    let data = archive(&[("../payload.so", b"\x7fELFnot executable")]);
    assert!(inventory::inspect_binary_inputs("bad.whl", &data, Limits::default()).is_err());
    let data = archive(&[("nested.so", b"\x7fELFnot executable")]);
    assert!(
        inventory::inspect_binary_inputs(
            "bad.whl",
            &data,
            Limits {
                expanded_bytes: 2,
                ..Limits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn oversize_binary_capture_is_incomplete_without_changing_plain_inventory_limits() {
    let mut data = vec![0; 16 * 1024 * 1024 + 1];
    data[..4].copy_from_slice(b"\x7fELF");
    assert!(inventory::inspect("large.so", &data, Limits::default()).is_ok());
    assert!(inventory::inspect_binary_inputs("large.so", &data, Limits::default()).is_err());
}

#[test]
fn unnamed_legacy_tar_and_gzip_payloads_cannot_hide_native_members() {
    let native = b"\x7fELFcontrolled archive member, never executed";
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_old();
    header.set_size(native.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "payload.so", &native[..])
        .unwrap();
    let tar = tar.into_inner().unwrap();
    assert_ne!(&tar[257..262], b"ustar");
    for prefix in [0, 1024] {
        let mut padded = vec![0; prefix];
        padded.extend_from_slice(&tar);
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&padded).unwrap();
        for input in [padded, gzip.finish().unwrap()] {
            let (_, files) =
                inventory::inspect_binary_inputs("opaque-output.bin", &input, Limits::default())
                    .unwrap();
            assert_eq!(files[&sha256(native)], native);
        }
    }
}
