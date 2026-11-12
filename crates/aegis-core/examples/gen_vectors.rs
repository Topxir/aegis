//! Regenerates `docs/test-vectors.json`: `cargo run -p aegis-core --example gen_vectors`.

use std::path::PathBuf;

fn main() {
    let doc = match aegis_core::vectors::generate() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("failed to build vectors: {e}");
            std::process::exit(1);
        }
    };
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "docs", "test-vectors.json"]
        .iter()
        .collect();
    let text = serde_json::to_string_pretty(&doc).unwrap_or_default() + "\n";
    if let Err(e) = std::fs::write(&path, text) {
        eprintln!("cannot write {}: {e}", path.display());
        std::process::exit(1);
    }
    println!("wrote {}", path.display());
}
