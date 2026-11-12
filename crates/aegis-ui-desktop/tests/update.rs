#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Desktop side of signed updates: sequence storage, staging and the exe swap.

use aegis_core::update::{self, Artifact, Offer, WINDOWS};
use aegis_core::Error;
use aegis_ui_desktop::engine::update::{accept, fetch, last_seq, matches, old_path, swap};
use std::collections::BTreeMap;
use std::path::PathBuf;

const SK: [u8; 32] = [9; 32];

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let n = u64::from_le_bytes(aegis_core::random_bytes::<8>().unwrap());
        let p = std::env::temp_dir().join(format!("aegis-upd-test-{tag}-{n:016x}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn artifact(data: &[u8], version: &str) -> Artifact {
    Artifact {
        name: "aegis-desktop.exe".into(),
        size: data.len() as u64,
        sha256: aegis_core::sha256(&[data]),
        version: version.into(),
        min: "0.0.1".into(),
        code: 0,
    }
}

fn signed(seq: u64, a: &Artifact) -> Vec<u8> {
    let mut files = BTreeMap::new();
    files.insert(WINDOWS.to_owned(), a.clone());
    update::sign(&SK, update::manifest_json(seq, &a.version, &files).as_bytes())
}

#[test]
fn accepted_sequence_blocks_replays() {
    let d = Dir::new("seq");
    let pk = update::public_key(&SK);
    let a = artifact(b"new build", "0.3.0");
    assert!(matches!(accept(&d.0, &signed(5, &a), &pk, "0.2.0"), Ok(Offer::Newer { .. })));
    assert_eq!(last_seq(&d.0), 5);
    assert_eq!(
        accept(&d.0, &signed(4, &a), &pk, "0.2.0"),
        Err(Error::Update("manifest rollback"))
    );
    // A lower version under a higher sequence is not offered.
    let old = artifact(b"old build", "0.1.0");
    assert_eq!(accept(&d.0, &signed(6, &old), &pk, "0.2.0"), Ok(Offer::Current));
    assert_eq!(last_seq(&d.0), 6);
}

#[test]
fn foreign_signature_does_not_move_the_sequence() {
    let d = Dir::new("sig");
    let a = artifact(b"x", "9.0.0");
    let pk = update::trusted_key().unwrap();
    assert_eq!(accept(&d.0, &signed(99, &a), &pk, "0.1.0"), Err(Error::BadSignature));
    assert_eq!(last_seq(&d.0), 0);
}

#[test]
fn only_a_matching_file_is_staged() {
    let d = Dir::new("fetch");
    let body = b"the new exe".to_vec();
    let a = artifact(&body, "0.3.0");
    let bad = fetch(&d.0, &a, |_| Ok(b"the old exe".to_vec()));
    assert_eq!(bad, Err(Error::Update("file hash")));
    let long = fetch(&d.0, &a, |_| Ok(vec![0; body.len() + 1]));
    assert_eq!(long, Err(Error::Update("file size")));
    assert_eq!(std::fs::read_dir(d.0.join("update")).unwrap().count(), 0);
    let path = fetch(&d.0, &a, |off| Ok(body[usize::try_from(off).unwrap()..].to_vec())).unwrap();
    assert!(matches(&path, &a));
    // Staged once, not downloaded again.
    assert_eq!(fetch(&d.0, &a, |_| Err(Error::BadResponse)).unwrap(), path);
}

#[test]
fn swap_keeps_the_old_exe_aside() {
    let d = Dir::new("swap");
    let exe = d.0.join("aegis-desktop.exe");
    let staged = d.0.join("staged.exe");
    std::fs::write(&exe, b"old").unwrap();
    std::fs::write(&staged, b"new").unwrap();
    swap(&staged, &exe).unwrap();
    assert_eq!(std::fs::read(&exe).unwrap(), b"new");
    assert_eq!(std::fs::read(old_path(&exe)).unwrap(), b"old");
    // A missing staged file leaves the current exe in place.
    std::fs::remove_file(&staged).unwrap();
    assert!(swap(&staged, &exe).is_err());
    assert_eq!(std::fs::read(&exe).unwrap(), b"new");
}
