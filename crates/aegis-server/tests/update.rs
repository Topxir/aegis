#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_core::net::Client;
use aegis_core::update::{self, Artifact, Offer, ANDROID, CHUNK, MAX_FILE, WINDOWS};
use aegis_core::Error;
use aegis_server::{handle_update, serve, BlobReply, Config, Request, ServerState, MANIFEST_FILE, UPDATE_DIR};
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("aegis-update-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const SK: [u8; 32] = [7u8; 32];

fn req(path: &str, query: &str) -> Request {
    Request {
        method: "GET".into(),
        path: path.into(),
        query: aegis_core::text::parse_pairs(query).unwrap(),
        body: Vec::new(),
    }
}

fn status(r: &BlobReply) -> u16 {
    match r {
        BlobReply::Json(j) => j.status,
        BlobReply::Bytes(_) => 200,
    }
}

fn artifact(name: &str, data: &[u8], version: &str, code: u64) -> Artifact {
    Artifact {
        name: name.into(),
        size: data.len() as u64,
        sha256: aegis_core::sha256(&[data]),
        version: version.into(),
        min: "0.1.0".into(),
        code,
    }
}

fn signed(seq: u64, files: &BTreeMap<String, Artifact>) -> Vec<u8> {
    update::sign(&SK, update::manifest_json(seq, "0.2.0", files).as_bytes())
}

fn pk() -> [u8; 32] {
    update::public_key(&SK)
}

#[test]
fn bad_signature_is_rejected() {
    let mut files = BTreeMap::new();
    files.insert(WINDOWS.to_owned(), artifact("a.exe", b"abc", "0.2.0", 0));
    let good = signed(1, &files);
    assert!(update::open(&good, &pk()).is_ok());

    let mut sig = good.clone();
    sig[5] ^= 1;
    assert_eq!(update::open(&sig, &pk()), Err(Error::BadSignature));
    let mut body = good.clone();
    let last = body.len() - 2;
    body[last] ^= 1;
    assert_eq!(update::open(&body, &pk()), Err(Error::BadSignature));
    assert_eq!(update::open(&good, &update::public_key(&[8u8; 32])), Err(Error::BadSignature));
    // A signature over the bare manifest, without the domain prefix, does not count.
    let plain = update::manifest_json(1, "0.2.0", &files);
    let raw = ed25519_sign_raw(plain.as_bytes());
    assert_eq!(update::open(&raw, &pk()), Err(Error::BadSignature));
    assert!(update::open(&good[..64], &pk()).is_err());
}

fn ed25519_sign_raw(msg: &[u8]) -> Vec<u8> {
    let sig = aegis_core::identity::ed25519_sign(&SK, msg);
    [sig.as_slice(), msg].concat()
}

#[test]
fn wrong_hash_or_size_fails_the_download() {
    let data = vec![9u8; CHUNK + 10];
    let a = artifact("a.exe", &data, "0.2.0", 0);
    let mut out = Vec::new();
    update::download_with(&a, &mut out, |off| Ok(data[off as usize..].iter().take(CHUNK).copied().collect()))
        .unwrap();
    assert_eq!(out, data);

    let mut bad = data.clone();
    bad[3] ^= 1;
    let r = update::download_with(&a, &mut Vec::new(), |off| {
        Ok(bad[off as usize..].iter().take(CHUNK).copied().collect())
    });
    assert_eq!(r, Err(Error::Update("file hash")));

    // The server sends more than the manifest promises.
    let long = [data.as_slice(), b"extra"].concat();
    let r = update::download_with(&a, &mut Vec::new(), |off| {
        Ok(long[off as usize..].iter().take(CHUNK + 5).copied().collect())
    });
    assert_eq!(r, Err(Error::Update("file size")));
    let r = update::download_with(&a, &mut Vec::new(), |_| Ok(Vec::new()));
    assert_eq!(r, Err(Error::Update("file size")));
}

#[test]
fn downgrade_and_replayed_manifest_are_refused() {
    let mut files = BTreeMap::new();
    files.insert(WINDOWS.to_owned(), artifact("a.exe", b"abc", "0.1.0", 0));
    files.insert(ANDROID.to_owned(), artifact("a.apk", b"abc", "0.2.0", 2));
    let m = update::open(&signed(4, &files), &pk()).unwrap();
    assert_eq!(update::evaluate(&m, WINDOWS, "0.1.0", 0, 0), Ok(Offer::Current));
    assert_eq!(update::evaluate(&m, WINDOWS, "0.3.0", 0, 0), Ok(Offer::Current));
    assert_eq!(update::evaluate(&m, ANDROID, "0.9.0", 3, 0), Ok(Offer::Current));
    assert_eq!(update::evaluate(&m, ANDROID, "0.2.0", 2, 4), Ok(Offer::Current));
    assert!(matches!(update::evaluate(&m, ANDROID, "0.1.0", 1, 4), Ok(Offer::Newer { .. })));
    assert_eq!(update::evaluate(&m, WINDOWS, "0.0.1", 0, 5), Err(Error::Update("manifest rollback")));
}

#[test]
fn oversized_entries_are_refused() {
    let mut a = artifact("a.exe", b"abc", "0.2.0", 0);
    a.size = MAX_FILE + 1;
    let mut files = BTreeMap::new();
    files.insert(WINDOWS.to_owned(), a.clone());
    assert_eq!(update::open(&signed(1, &files), &pk()), Err(Error::Update("file size")));
    assert_eq!(update::download_with(&a, &mut Vec::new(), |_| Ok(vec![0])), Err(Error::Update("file size")));
    let huge = vec![b' '; update::MAX_MANIFEST + 1];
    assert_eq!(update::open(&huge, &pk()), Err(Error::Update("manifest size")));
}

#[test]
fn manifest_with_unsafe_name_is_refused() {
    for name in ["../a.exe", "a\\b.exe", ".a", "C:a.exe"] {
        let mut files = BTreeMap::new();
        files.insert(WINDOWS.to_owned(), artifact(name, b"abc", "0.2.0", 0));
        assert_eq!(update::open(&signed(1, &files), &pk()), Err(Error::Update("file name")), "{name}");
    }
}

#[test]
fn server_serves_only_plain_files_in_the_update_dir() {
    let dir = TempDir::new();
    let up = dir.0.join(UPDATE_DIR);
    assert_eq!(status(&handle_update(Some(&up), &req("/api/v2/update/manifest", ""))), 404);
    std::fs::create_dir_all(up.join("sub")).unwrap();
    std::fs::write(dir.0.join("secret.txt"), b"outside").unwrap();
    std::fs::write(up.join("sub").join("x.bin"), b"inner").unwrap();
    let data: Vec<u8> = (0..CHUNK + 100).map(|i| i as u8).collect();
    std::fs::write(up.join("a.exe"), &data).unwrap();
    std::fs::write(up.join(MANIFEST_FILE), b"signed bytes").unwrap();

    let r = handle_update(Some(&up), &req("/api/v2/update/manifest", ""));
    assert_eq!(r, BlobReply::Bytes(b"signed bytes".to_vec()));
    let r = handle_update(Some(&up), &req("/api/v2/update/file", "name=a.exe"));
    assert_eq!(r, BlobReply::Bytes(data[..CHUNK].to_vec()));
    let r = handle_update(Some(&up), &req("/api/v2/update/file", &format!("name=a.exe&off={CHUNK}")));
    assert_eq!(r, BlobReply::Bytes(data[CHUNK..].to_vec()));
    let past = format!("name=a.exe&off={}", data.len());
    assert_eq!(status(&handle_update(Some(&up), &req("/api/v2/update/file", &past))), 416);

    for q in [
        "name=..%2Fsecret.txt",
        "name=..%5Csecret.txt",
        "name=..",
        "name=sub%2Fx.bin",
        "name=%2E%2E%2Fsecret.txt",
        "name=C%3A%5Cwindows%5Cwin.ini",
        "name=%2Fetc%2Fpasswd",
        "name=manifest.signed",
        "name=a.exe&name=b.exe",
        "name=a.exe&off=-1",
        "name=a.exe&off=01",
        "",
    ] {
        assert_eq!(status(&handle_update(Some(&up), &req("/api/v2/update/file", q))), 400, "{q}");
    }
    assert_eq!(status(&handle_update(Some(&up), &req("/api/v2/update/file", "name=sub"))), 404);
    assert_eq!(status(&handle_update(Some(&up), &req("/api/v2/update/file", "name=missing.exe"))), 404);
    assert_eq!(status(&handle_update(Some(&up), &req("/api/v2/update/other", ""))), 404);
    assert_eq!(status(&handle_update(None, &req("/api/v2/update/manifest", ""))), 404);
    let mut post = req("/api/v2/update/manifest", "");
    post.method = "POST".into();
    assert_eq!(status(&handle_update(Some(&up), &post)), 405);
}

#[test]
fn server_refuses_oversized_files() {
    let dir = TempDir::new();
    let up = dir.0.join(UPDATE_DIR);
    std::fs::create_dir_all(&up).unwrap();
    let big = std::fs::File::create(up.join("big.exe")).unwrap();
    big.set_len(MAX_FILE + 1).unwrap();
    drop(big);
    let manifest = std::fs::File::create(up.join(MANIFEST_FILE)).unwrap();
    manifest.set_len(update::MAX_MANIFEST as u64 + 1).unwrap();
    drop(manifest);
    assert_eq!(status(&handle_update(Some(&up), &req("/api/v2/update/file", "name=big.exe"))), 413);
    assert_eq!(status(&handle_update(Some(&up), &req("/api/v2/update/manifest", ""))), 413);
}

fn spawn(dir: &Path) -> (String, Arc<AtomicBool>, std::thread::JoinHandle<()>, [u8; 32]) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(ServerState::open_with(dir, Config::default()).unwrap()));
    let srv_pk = state.lock().unwrap().server_public_key().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = Arc::clone(&stop);
    let h = std::thread::spawn(move || serve(&listener, &state, &s2).unwrap());
    (url, stop, h, srv_pk)
}

#[test]
fn client_downloads_and_verifies_over_the_sealed_route() {
    let dir = TempDir::new();
    let up = dir.0.join(UPDATE_DIR);
    std::fs::create_dir_all(&up).unwrap();
    let data: Vec<u8> = (0..2 * CHUNK + 3).map(|i| (i * 7) as u8).collect();
    std::fs::write(up.join("aegis.exe"), &data).unwrap();
    let mut files = BTreeMap::new();
    files.insert(WINDOWS.to_owned(), artifact("aegis.exe", &data, "0.2.0", 0));
    std::fs::write(up.join(MANIFEST_FILE), signed(3, &files)).unwrap();

    let (url, stop, h, srv_pk) = spawn(&dir.0);
    let c = Client::new(&url, None).unwrap().with_server_key(srv_pk);
    let m = update::open(&c.update_manifest().unwrap().unwrap(), &pk()).unwrap();
    let Ok(Offer::Newer { artifact, required: false }) = update::evaluate(&m, WINDOWS, "0.1.0", 0, 2) else {
        panic!("expected an update");
    };
    let mut out = Vec::new();
    update::download(&c, &artifact, &mut out).unwrap();
    assert_eq!(out, data);

    // Tampered file on the server: the hash check catches it.
    let mut bad = data.clone();
    bad[CHUNK + 1] ^= 0xff;
    std::fs::write(up.join("aegis.exe"), &bad).unwrap();
    assert_eq!(update::download(&c, &artifact, &mut Vec::new()), Err(Error::Update("file hash")));
    assert!(matches!(c.update_chunk("../aegis-server.state", 0), Err(Error::Update("file name"))));

    std::fs::remove_file(up.join(MANIFEST_FILE)).unwrap();
    assert_eq!(c.update_manifest().unwrap(), None);
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap();
}

fn tool(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_aegis-update")).args(args).output().unwrap()
}

#[test]
fn tool_keygen_and_sign() {
    let dir = TempDir::new();
    let key = dir.0.join("k");
    let keyp = key.to_str().unwrap();
    let out = tool(&["keygen", keyp]);
    assert!(out.status.success());
    let pk_hex = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    assert_eq!(pk_hex.len(), 64);
    let before = std::fs::read(&key).unwrap();
    assert!(!tool(&["keygen", keyp]).status.success());
    assert_eq!(std::fs::read(&key).unwrap(), before, "keygen must not overwrite");

    let exe = dir.0.join("aegis-desktop.exe");
    let apk = dir.0.join("aegis.apk");
    std::fs::write(&exe, b"exe bytes").unwrap();
    std::fs::write(&apk, b"apk bytes").unwrap();
    let outdir = dir.0.join("update");
    let o = outdir.to_str().unwrap();
    let base = ["sign", "--key", keyp, "--out", o, "--version", "0.2.0"];
    let full = [
        &base[..],
        &["--windows", exe.to_str().unwrap(), "--windows-min", "0.1.0"],
        &["--android", apk.to_str().unwrap(), "--android-code", "3", "--android-version", "0.2.0-alpha"],
    ]
    .concat();
    let s = tool(&full);
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    let pk: [u8; 32] = aegis_core::hex::decode_array(&pk_hex).unwrap();
    let m = update::open(&std::fs::read(outdir.join(MANIFEST_FILE)).unwrap(), &pk).unwrap();
    assert_eq!(m.seq, 1);
    assert_eq!(m.files[WINDOWS].name, "aegis-desktop.exe");
    assert_eq!(m.files[WINDOWS].min, "0.1.0");
    assert_eq!(m.files[ANDROID].code, 3);
    assert_eq!(m.files[ANDROID].sha256, aegis_core::sha256(&[b"apk bytes"]));
    assert_eq!(std::fs::read(outdir.join("aegis.apk")).unwrap(), b"apk bytes");

    let s = tool(&full);
    assert!(s.status.success());
    let m = update::open(&std::fs::read(outdir.join(MANIFEST_FILE)).unwrap(), &pk).unwrap();
    assert_eq!(m.seq, 2);
    let lower = [&full[..], &["--seq", "2"]].concat();
    assert!(!tool(&lower).status.success(), "seq must grow");
    assert!(!tool(&base).status.success(), "nothing to sign");
}
