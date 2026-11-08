//! Release signing for application updates (spec section 29).
//!
//! `aegis-update keygen <path>` writes a new signing key and prints its public key.
//! `aegis-update sign --key <path> --out <dir> --version <v> [--seq <n>]
//!     [--windows <exe> [--windows-version <v>] [--windows-min <v>]]
//!     [--android <apk> --android-code <n> [--android-version <v>] [--android-min <v>]]`
//! copies the files into `<dir>` and writes `<dir>/manifest.signed`.

use aegis_core::update::{self, Artifact, ANDROID, MAX_FILE, WINDOWS};
use aegis_core::hex;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage:\n  aegis-update keygen <path>\n  aegis-update sign --key <path> --out <dir> --version <v> [--seq <n>]\n      [--windows <exe> [--windows-version <v>] [--windows-min <v>]]\n      [--android <apk> --android-code <n> [--android-version <v>] [--android-min <v>]]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("keygen") if args.len() == 2 => keygen(Path::new(&args[1])),
        Some("sign") => sign(&args[1..]),
        _ => Err(USAGE.to_owned()),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aegis-update: {e}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(path: &Path) -> Result<(), String> {
    let sk = aegis_core::random_bytes::<32>().map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(format!("{}\n", hex::encode(&sk)).as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    println!("{}", hex::encode(&update::public_key(&sk)));
    Ok(())
}

fn read_key(path: &Path) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    hex::decode_array(text.trim()).map_err(|_| format!("{}: not a signing key", path.display()))
}

#[derive(Default)]
struct Opts {
    key: Option<PathBuf>,
    out: Option<PathBuf>,
    version: Option<String>,
    seq: Option<u64>,
    flags: BTreeMap<String, String>,
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let val = it.next().ok_or_else(|| format!("{flag} needs a value"))?.clone();
        match flag.as_str() {
            "--key" => o.key = Some(val.into()),
            "--out" => o.out = Some(val.into()),
            "--version" => o.version = Some(val),
            "--seq" => o.seq = Some(val.parse().map_err(|_| "bad --seq".to_owned())?),
            "--windows" | "--windows-version" | "--windows-min" | "--android" | "--android-code"
            | "--android-version" | "--android-min" => {
                o.flags.insert(flag.trim_start_matches("--").to_owned(), val);
            }
            _ => return Err(format!("unknown option {flag}\n{USAGE}")),
        }
    }
    Ok(o)
}

/// Sequence number of the manifest already in `out`, 0 if none.
fn previous_seq(out: &Path) -> Result<u64, String> {
    let bytes = match std::fs::read(out.join(aegis_server::MANIFEST_FILE)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.to_string()),
    };
    let body = bytes.get(64..).ok_or("old manifest is damaged")?;
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| "old manifest is damaged")?;
    v["seq"].as_u64().ok_or_else(|| "old manifest is damaged".to_owned())
}

fn artifact(
    out: &Path,
    file: &str,
    version: &str,
    min: &str,
    code: u64,
) -> Result<Artifact, String> {
    let src = Path::new(file);
    let name = src
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| update::valid_name(n) && *n != aegis_server::MANIFEST_FILE)
        .ok_or_else(|| format!("{file}: unsupported file name"))?
        .to_owned();
    if update::parse_version(version).is_none() || update::parse_version(min).is_none() {
        return Err(format!("{file}: bad version"));
    }
    let mut f = std::fs::File::open(src).map_err(|e| format!("{file}: {e}"))?;
    let (sha256, size) = update::hash_reader(&mut f).map_err(|e| format!("{file}: {e}"))?;
    if size == 0 || size > MAX_FILE {
        return Err(format!("{file}: size {size} not allowed"));
    }
    let dst = out.join(&name);
    let same = std::fs::canonicalize(src).ok() == std::fs::canonicalize(&dst).ok();
    if !same {
        std::fs::copy(src, &dst).map_err(|e| format!("{}: {e}", dst.display()))?;
    }
    Ok(Artifact { name, size, sha256, version: version.to_owned(), min: min.to_owned(), code })
}

fn sign(args: &[String]) -> Result<(), String> {
    let o = parse(args)?;
    let (Some(key), Some(out), Some(version)) = (o.key, o.out, o.version) else {
        return Err(USAGE.to_owned());
    };
    if update::parse_version(&version).is_none() {
        return Err("bad --version".into());
    }
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let prev = previous_seq(&out)?;
    let seq = o.seq.unwrap_or(prev + 1);
    if seq <= prev {
        return Err(format!("--seq must be above {prev}"));
    }
    let flag = |k: &str| o.flags.get(k).map(String::as_str);
    let mut files = BTreeMap::new();
    if let Some(exe) = flag("windows") {
        let v = flag("windows-version").unwrap_or(&version);
        let a = artifact(&out, exe, v, flag("windows-min").unwrap_or("0"), 0)?;
        files.insert(WINDOWS.to_owned(), a);
    }
    if let Some(apk) = flag("android") {
        let code: u64 = flag("android-code")
            .and_then(|c| c.parse().ok())
            .filter(|c| *c > 0)
            .ok_or("--android needs --android-code")?;
        let v = flag("android-version").unwrap_or(&version);
        let a = artifact(&out, apk, v, flag("android-min").unwrap_or("0"), code)?;
        files.insert(ANDROID.to_owned(), a);
    }
    if files.is_empty() {
        return Err("nothing to sign: pass --windows and/or --android".into());
    }
    let sk = read_key(&key)?;
    let body = update::manifest_json(seq, &version, &files);
    let signed = update::sign(&sk, body.as_bytes());
    let tmp = out.join(format!("{}.tmp", aegis_server::MANIFEST_FILE));
    std::fs::write(&tmp, &signed)
        .and_then(|()| std::fs::rename(&tmp, out.join(aegis_server::MANIFEST_FILE)))
        .map_err(|e| format!("{}: {e}", out.display()))?;
    println!("manifest seq {seq}, {} file(s), signed by {}", files.len(), hex::encode(&update::public_key(&sk)));
    Ok(())
}
