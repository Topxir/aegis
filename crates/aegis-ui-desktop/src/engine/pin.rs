//! PIN unlock (spec sections 20 and 25) and the duress PIN.
//!
//! The vault is still opened by the password. A random vault key wraps that password in
//! `<vault>.pinpw`; the key itself is wrapped by the PIN and a secret that only the server
//! releases (`<vault>.pin`). Three wrong PINs and the server forgets the secret.
//!
//! Files next to the vault, none of them readable without the PIN or the password except
//! `.pinmeta`, which has to be readable before unlocking because the server has to be reached:
//! it holds the endpoint, the proxy address and the pinned server key, and nothing else (no
//! username, no times). The PIN verifier goes to whatever server that file names, so the file is
//! sealed to the operating system user (see `oseal`) and a copy that was edited, or made for
//! another vault, is refused before anything is sent.

use super::*;
use super::oseal;
use aegis_core::net::PinOpen;
use aegis_core::pin::{is_valid_pin, DuressRecord, PinFile, PinSetup};
use aegis_core::hex;
use serde::{Deserialize, Serialize};

pub(super) fn side(vault: &Path, ext: &str) -> PathBuf {
    let mut n = vault.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    n.push(".");
    n.push(ext);
    vault.with_file_name(n)
}

/// What is needed to reach the server before the vault is open.
#[derive(Serialize, Deserialize)]
pub(super) struct PinMeta {
    endpoint: String,
    socks5: String,
    tor: bool,
    server_key: String,
}

impl PinMeta {
    pub(super) fn from_settings(st: &Settings) -> Option<Self> {
        let key = st.pinned_key()?;
        Some(Self {
            endpoint: st.endpoint.clone(),
            socks5: st.socks5.clone(),
            tor: st.tor,
            server_key: hex::encode(&key),
        })
    }

    pub(super) fn settings(&self, lang: Lang) -> Option<Settings> {
        let key: [u8; 32] = hex::decode_array(&self.server_key).ok()?;
        let mut st = Settings::new(lang);
        st.endpoint.clone_from(&self.endpoint);
        st.socks5.clone_from(&self.socks5);
        st.tor = self.tor;
        st.server_key = Some(key);
        st.server_key_for.clone_from(&self.endpoint);
        Some(st)
    }
}

/// Rewrites `.pinmeta` when it differs. A PIN has to keep working after the user changes the
/// server or the proxy.
pub(super) fn sync_meta(vault: &Path, st: &Settings) {
    let pin = side(vault, "pin");
    if !pin.exists() {
        return;
    }
    let Some(meta) = PinMeta::from_settings(st) else {
        return;
    };
    let Ok(json) = serde_json::to_vec(&meta) else {
        return;
    };
    let file = side(vault, "pinmeta");
    let ctx = meta_context(vault);
    if std::fs::read(&file).is_ok_and(|old| oseal::open(&old, &ctx).is_some_and(|j| j == json)) {
        return;
    }
    if let Some(bytes) = oseal::seal(&json, &ctx) {
        let _ = write_atomic(&file, &bytes);
    }
}

fn meta_context(vault: &Path) -> Vec<u8> {
    vault
        .file_name()
        .map(|n| n.to_string_lossy().into_owned().into_bytes())
        .unwrap_or_default()
}

/// The authentic `.pinmeta` of a vault, or `None` when it is missing, edited or not ours.
fn read_meta(vault: &Path) -> Option<PinMeta> {
    let blob = std::fs::read(side(vault, "pinmeta")).ok()?;
    let json = oseal::open(&blob, &meta_context(vault))?;
    serde_json::from_slice(&json).ok()
}

fn remove_quiet(p: &Path) {
    let _ = std::fs::remove_file(p);
}

/// Removes every PIN file of a vault.
pub(super) fn remove_pin_files(vault: &Path) {
    for ext in ["pin", "pinpw", "pinmeta", "duress"] {
        remove_quiet(&side(vault, ext));
    }
}

fn wrong(left: u32) -> Failure {
    Failure {
        key: "err.pin_wrong",
        detail: left.to_string(),
    }
}

/// Maps a 429 from a PIN call to its own message; any other error passes through.
fn throttled(e: aegis_core::Error) -> Failure {
    if matches!(e, aegis_core::Error::Http(429)) {
        Failure::new("err.pin_throttled")
    } else {
        Failure::from(e)
    }
}

fn hex_key(k: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(hex::encode(k))
}

impl Engine {
    /// A wrong PIN: remembers the count the server gave, for the duress answer.
    fn wrong_left(&self, left: u32) -> Failure {
        self.app().pin_left = Some(left);
        wrong(left)
    }

    /// Re-reads which PIN files exist for the open session.
    pub(super) fn refresh_pin(&self) {
        let mut app = self.app();
        let Some(s) = app.session.as_ref() else {
            app.pin_on = false;
            app.duress_on = false;
            return;
        };
        let p = self.vault_path(&s.data.username);
        app.pin_on = side(&p, "pin").exists();
        app.duress_on = app.pin_on && side(&p, "duress").exists();
    }

    /// Everything a PIN operation needs from the open session.
    fn pin_context(&self) -> Result<(Client, PathBuf, Zeroizing<String>), Failure> {
        let app = self.app();
        let s = app.session.as_ref().ok_or(Failure::new("err.locked"))?;
        let client = self.client_for(&s.data.settings)?;
        Ok((client, self.vault_path(&s.data.username), s.password.clone()))
    }

    fn read_pin_file(path: &Path) -> Result<PinFile, Failure> {
        let b = std::fs::read(side(path, "pin")).map_err(|_| Failure::new("err.pin_none"))?;
        Ok(PinFile::parse(&b)?)
    }

    pub fn pin_set(&self, pin: &str, confirm: &str) -> Result<(), Failure> {
        if !is_valid_pin(pin) {
            return Err(Failure::new("err.pin_format"));
        }
        if pin != confirm {
            return Err(Failure::new("err.pin_mismatch"));
        }
        self.flush()?;
        let (client, path, password) = self.pin_context()?;
        if side(&path, "pin").exists() {
            return Err(Failure::new("err.pin_exists"));
        }
        let vault_key = Zeroizing::new(aegis_core::random_bytes::<32>()?);
        let setup = PinSetup::new(pin, &vault_key)?;
        let wrapped = vault_encrypt(
            &hex_key(&vault_key),
            self.cfg.vault_params,
            password.as_bytes(),
        )?;
        client
            .pin_create(&setup.file.slot, &setup.verifier, &setup.s)
            .map_err(throttled)?;
        let written = (|| -> Result<(), Failure> {
            std::fs::create_dir_all(&self.cfg.data_dir).map_err(|e| io_failure(&e))?;
            write_atomic(&side(&path, "pinpw"), &wrapped)?;
            write_atomic(&side(&path, "pin"), &setup.file.encode())?;
            Ok(())
        })();
        if let Err(e) = written {
            remove_pin_files(&path);
            let _ = client.pin_delete(&setup.file.slot, &setup.verifier);
            return Err(e);
        }
        let st = self
            .app()
            .session
            .as_ref()
            .map(|s| s.data.settings.clone());
        if let Some(st) = st {
            sync_meta(&path, &st);
        }
        if let Some(s) = self.app().session.as_mut() {
            s.data.pin_verifier = hex::encode(&setup.verifier);
            s.dirty = true;
        }
        self.refresh_pin();
        self.flush()
    }

    /// Checks `pin` against the server without opening anything. Counts as an attempt.
    fn pin_verify(&self, client: &Client, file: &PinFile, pin: &str) -> Result<(), Failure> {
        if !is_valid_pin(pin) {
            return Err(Failure::new("err.pin_format"));
        }
        let key = file.derive(pin)?;
        match client.pin_open(&file.slot, &key.verifier()?).map_err(throttled)? {
            PinOpen::Secret(s) => {
                self.app().pin_left = None;
                file.unwrap(&key, &s)?;
                Ok(())
            }
            PinOpen::Wrong { left } => Err(self.wrong_left(left)),
            PinOpen::Throttled => Err(Failure::new("err.pin_throttled")),
            PinOpen::Gone => Err(Failure::new("err.pin_gone")),
        }
    }

    pub fn pin_remove(&self, pin: &str) -> Result<(), Failure> {
        let (client, path, _) = self.pin_context()?;
        let file = Self::read_pin_file(&path)?;
        if !is_valid_pin(pin) {
            return Err(Failure::new("err.pin_format"));
        }
        let key = file.derive(pin)?;
        match client.pin_open(&file.slot, &key.verifier()?).map_err(throttled)? {
            PinOpen::Secret(_) => self.app().pin_left = None,
            PinOpen::Wrong { left } => return Err(self.wrong_left(left)),
            PinOpen::Throttled => return Err(Failure::new("err.pin_throttled")),
            // Nothing is left on the server: only the local files remain to remove.
            PinOpen::Gone => {
                remove_pin_files(&path);
                self.refresh_pin();
                return Ok(());
            }
        }
        client
            .pin_delete(&file.slot, &key.verifier()?)
            .map_err(throttled)?;
        remove_pin_files(&path);
        if let Some(s) = self.app().session.as_mut() {
            s.data.pin_verifier.clear();
            s.dirty = true;
        }
        self.refresh_pin();
        Ok(())
    }

    pub fn duress_set(&self, pin: &str, duress: &str) -> Result<(), Failure> {
        let (client, path, _) = self.pin_context()?;
        let file = Self::read_pin_file(&path)?;
        if !is_valid_pin(duress) {
            return Err(Failure::new("err.pin_format"));
        }
        self.pin_verify(&client, &file, pin)?;
        let rec = DuressRecord::new(duress)?;
        if rec.matches(pin)? {
            return Err(Failure::new("err.duress_same"));
        }
        write_atomic(&side(&path, "duress"), &rec.encode())?;
        self.refresh_pin();
        Ok(())
    }

    pub fn duress_clear(&self) -> Result<(), Failure> {
        let (_, path, _) = self.pin_context()?;
        remove_quiet(&side(&path, "duress"));
        self.refresh_pin();
        Ok(())
    }

    /// Unlock with a PIN. The duress record is checked first and locally; the server is not
    /// contacted for it.
    pub(super) fn pin_unlock(&self, username: &str, path: &Path, pin: &str) -> Result<(), Failure> {
        if let Ok(b) = std::fs::read(side(path, "duress")) {
            if DuressRecord::parse(&b)?.matches(pin)? {
                return self.duress_open(path);
            }
        }
        let file = Self::read_pin_file(path)?;
        let meta = read_meta(path)
            .and_then(|m| m.settings(self.app().pre_lang))
            .ok_or(Failure::new("err.pin_gone"))?;
        let client = self.client_for(&meta)?;
        let key = file.derive(pin)?;
        let s = match client.pin_open(&file.slot, &key.verifier()?).map_err(throttled)? {
            PinOpen::Secret(s) => {
                self.app().pin_left = None;
                s
            }
            PinOpen::Wrong { left } => return Err(self.wrong_left(left)),
            PinOpen::Throttled => return Err(Failure::new("err.pin_throttled")),
            PinOpen::Gone => {
                // The PIN cannot work any more. The password still opens the vault.
                remove_pin_files(path);
                return Err(Failure::new("err.pin_gone"));
            }
        };
        let vault_key = file.unwrap(&key, &s)?;
        let wrapped = std::fs::read(side(path, "pinpw")).map_err(|_| Failure::new("err.pin_gone"))?;
        let pw = vault_decrypt(&hex_key(&vault_key), &wrapped)?;
        let password = Zeroizing::new(
            String::from_utf8(pw.to_vec()).map_err(|_| Failure::new("err.vault_format"))?,
        );
        let bytes = read_vault_file(path)?;
        let data = decode_vault(&password, &bytes)?;
        if data.username != username {
            return Err(Failure::new("err.vault_format"));
        }
        self.install(Session::new(data, &password)?);
        Ok(())
    }

    /// The duress PIN (spec section 25): the vault, the PIN files and the media folder are
    /// deleted and the answer is the ordinary "wrong PIN". Nothing opens and the network is not
    /// touched.
    fn duress_open(&self, path: &Path) -> Result<(), Failure> {
        let _g = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _ = std::fs::remove_dir_all(media::media_dir(path));
        remove_pin_files(path);
        let mut tmp = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        tmp.push(".tmp");
        for p in [path.to_path_buf(), path.with_file_name(tmp)] {
            remove_quiet(&p);
        }
        // Looks like a wrong attempt: the last count the server gave, else a fresh slot's.
        let left = self.app().pin_left.unwrap_or(4);
        self.write_ghost(path, left);
        Err(self.wrong_left(left))
    }

    /// Leaves a stand-in for the wiped account: a counter and a vault-shaped blob nobody can
    /// open. With it the Unlock screen looks the same after a restart and further tries behave
    /// as they would on a real account (`ghost_unlock`).
    fn write_ghost(&self, vault: &Path, left: u32) {
        let Ok(pw) = aegis_core::random_bytes::<16>() else {
            return;
        };
        let Ok(blob) = vault_encrypt(&hex::encode(&pw), self.cfg.vault_params, b"{}") else {
            return;
        };
        let mut bytes = vec![u8::try_from(left.min(255)).unwrap_or(0)];
        bytes.extend(blob);
        let _ = write_atomic(&side(vault, "ghost"), &bytes);
    }

    /// An attempt on an account that was wiped by the duress PIN. A PIN counts down like a
    /// wrong PIN on the server would, then "PIN gone"; anything else is answered like a wrong
    /// password, by trying it against the stand-in vault.
    pub(super) fn ghost_unlock(&self, path: &Path, secret: &str) -> Option<Failure> {
        let bytes = std::fs::read(side(path, "ghost")).ok()?;
        let (&left, blob) = bytes.split_first()?;
        if is_valid_pin(secret) && left > 0 {
            let left = u32::from(left) - 1;
            let mut out = vec![u8::try_from(left).unwrap_or(0)];
            out.extend_from_slice(blob);
            let _ = write_atomic(&side(path, "ghost"), &out);
            return Some(if left > 0 {
                self.wrong_left(left)
            } else {
                Failure::new("err.pin_gone")
            });
        }
        Some(
            vault_decrypt(secret, blob)
                .err()
                .map_or_else(|| Failure::new("err.vault_format"), Failure::from),
        )
    }

    /// Frees the server slot of the open account's PIN, if it has one and the verifier is
    /// known. Best effort: a slot that cannot be reached expires on the server by itself.
    pub(super) fn pin_free_slot(&self) {
        let Ok((client, path, _)) = self.pin_context() else {
            return;
        };
        let verifier: Option<[u8; 32]> = self
            .app()
            .session
            .as_ref()
            .and_then(|s| hex::decode_array(&s.data.pin_verifier).ok());
        if let (Ok(file), Some(v)) = (Self::read_pin_file(&path), verifier) {
            let _ = client.pin_delete(&file.slot, &v);
        }
    }

    /// True when `path` is a vault that the duress PIN wiped.
    pub(super) fn is_ghost(path: &Path) -> bool {
        !path.exists() && side(path, "ghost").exists()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn side_files_sit_next_to_the_vault() {
        let p = Path::new("data").join("abc.vault");
        assert_eq!(side(&p, "pin"), Path::new("data").join("abc.vault.pin"));
        assert_eq!(side(&p, "pinmeta"), Path::new("data").join("abc.vault.pinmeta"));
    }

    #[test]
    fn meta_holds_only_what_is_needed_to_reach_the_server() {
        let mut st = Settings::new(Lang::En);
        st.endpoint = "http://x".into();
        st.server_key = Some([5; 32]);
        st.server_key_for = "http://x".into();
        let meta = PinMeta::from_settings(&st).expect("pinned");
        let text = serde_json::to_string(&meta).expect("json");
        for k in ["endpoint", "socks5", "tor", "server_key"] {
            assert!(text.contains(k), "{k}");
        }
        assert!(!text.contains("user"));
        let back = meta.settings(Lang::En).expect("settings");
        assert_eq!(back.pinned_key(), Some([5; 32]));
        st.server_key_for = "other".into();
        assert!(PinMeta::from_settings(&st).is_none(), "an unpinned key is never written");
    }
}
