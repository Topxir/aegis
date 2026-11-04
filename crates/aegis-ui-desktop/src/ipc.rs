//! Messages from the page to the application. The enum below is the complete
//! allowlist: anything that does not parse into it is rejected.

use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

pub const MAX_IPC_BYTES: usize = 64 * 1024;

/// Origins the embedded page may report. WebView2 maps the custom scheme to https.
pub const ALLOWED_ORIGINS: [&str; 2] = ["https://aegis.localhost/", "aegis://localhost/"];

pub fn origin_allowed(uri: &str) -> bool {
    ALLOWED_ORIGINS.iter().any(|o| uri.starts_with(*o))
}

fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

#[derive(Deserialize)]
#[serde(tag = "cmd", content = "args", rename_all = "snake_case")]
pub enum Cmd {
    Ready {
        lang: String,
    },
    Ping {},
    AuthTab {
        tab: String,
    },
    SetLang {
        lang: String,
    },
    Create {
        username: String,
        display: String,
        #[serde(deserialize_with = "secret")]
        password: Zeroizing<String>,
        #[serde(deserialize_with = "secret")]
        confirm: Zeroizing<String>,
    },
    Unlock {
        username: String,
        #[serde(deserialize_with = "secret")]
        password: Zeroizing<String>,
    },
    Import {
        path: String,
        #[serde(deserialize_with = "secret")]
        password: Zeroizing<String>,
    },
    Lock {},
    Nav {
        to: String,
        #[serde(default)]
        id: String,
    },
    OpenDialog {
        kind: String,
        #[serde(default)]
        id: String,
    },
    CloseDialog {},
    DismissFlash {},
    AddContact {
        username: String,
    },
    Send {
        text: String,
    },
    Retry {
        id: String,
    },
    SetTtl {
        ttl: u64,
    },
    Verify {
        on: bool,
    },
    AcceptKey {
        id: String,
    },
    DismissKey {
        id: String,
    },
    CreateGroup {
        title: String,
        #[serde(default)]
        members: Vec<String>,
    },
    ResendInvite {
        member: String,
    },
    LeaveGroup {},
    DeleteChat {},
    SaveSettings {
        endpoint: String,
        socks5: String,
        idle_min: String,
        flash: bool,
    },
    TestConn {
        endpoint: String,
        socks5: String,
    },
    UpdateDisplay {
        display: String,
    },
    Export {
        path: String,
    },
    DeleteAccount {
        confirm: String,
    },
}

/// Commands carry passwords, so they never print their contents.
impl core::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Cmd")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    Origin,
    TooLarge,
    Malformed,
}

/// Validates the origin and size, then parses the request body.
pub fn parse(origin: &str, body: &str) -> Result<Cmd, Reject> {
    if !origin_allowed(origin) {
        return Err(Reject::Origin);
    }
    if body.len() > MAX_IPC_BYTES {
        return Err(Reject::TooLarge);
    }
    serde_json::from_str(body).map_err(|_| Reject::Malformed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn unknown_command_is_rejected() {
        let o = "https://aegis.localhost/";
        assert_eq!(
            parse(o, r#"{"cmd":"eval","args":{}}"#).unwrap_err(),
            Reject::Malformed
        );
        assert_eq!(
            parse(o, r#"{"cmd":"read_file","args":{"path":"x"}}"#).unwrap_err(),
            Reject::Malformed
        );
        assert!(parse(o, r#"{"cmd":"lock","args":{}}"#).is_ok());
        assert!(parse(o, r#"{"cmd":"send","args":{"text":"hi"}}"#).is_ok());
        assert!(parse(o, r#"{"cmd":"send","args":{}}"#).is_err());
    }

    #[test]
    fn foreign_origin_and_oversize_are_rejected() {
        let ok = r#"{"cmd":"lock","args":{}}"#;
        assert_eq!(
            parse("https://example.com/", ok).unwrap_err(),
            Reject::Origin
        );
        assert_eq!(
            parse("https://aegis.localhost.evil.com/", ok).unwrap_err(),
            Reject::Origin
        );
        assert_eq!(parse("", ok).unwrap_err(), Reject::Origin);
        let big = format!(
            r#"{{"cmd":"send","args":{{"text":"{}"}}}}"#,
            "a".repeat(MAX_IPC_BYTES)
        );
        assert_eq!(
            parse("https://aegis.localhost/", &big).unwrap_err(),
            Reject::TooLarge
        );
    }
}
