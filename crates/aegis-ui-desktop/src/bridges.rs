//! Tor bridges for networks that block Tor. The built-in lists are the ones Tor Browser ships
//! (`bridges.torproject.org/moat/circumvention/builtin`); custom lines are pasted by the user and
//! checked here before anything reaches the torrc.

use crate::i18n::{tr, Lang};
use crate::render::esc;
use crate::session::Failure;

pub const OBFS4: &[&str] = &[
    "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
    "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
    "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
    "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
    "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
    "obfs4 212.83.43.95:443 BFE712113A72899AD685764B211FACD30FF52C31 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=1",
    "obfs4 212.83.43.74:443 39562501228A4D5E27FCA4C0C81A01EE23AE3EE4 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=1",
];

pub const SNOWFLAKE: &[&str] = &[
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
];

/// Transports lyrebird provides, besides snowflake.
const LYREBIRD: &[&str] = &["meek_lite", "obfs4", "webtunnel"];
pub use crate::tor::LYREBIRD_PATH;

pub const MAX_LINES: usize = 32;
pub const MAX_LINE: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    Snowflake,
    Obfs4,
    Custom,
}

impl Mode {
    pub const ALL: [Mode; 4] = [Mode::Off, Mode::Snowflake, Mode::Obfs4, Mode::Custom];

    pub fn code(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Snowflake => "snowflake",
            Mode::Obfs4 => "obfs4",
            Mode::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.code() == s.trim())
    }

    fn label(self) -> &'static str {
        match self {
            Mode::Off => "conn.bridges_off",
            Mode::Snowflake => "conn.bridges_snowflake",
            Mode::Obfs4 => "conn.bridges_obfs4",
            Mode::Custom => "conn.bridges_custom",
        }
    }
}

fn valid_addr(s: &str) -> bool {
    s.parse::<std::net::SocketAddr>().is_ok_and(|a| a.port() != 0)
}

/// One pasted bridge line in the canonical form `transport addr [fingerprint] [k=v ...]`
/// (without the `Bridge` keyword), or `None` if it is not a bridge line.
pub fn parse_line(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.len() > MAX_LINE || !s.bytes().all(|b| (0x20..0x7f).contains(&b) || b == b'\t') {
        return None;
    }
    let mut toks: Vec<&str> = s.split_whitespace().collect();
    if toks.first().is_some_and(|t| t.eq_ignore_ascii_case("bridge")) {
        toks.remove(0);
    }
    let mut it = toks.iter().copied().peekable();
    let first = it.next()?;
    let transport = if valid_addr(first) {
        None
    } else if LYREBIRD.contains(&first) || first == "snowflake" {
        if !it.next().is_some_and(valid_addr) {
            return None;
        }
        Some(first)
    } else {
        return None;
    };
    if it.peek().is_some_and(|t| t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit())) {
        it.next();
    }
    for t in it {
        let (k, v) = t.split_once('=')?;
        let key_ok = !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if transport.is_none() || !key_ok || v.is_empty() {
            return None;
        }
    }
    Some(toks.join(" "))
}

/// Pasted text: one bridge per line, empty lines and `#` comments skipped. On error the
/// failure detail is the 1-based number of the bad line.
pub fn parse_lines(text: &str) -> Result<Vec<String>, Failure> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some(line) = parse_line(t) else {
            return Err(Failure { key: "err.bridge_line", detail: (i + 1).to_string() });
        };
        if !out.contains(&line) {
            out.push(line);
        }
        if out.len() > MAX_LINES {
            return Err(Failure::new("err.bridges_many"));
        }
    }
    Ok(out)
}

/// Checks a saved form: the mode code and the text stored for custom bridges.
pub fn check(mode: &str, text: &str) -> Result<(Mode, String), Failure> {
    let mode = Mode::parse(mode).ok_or(Failure::new("err.generic"))?;
    let lines = parse_lines(text)?;
    if mode == Mode::Custom && lines.is_empty() {
        return Err(Failure::new("err.bridges_empty"));
    }
    Ok((mode, lines.join("\n")))
}

/// The bridge lines for a mode; custom lines come from `custom`, which was checked on save.
pub fn lines_for(mode: Mode, custom: &str) -> Vec<String> {
    match mode {
        Mode::Off => Vec::new(),
        Mode::Snowflake => SNOWFLAKE.iter().map(|s| (*s).to_owned()).collect(),
        Mode::Obfs4 => OBFS4.iter().map(|s| (*s).to_owned()).collect(),
        Mode::Custom => custom.lines().filter_map(parse_line).take(MAX_LINES).collect(),
    }
}

fn transport(line: &str) -> Option<&str> {
    let t = line.split(' ').next()?;
    (!valid_addr(t)).then_some(t)
}

/// The torrc for the bridge settings. Lines are re-checked here, so a stored value that did not
/// go through `check` still cannot add other options.
pub fn torrc(mode: Mode, custom: &str) -> String {
    let lines = lines_for(mode, custom);
    if lines.is_empty() {
        return String::new();
    }
    let mut rc = String::from("UseBridges 1\n");
    let used = |set: &[&str]| lines.iter().any(|l| transport(l).is_some_and(|t| set.contains(&t)));
    if used(LYREBIRD) {
        rc.push_str(&format!("ClientTransportPlugin {} exec {LYREBIRD_PATH}\n", LYREBIRD.join(",")));
    }
    if used(&["snowflake"]) {
        rc.push_str(&format!("ClientTransportPlugin snowflake exec {LYREBIRD_PATH}\n"));
    }
    for l in &lines {
        rc.push_str("Bridge ");
        rc.push_str(l);
        rc.push('\n');
    }
    rc
}

/// The torrc for a saved account settings.
pub fn torrc_for(st: &crate::model::Settings) -> String {
    torrc(Mode::parse(&st.bridges).unwrap_or(Mode::Off), &st.bridge_lines)
}

/// Suffix for the Tor status line, empty without bridges.
pub fn status_suffix(l: Lang, st: &crate::model::Settings) -> String {
    match Mode::parse(&st.bridges) {
        None | Some(Mode::Off) => String::new(),
        Some(m) => format!(" {} {}", tr(l, "conn.tor_bridge"), tr(l, m.label())),
    }
}

/// The bridge select and the box for pasted lines on the connection page.
pub fn form_html(l: Lang, st: &crate::model::Settings) -> String {
    let cur = Mode::parse(&st.bridges).unwrap_or(Mode::Off);
    let opts: String = Mode::ALL
        .iter()
        .map(|m| {
            format!(
                r#"<option value="{}"{}>{}</option>"#,
                m.code(),
                if *m == cur { " selected" } else { "" },
                esc(tr(l, m.label()))
            )
        })
        .collect();
    format!(
        r#"<label class="f"><span>{}</span><select name="bridges">{opts}</select></label><label class="f"><span>{}</span><textarea name="bridge_lines" rows="3" autocomplete="off" spellcheck="false" placeholder="webtunnel [2001:db8::1]:443 FINGERPRINT url=https://example.com/path">{}</textarea></label><p class="note">{}</p>"#,
        esc(tr(l, "conn.bridges")),
        esc(tr(l, "f.bridge_lines")),
        esc(&st.bridge_lines),
        esc(tr(l, "conn.bridges_note"))
    )
}
