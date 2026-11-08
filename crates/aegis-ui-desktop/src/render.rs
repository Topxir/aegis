//! HTML for each screen region. Every value that did not come from a string
//! literal in this file passes through [`esc`] before it is placed in markup.

use crate::engine::{App, AuthTab, ConnTest, Dialog, Route};
use crate::i18n::{tr, Lang};
use crate::media;
use crate::model::{clean_text, Channel, Chat, Contact, Msg, MsgState, Pending, UNDECRYPTABLE};
use crate::session::{ChatRef, Session, TTL_CHOICES};
use aegis_core::official;
use aegis_core::text::sanitize_display_text;
use serde_json::{json, Value};

mod invite;

/// Escapes text for use in element content and in quoted attribute values.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            '`' => o.push_str("&#96;"),
            _ => o.push(c),
        }
    }
    o
}

/// Display name from the network: sanitized, then escaped.
fn disp(s: &str) -> String {
    esc(&sanitize_display_text(s))
}

fn icon(name: &str) -> &'static str {
    match name {
        "shield" => {
            r#"<svg class="i logo" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l7 3v5.5c0 4.4-3 7.6-7 9.5-4-1.9-7-5.1-7-9.5V6z"/><path d="M9 12l2.2 2.2L15.5 10"/></svg>"#
        }
        "shield-sm" => {
            r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l7 3v5.5c0 4.4-3 7.6-7 9.5-4-1.9-7-5.1-7-9.5V6z"/></svg>"#
        }
        "settings" => {
            r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/></svg>"#
        }
        "lock" => {
            r#"<svg class="i s" viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="1.5"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>"#
        }
        "edit" => {
            r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5H6a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-6"/><path d="M17.5 3.5a1.8 1.8 0 0 1 2.6 2.6L11 15.2 7.5 16l.8-3.5z"/></svg>"#
        }
        "users" => {
            r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="3.2"/><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6"/><path d="M16 5.2a3.2 3.2 0 0 1 0 5.6M18 14.4c1.9.8 3 2.6 3 5.6"/></svg>"#
        }
        "clock" => {
            r#"<svg class="i s" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/></svg>"#
        }
        "burger" => {
            r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>"#
        }
        "search" => {
            r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="M16 16l4 4"/></svg>"#
        }
        "clip" => {
            r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11.5l-8 8a5 5 0 0 1-7-7l8.5-8.5a3.3 3.3 0 0 1 4.7 4.7L9.5 17.3a1.7 1.7 0 0 1-2.4-2.4L15 7"/></svg>"#
        }
        "dots" => {
            r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="5.5" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="12" cy="18.5" r="1.2"/></svg>"#
        }
        "check" => {
            r#"<svg class="i s" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.2 4.2L19 7"/></svg>"#
        }
        "pin" => {
            r#"<svg class="i s" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 4h6l-1 6 3 3H7l3-3zM12 13v7"/></svg>"#
        }
        "user" => {
            r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.5"/><path d="M5 20c0-3.9 3.1-7 7-7s7 3.1 7 7"/></svg>"#
        }
        "mega" => {
            r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 10v4h3l7 4V6L7 10zM17 9.5a3.5 3.5 0 0 1 0 5"/></svg>"#
        }
        "back" => {
            r#"<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M15 5l-7 7 7 7"/></svg>"#
        }
        _ => "",
    }
}

fn ttl_key(t: u64) -> &'static str {
    match t {
        0 => "ttl.off",
        3600 => "ttl.1h",
        86_400 => "ttl.1d",
        _ => "ttl.7d",
    }
}

/// Host part of a server address for display: no scheme, path or credentials.
fn host_of(endpoint: &str) -> String {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    let rest = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let rest = rest.rsplit('@').next().unwrap_or_default();
    rest.chars().take(64).collect()
}

fn contact_name(c: &Contact) -> String {
    let n = sanitize_display_text(&c.name);
    if n.is_empty() {
        c.u.clone()
    } else {
        n
    }
}

fn who(s: &Session, u: &str) -> String {
    s.data
        .contacts
        .get(u)
        .map_or_else(|| u.to_owned(), contact_name)
}

fn time_tag(ms: u64) -> String {
    format!(r#"<time data-ts="{ms}"></time>"#)
}

fn field(l: Lang, name: &str, label: &str, kind: &str, extra: &str) -> String {
    format!(
        r#"<label class="f"><span>{}</span><input name="{name}" type="{kind}" autocomplete="off" spellcheck="false" {extra}></label>"#,
        esc(tr(l, label))
    )
}

fn lang_select(l: Lang) -> String {
    let opt = |c: Lang, label: &str| {
        format!(
            r#"<option value="{}"{}>{}</option>"#,
            c.code(),
            if c == l { " selected" } else { "" },
            label
        )
    };
    format!(
        r#"<select data-change="set_lang" data-key="lang" aria-label="{}">{}{}</select>"#,
        esc(tr(l, "set.language")),
        opt(Lang::En, "English"),
        opt(Lang::Ru, "Русский")
    )
}

// ---- auth ---------------------------------------------------------------------

pub fn auth(app: &App) -> String {
    let l = app.lang();
    let busy = app.busy.is_some();
    let tabs = [
        (AuthTab::Unlock, "unlock", "auth.tab_unlock"),
        (AuthTab::Create, "create", "auth.tab_create"),
        (AuthTab::Import, "import", "auth.tab_import"),
    ];
    let mut h = String::new();
    h.push_str(r#"<div class="auth-bg" aria-hidden="true"><span class="orb o1"></span><span class="orb o2"></span><span class="grid"></span></div><div class="auth-wrap"><section class="hero">"#);
    h.push_str(&format!(
        r#"<div class="brandrow rise r0">{}<span class="brand">AEGIS</span></div>"#,
        icon("shield")
    ));
    h.push_str(&format!(
        r#"<p class="eyebrow mono rise r1">{}</p><h1 class="rise r1">{}</h1><p class="sub rise r2">{}</p><ul class="chips mono rise r3">"#,
        esc(tr(l, "auth.eyebrow")),
        esc(tr(l, "auth.headline")),
        esc(tr(l, "auth.tagline"))
    ));
    for k in ["auth.chip1", "auth.chip2", "auth.chip3"] {
        h.push_str(&format!("<li>{}</li>", esc(tr(l, k))));
    }
    h.push_str(
        r#"</ul></section><div class="card-wrap rise r2"><span class="halo" aria-hidden="true"></span><section class="auth-card"><div class="tabs" role="tablist">"#,
    );
    for (t, id, key) in tabs {
        let sel = t == app.tab;
        h.push_str(&format!(
            r#"<button type="button" role="tab" class="tab{}" aria-selected="{sel}" data-act="auth_tab" data-tab="{id}">{}</button>"#,
            if sel { " on" } else { "" },
            esc(tr(l, key))
        ));
    }
    h.push_str("</div>");
    let dis = if busy { " disabled" } else { "" };
    h.push_str(r#"<div class="form" data-scope>"#);
    match app.tab {
        AuthTab::Unlock => {
            h.push_str(&field(
                l,
                "username",
                "f.username",
                "text",
                r#"class="mono" maxlength="32" autofocus"#,
            ));
            h.push_str(&field(l, "password", "f.secret", "password", ""));
            h.push_str(&format!(
                r#"<button type="button" class="btn primary" data-act="unlock" data-primary{dis}>{}</button>"#,
                esc(tr(l, "auth.unlock"))
            ));
        }
        AuthTab::Create => {
            h.push_str(&field(
                l,
                "username",
                "f.username_new",
                "text",
                r#"class="mono" maxlength="32" autofocus"#,
            ));
            h.push_str(&field(
                l,
                "display",
                "f.display",
                "text",
                r#"maxlength="64""#,
            ));
            h.push_str(&field(l, "password", "f.password_new", "password", ""));
            h.push_str(&field(l, "confirm", "f.confirm", "password", ""));
            h.push_str(&format!(
                r#"<button type="button" class="btn primary" data-act="create" data-primary{dis}>{}</button>"#,
                esc(tr(l, "auth.create"))
            ));
        }
        AuthTab::Import => {
            h.push_str(&field(l, "path", "f.vault_path", "text", r#"autofocus"#));
            h.push_str(&field(l, "password", "f.password", "password", ""));
            h.push_str(&format!(
                r#"<p class="note">{}</p>"#,
                esc(tr(l, "auth.import_note"))
            ));
            h.push_str(&format!(
                r#"<button type="button" class="btn primary" data-act="import" data-primary{dis}>{}</button>"#,
                esc(tr(l, "auth.import"))
            ));
        }
    }
    h.push_str("</div>");
    if let Some(k) = app.busy {
        h.push_str(&format!(
            r#"<p class="status" role="status">{}</p>"#,
            esc(tr(l, k))
        ));
    }
    h.push_str(&flash_html(app, l));
    h.push_str(&format!(
        r#"<p class="note">{}</p>"#,
        esc(tr(l, "auth.pwnote"))
    ));
    h.push_str(&format!(
        r#"</section></div><div class="auth-foot rise r4"><span class="muted">{}</span>{}</div></div>"#,
        esc(tr(l, "auth.foot")),
        lang_select(l)
    ));
    h
}

fn flash_html(app: &App, l: Lang) -> String {
    let Some(f) = &app.flash else {
        return String::new();
    };
    let mut t = tr(l, f.key).to_owned();
    if !f.detail.is_empty() && !f.ok {
        t.push_str(" (");
        t.push_str(&f.detail);
        t.push(')');
    } else if !f.detail.is_empty() {
        t.push_str(": ");
        t.push_str(&f.detail);
    }
    format!(
        r#"<div class="flash {}" role="alert"><span>{}</span><button type="button" class="x" data-act="dismiss_flash" aria-label="{}">&times;</button></div>"#,
        if f.ok { "ok" } else { "bad" },
        esc(&t),
        esc(tr(l, "common.close"))
    )
}

// ---- avatars and small helpers ----------------------------------------------------

/// Key that gives groups and channels a stable avatar.
fn id_key(id: &str) -> [u8; 32] {
    aegis_core::sha256(&[b"aegis ui avatar", id.as_bytes()])
}

/// Default avatar (spec section 17): a 5x5 grayscale grid in a circle with a one-cell margin.
fn avatar(key: &[u8; 32], cls: &str) -> String {
    let a = aegis_core::avatar::Avatar::from_ed_pk(key);
    let mut d = String::new();
    for (r, row) in a.cells.iter().enumerate() {
        for (c, on) in row.iter().enumerate() {
            if *on {
                d.push_str(&format!("M{} {}h1v1h-1z", c + 1, r + 1));
            }
        }
    }
    format!(
        r##"<svg class="av {cls}" viewBox="0 0 7 7" aria-hidden="true"><circle cx="3.5" cy="3.5" r="3.5" fill="#{bg:02x}{bg:02x}{bg:02x}"/><path fill="#{fg:02x}{fg:02x}{fg:02x}" d="{d}"/></svg>"##,
        bg = a.bg,
        fg = a.fg
    )
}

fn contact_key(s: &Session, u: &str) -> [u8; 32] {
    s.data.contacts.get(u).map_or_else(|| id_key(u), |c| c.ed)
}

/// Only the fixed set of effect names ever reaches markup.
fn pfx(s: &str) -> &'static str {
    match s {
        "dust" => "dust",
        "snow" => "snow",
        "embers" => "embers",
        "orbit" => "orbit",
        "rain" => "rain",
        _ => "none",
    }
}

fn pbanner(p: &str, live: bool) -> String {
    format!(
        r#"<div class="pbanner{}" data-particles="{}"></div>"#,
        if live { " live" } else { "" },
        pfx(p)
    )
}

fn fmt_dur(ms: u64) -> String {
    let s = ms / 1000;
    format!("{}:{:02}", s / 60, s % 60)
}

/// Placeholder that the page fills with an image or a video from `/media/<id>`.
fn media_div(app: &App, m: &crate::model::MediaRef, cls: &str) -> String {
    let sid = media::session_id(&app.media_secret, &m.file);
    let extra = if m.video {
        format!(
            r#"<span class="play"></span><span class="dur">{}</span>"#,
            fmt_dur(m.dur_ms)
        )
    } else {
        String::new()
    };
    format!(
        r#"<div class="{cls}" data-media="/media/{sid}" data-w="{}" data-h="{}"{}>{extra}</div>"#,
        m.w,
        m.h,
        if m.video { r#" data-video="1""# } else { "" }
    )
}

fn chan_title(ch: &Channel) -> String {
    sanitize_display_text(&ch.title)
}

fn chan_status(l: Lang, ch: &Channel) -> String {
    if ch.official && official::OFFICIAL_OWNER_ED_PK.is_none() {
        tr(l, "chan.official_off").to_owned()
    } else if ch.official {
        tr(l, "chan.official").to_owned()
    } else if ch.mine {
        format!("{} {}", ch.subs.len(), tr(l, "chan.subs_n"))
    } else {
        tr(l, "chan.channel").to_owned()
    }
}

// ---- sidebar ------------------------------------------------------------------

struct Row {
    last: u64,
    kind: &'static str,
    id: String,
    title: String,
    key: [u8; 32],
    pinned: bool,
    official: bool,
    muted: bool,
    unread: u32,
    chat: ChatRef,
    prev: String,
}

fn preview(s: &Session, l: Lang, chat: &Chat, group: bool) -> String {
    let Some(m) = chat.msgs.last() else {
        return String::new();
    };
    let mut t = if m.text == UNDECRYPTABLE {
        tr(l, "chat.undecryptable").to_owned()
    } else {
        clean_text(&m.text).replace('\n', " ")
    };
    if let Some(mr) = &m.media {
        let label = tr(
            l,
            if mr.video {
                "media.video"
            } else {
                "media.photo"
            },
        );
        t = if t.is_empty() {
            label.to_owned()
        } else {
            format!("{label}, {t}")
        };
    }
    let t: String = t.chars().take(60).collect();
    if m.out {
        format!("{} {t}", tr(l, "list.you"))
    } else if group {
        format!("{}: {t}", sanitize_display_text(&who(s, &m.from)))
    } else {
        t
    }
}

fn rows(app: &App) -> Vec<Row> {
    let (Some(s), l) = (&app.session, app.lang()) else {
        return Vec::new();
    };
    let mut rows: Vec<Row> = Vec::new();
    for (u, chat) in &s.data.dms {
        if let Some(c) = s.data.contacts.get(u) {
            let r = ChatRef::Dm(u.clone());
            rows.push(Row {
                last: chat.last_ms(),
                kind: "dm",
                id: u.clone(),
                title: contact_name(c),
                key: c.ed,
                pinned: s.is_pinned(&r),
                official: false,
                muted: s.is_muted(&r),
                unread: chat.unread,
                prev: preview(s, l, chat, false),
                chat: r,
            });
        }
    }
    for (id, g) in &s.data.groups {
        let r = ChatRef::Group(id.clone());
        rows.push(Row {
            last: g.chat.last_ms(),
            kind: "group",
            id: id.clone(),
            title: sanitize_display_text(&g.title),
            key: id_key(id),
            pinned: s.is_pinned(&r),
            official: false,
            muted: s.is_muted(&r),
            unread: g.chat.unread,
            prev: preview(s, l, &g.chat, true),
            chat: r,
        });
    }
    for (id, ch) in &s.data.channels {
        let r = ChatRef::Channel(id.clone());
        rows.push(Row {
            last: ch.chat.last_ms(),
            kind: "channel",
            id: id.clone(),
            title: chan_title(ch),
            key: id_key(id),
            pinned: s.is_pinned(&r),
            official: ch.official,
            muted: s.is_muted(&r),
            unread: ch.chat.unread,
            prev: preview(s, l, &ch.chat, false),
            chat: r,
        });
    }
    rows.sort_by(|a, b| {
        b.official
            .cmp(&a.official)
            .then_with(|| b.pinned.cmp(&a.pinned))
            .then_with(|| b.last.cmp(&a.last))
            .then_with(|| a.id.cmp(&b.id))
    });
    rows
}

/// Drawer opened by the menu button next to the search field.
pub fn drawer(app: &App) -> String {
    let l = app.lang();
    let Some(s) = &app.session else {
        return String::new();
    };
    let mut h = format!(
        r#"<div class="dr-head">{}<div class="dr-name">{}</div><div class="dr-u mono muted">@{}</div></div><div class="dr-items">"#,
        avatar(&s.ed_public(), "a56"),
        disp(&s.data.display),
        esc(&s.data.username)
    );
    for (to, id, ic, key) in [
        ("account", "profile", "user", "drawer.account"),
        ("new_group", "", "users", "nav.new_group"),
        ("new_channel", "", "mega", "nav.new_channel"),
        ("new_chat", "", "edit", "nav.new_chat"),
        ("contacts", "", "users", "nav.contacts"),
    ] {
        let id = if id.is_empty() {
            String::new()
        } else {
            format!(r#" data-id="{id}""#)
        };
        h.push_str(&format!(
            r#"<button type="button" class="dr-item" data-act="nav" data-to="{to}"{id}>{}<span>{}</span></button>"#,
            icon(ic),
            esc(tr(l, key))
        ));
    }
    h.push_str(&format!(
        r#"<button type="button" class="dr-item" data-act="lock">{}<span>{}</span></button></div>"#,
        icon("lock"),
        esc(tr(l, "nav.lock"))
    ));
    h
}

/// All / Groups / Channels with unread counts. The page draws the sliding underline.
pub fn tabs(app: &App) -> String {
    let l = app.lang();
    if app.session.is_none() {
        return String::new();
    }
    let rs = rows(app);
    let count = |kind: Option<&str>| -> u32 {
        rs.iter()
            .filter(|r| kind.is_none_or(|k| r.kind == k) && !r.muted)
            .map(|r| r.unread)
            .sum()
    };
    let mut h = String::new();
    for (id, key, n) in [
        ("all", "tab.all", count(None)),
        ("group", "tab.groups", count(Some("group"))),
        ("channel", "tab.channels", count(Some("channel"))),
    ] {
        let c = if n > 0 {
            format!(r#"<span class="cnt">{}</span>"#, n.min(99))
        } else {
            String::new()
        };
        h.push_str(&format!(
            r#"<button type="button" class="tb" data-ui="tab" data-tab="{id}"><span>{}</span>{c}</button>"#,
            esc(tr(l, key))
        ));
    }
    h.push_str(r#"<span class="ul"></span>"#);
    h
}

/// Connection row at the bottom of the sidebar. The dot pulses only while connected.
pub fn sidefoot(app: &App) -> String {
    let l = app.lang();
    let Some(s) = &app.session else {
        return String::new();
    };
    let (cls, key) = match app.net_ok {
        Some(true) => ("on", "status.online"),
        Some(false) => ("off", "status.offline"),
        None => ("idle", "status.connecting"),
    };
    format!(
        r#"<span class="conn" title="{0}"><span class="dot {cls}" role="img" aria-label="{0}"></span><span class="host mono">{1}</span></span>"#,
        esc(tr(l, key)),
        esc(&host_of(&s.data.settings.endpoint)),
    )
}

pub fn list(app: &App) -> String {
    let l = app.lang();
    if app.session.is_none() {
        return String::new();
    }
    let rs = rows(app);
    let mut h = String::new();
    for r in rs {
        let active = matches!(&app.route, Route::Chat(c) if *c == r.chat);
        let unread = if r.unread > 0 && !active {
            format!(
                r#"<span class="badge{}">{}</span>"#,
                if r.muted { " dim" } else { "" },
                r.unread.min(99)
            )
        } else if r.pinned {
            icon("pin").to_owned()
        } else {
            String::new()
        };
        let tag = if r.official {
            format!(
                r#"<span class="otag">{}</span>"#,
                esc(tr(l, "chan.official_tag"))
            )
        } else {
            String::new()
        };
        let q = format!("{} {}", r.title, r.id).to_lowercase();
        let time = if r.last == 0 {
            String::new()
        } else {
            format!(r#"<time class="s" data-ts="{}"></time>"#, r.last)
        };
        h.push_str(&format!(
            r#"<button type="button" class="item{}" data-act="nav" data-to="{}" data-id="{}" data-kind="{}" data-q="{}">{}<span class="it-body"><span class="it-top"><span class="it-name">{}{}</span>{}</span><span class="it-bot"><span class="it-prev muted">{}</span>{}</span></span></button>"#,
            if active { " on" } else { "" },
            r.kind,
            esc(&r.id),
            r.kind,
            esc(&q),
            avatar(&r.key, "a48"),
            esc(&r.title),
            tag,
            time,
            esc(&r.prev),
            unread
        ));
    }
    if h.is_empty() {
        h = format!(r#"<p class="empty muted">{}</p>"#, esc(tr(l, "list.empty")));
    }
    h
}

// ---- main pane ----------------------------------------------------------------

fn menu_html(l: Lang, s: &Session, r: &ChatRef) -> String {
    let item = |attrs: &str, key: &str, danger: bool| {
        format!(
            r#"<button type="button" class="mi{}" {attrs}>{}</button>"#,
            if danger { " bad" } else { "" },
            esc(tr(l, key))
        )
    };
    let mut h = String::from(r#"<div class="menu" hidden>"#);
    h.push_str(&item(r#"data-act="info_toggle""#, "menu.info", false));
    h.push_str(&item(
        r#"data-act="pin""#,
        if s.is_pinned(r) {
            "menu.unpin"
        } else {
            "menu.pin"
        },
        false,
    ));
    h.push_str(&item(
        r#"data-act="mute""#,
        if s.is_muted(r) {
            "menu.unmute"
        } else {
            "menu.mute"
        },
        false,
    ));
    h.push_str(&item(
        &format!(
            r#"data-act="open_dialog" data-kind="clear_chat" data-id="{}""#,
            esc(&r.key())
        ),
        "menu.clear",
        false,
    ));
    match r {
        ChatRef::Dm(u) => h.push_str(&item(
            &format!(
                r#"data-act="open_dialog" data-kind="delete_chat" data-id="{}""#,
                esc(u)
            ),
            "contact.delete",
            true,
        )),
        ChatRef::Group(g) => h.push_str(&item(
            &format!(
                r#"data-act="open_dialog" data-kind="leave_group" data-id="{}""#,
                esc(g)
            ),
            "group.leave",
            true,
        )),
        ChatRef::Channel(c) => {
            if !s.data.channels.get(c).is_some_and(|c| c.official) {
                h.push_str(&item(
                    &format!(
                        r#"data-act="open_dialog" data-kind="leave_channel" data-id="{}""#,
                        esc(c)
                    ),
                    "chan.leave",
                    true,
                ));
            }
        }
    }
    h.push_str("</div>");
    h
}

pub fn head(app: &App) -> String {
    let l = app.lang();
    let Some(s) = &app.session else {
        return String::new();
    };
    let plain = |key: &str| format!(r#"<span class="title static">{}</span>"#, esc(tr(l, key)));
    let back = |to: &str, id: &str| {
        format!(
            r#"<button type="button" class="ib" data-act="nav" data-to="{to}" data-id="{}" aria-label="{}">{}</button>"#,
            esc(id),
            esc(tr(l, "common.back")),
            icon("back")
        )
    };
    match &app.route {
        Route::Welcome => plain("main.welcome_title"),
        Route::NewChat => plain("nav.new_chat"),
        Route::NewGroup => plain("nav.new_group"),
        Route::NewChannel => plain("nav.new_channel"),
        Route::Contacts => plain("nav.contacts"),
        Route::Account(_) => plain("drawer.account"),
        Route::Contact(u) => format!("{}{}", back("dm", u), plain("contact.title")),
        Route::GroupInfo(g) => format!("{}{}", back("group", g), plain("group.info")),
        Route::ChannelInfo(c) => format!("{}{}", back("channel", c), plain("chan.manage")),
        Route::Chat(r) => {
            let Some(chat) = s.chat(r) else {
                return String::new();
            };
            let (title, sub, key) = match r {
                ChatRef::Dm(u) => {
                    let c = s.data.contacts.get(u);
                    let name = c.map_or_else(|| u.clone(), contact_name);
                    let v = if c.is_some_and(|c| c.verified) {
                        tr(l, "contact.key_verified")
                    } else {
                        tr(l, "contact.unverified")
                    };
                    (name, v.to_owned(), contact_key(s, u))
                }
                ChatRef::Group(g) => {
                    let grp = s.data.groups.get(g);
                    (
                        grp.map(|g| sanitize_display_text(&g.title))
                            .unwrap_or_default(),
                        format!(
                            "{} {}",
                            grp.map_or(0, |g| g.members.len()),
                            tr(l, "group.members_n")
                        ),
                        id_key(g),
                    )
                }
                ChatRef::Channel(c) => {
                    let ch = s.data.channels.get(c);
                    (
                        ch.map(chan_title).unwrap_or_default(),
                        ch.map(|c| chan_status(l, c)).unwrap_or_default(),
                        id_key(c),
                    )
                }
            };
            let sub = if chat.ttl_s == 0 {
                sub
            } else {
                format!(
                    "{sub} · {}: {}",
                    tr(l, "ttl.short"),
                    tr(l, ttl_key(chat.ttl_s))
                )
            };
            format!(
                r#"<button type="button" class="hmain" data-act="info_toggle">{}<span class="title"><span class="t1">{}</span><span class="t2 muted">{}</span></span></button><div class="hbtns"><button type="button" class="ib" data-ui="msgsearch" title="{3}" aria-label="{3}">{4}</button><span class="menuwrap"><button type="button" class="ib" data-ui="menu" aria-label="{5}">{6}</button>{7}</span></div>"#,
                avatar(&key, "a40"),
                esc(&title),
                esc(&sub),
                esc(tr(l, "chat.search")),
                icon("search"),
                esc(tr(l, "menu.more")),
                icon("dots"),
                menu_html(l, s, r)
            )
        }
    }
}

struct Ctx {
    group: bool,
    channel: bool,
    first: bool,
    last: bool,
}

fn msg_html(app: &App, s: &Session, l: Lang, m: &Msg, c: &Ctx) -> String {
    let mut cls = String::from("m");
    cls.push_str(if m.out { " out" } else { " in" });
    if c.first {
        cls.push_str(" first");
    }
    if c.last {
        cls.push_str(" last");
    }
    if c.channel {
        cls.push_str(" post");
    }
    let text = if m.text == UNDECRYPTABLE {
        tr(l, "chat.undecryptable").to_owned()
    } else {
        clean_text(&m.text)
    };
    let bare = m.media.is_some() && text.is_empty();
    let mut h = format!(
        r#"<div class="{cls}" data-mid="{}" data-ts="{}">"#,
        esc(&m.id),
        m.ts_ms
    );
    if c.group && !m.out {
        if c.last {
            h.push_str(&format!(
                r#"<span class="gav">{}</span>"#,
                avatar(&contact_key(s, &m.from), "a28")
            ));
        } else {
            h.push_str(r#"<span class="gav"></span>"#);
        }
    }
    h.push_str(&format!(
        r#"<div class="bubble{}">"#,
        if bare { " bare" } else { "" }
    ));
    if c.group && !m.out && c.first {
        h.push_str(&format!(
            r#"<div class="who">{}</div>"#,
            disp(&who(s, &m.from))
        ));
    }
    if let Some(mr) = &m.media {
        h.push_str(&media_div(app, mr, "media"));
    }
    if !text.is_empty() {
        h.push_str(&format!(r#"<div class="t">{}</div>"#, esc(&text)));
    }
    h.push_str(&format!(
        r#"<div class="meta{}">"#,
        if bare { " ov" } else { "" }
    ));
    if m.ttl_s != 0 {
        h.push_str(icon("clock"));
    }
    h.push_str(&time_tag(m.ts_ms));
    match (m.out, m.state) {
        (true, MsgState::Sending) => h.push_str(&format!(
            r#"<span class="st">{}</span>"#,
            esc(tr(l, "msg.sending"))
        )),
        (true, MsgState::Failed) => h.push_str(&format!(
            r#"<span class="st bad">{}</span><button type="button" class="link" data-act="retry" data-id="{}">{}</button>"#,
            esc(tr(l, "msg.failed")),
            esc(&m.id),
            esc(tr(l, "msg.retry"))
        )),
        (true, _) => h.push_str(&format!(r#"<span class="tick">{}</span>"#, icon("check"))),
        _ => {}
    }
    h.push_str("</div></div></div>");
    h
}

fn key_banner(l: Lang, c: &Contact, with_accept: bool) -> String {
    let mut h = format!(
        r#"<div class="banner" role="alert"><p>{} <strong>{}</strong> (@{}). {}</p><div class="row">"#,
        esc(tr(l, "warn.key_changed")),
        disp(&c.name),
        esc(&c.u),
        esc(tr(
            l,
            if c.changed.as_ref().is_some_and(|x| x.via_dm) {
                "warn.compare"
            } else {
                "warn.group_only"
            }
        )),
    );
    h.push_str(&format!(
        r#"<button type="button" class="btn ghost" data-act="nav" data-to="contact" data-id="{}">{}</button>"#,
        esc(&c.u),
        esc(tr(l, "warn.view"))
    ));
    if with_accept {
        h.push_str(&format!(
            r#"<button type="button" class="btn" data-act="accept_key" data-id="{}">{}</button>"#,
            esc(&c.u),
            esc(tr(l, "warn.accept"))
        ));
    }
    h.push_str(&format!(
        r#"<button type="button" class="btn ghost" data-act="dismiss_key" data-id="{}">{}</button></div></div>"#,
        esc(&c.u),
        esc(tr(l, "warn.dismiss"))
    ));
    h
}

pub fn msgs(app: &App) -> String {
    let l = app.lang();
    let (Some(s), Route::Chat(r)) = (&app.session, &app.route) else {
        return String::new();
    };
    let Some(chat) = s.chat(r) else {
        return String::new();
    };
    let mut h = String::new();
    match r {
        ChatRef::Dm(u) => {
            if let Some(c) = s.data.contacts.get(u).filter(|c| c.changed.is_some()) {
                h.push_str(&key_banner(
                    l,
                    c,
                    c.changed.as_ref().is_some_and(|x| x.via_dm),
                ));
            }
        }
        ChatRef::Group(g) => {
            if let Some(grp) = s.data.groups.get(g) {
                for u in &grp.members {
                    if let Some(c) = s.data.contacts.get(u).filter(|c| c.changed.is_some()) {
                        h.push_str(&key_banner(
                            l,
                            c,
                            c.changed.as_ref().is_some_and(|x| x.via_dm),
                        ));
                    }
                }
            }
        }
        ChatRef::Channel(id) => {
            if s.data.channels.get(id).is_some_and(|c| c.warn) {
                h.push_str(&format!(
                    r#"<p class="sys warnq">{}</p>"#,
                    esc(tr(l, "chan.key_changed"))
                ));
            }
        }
    }
    if chat.msgs.is_empty() {
        h.push_str(&format!(
            r#"<p class="empty muted">{}</p>"#,
            esc(tr(l, "chat.empty"))
        ));
    }
    if chat.ttl_s != 0 {
        h.push_str(&format!(
            r#"<p class="sys">{}</p>"#,
            esc(tr(l, "chat.ttl_on"))
        ));
    }
    let group = matches!(r, ChatRef::Group(_));
    let channel = matches!(r, ChatRef::Channel(_));
    let n = chat.msgs.len();
    for (i, m) in chat.msgs.iter().enumerate() {
        let same = |o: &Msg| o.from == m.from && o.out == m.out;
        let ctx = Ctx {
            group,
            channel,
            first: channel || i == 0 || !chat.msgs.get(i - 1).is_some_and(same),
            last: channel || i + 1 == n || !chat.msgs.get(i + 1).is_some_and(same),
        };
        h.push_str(&msg_html(app, s, l, m, &ctx));
    }
    h
}

/// True when the composer is shown; subscribers of a channel get a bar instead.
pub fn compose(app: &App) -> bool {
    let (Some(s), Route::Chat(r)) = (&app.session, &app.route) else {
        return false;
    };
    match r {
        ChatRef::Channel(c) => s.data.channels.get(c).is_some_and(|c| c.mine),
        _ => true,
    }
}

pub fn bar(app: &App) -> String {
    let l = app.lang();
    let (Some(s), Route::Chat(r @ ChatRef::Channel(_))) = (&app.session, &app.route) else {
        return String::new();
    };
    if compose(app) {
        return String::new();
    }
    format!(
        r#"<button type="button" class="mutebar" data-act="mute">{}</button>"#,
        esc(tr(
            l,
            if s.is_muted(r) {
                "menu.unmute"
            } else {
                "menu.mute"
            }
        ))
    )
}

/// Right-hand panel for the open chat.
pub fn info(app: &App) -> String {
    let l = app.lang();
    let (Some(s), Route::Chat(r), true) = (&app.session, &app.route, app.info) else {
        return String::new();
    };
    let Some(chat) = s.chat(r) else {
        return String::new();
    };
    let (name, sub, about, particles, key) = match r {
        ChatRef::Dm(u) => {
            let c = s.data.contacts.get(u);
            (
                c.map_or_else(|| u.clone(), contact_name),
                format!("@{u}"),
                c.map(|c| clean_text(&c.about)).unwrap_or_default(),
                c.map(|c| c.particles.clone()).unwrap_or_default(),
                contact_key(s, u),
            )
        }
        ChatRef::Group(g) => {
            let grp = s.data.groups.get(g);
            (
                grp.map(|g| sanitize_display_text(&g.title))
                    .unwrap_or_default(),
                format!(
                    "{} {}",
                    grp.map_or(0, |g| g.members.len()),
                    tr(l, "group.members_n")
                ),
                String::new(),
                String::new(),
                id_key(g),
            )
        }
        ChatRef::Channel(c) => {
            let ch = s.data.channels.get(c);
            (
                ch.map(chan_title).unwrap_or_default(),
                ch.map(|c| chan_status(l, c)).unwrap_or_default(),
                ch.map(|c| clean_text(&c.about)).unwrap_or_default(),
                String::new(),
                id_key(c),
            )
        }
    };
    let mut h = format!(
        r#"<div class="in-bar"><button type="button" class="ib" data-act="info_toggle" aria-label="{}">&times;</button></div><div class="in-top">{}<div class="in-av">{}</div></div><div class="in-body"><h2>{}</h2><p class="muted">{}</p>"#,
        esc(tr(l, "common.close")),
        pbanner(&particles, false),
        avatar(&key, "a96"),
        esc(&name),
        esc(&sub)
    );
    if !about.is_empty() {
        h.push_str(&format!(r#"<p class="about">{}</p>"#, esc(&about)));
    }
    let btn = |attrs: &str, key: &str, danger: bool| {
        format!(
            r#"<button type="button" class="btn ghost{}" {attrs}>{}</button>"#,
            if danger { " danger" } else { "" },
            esc(tr(l, key))
        )
    };
    h.push_str(r#"<div class="acts">"#);
    h.push_str(&btn(
        r#"data-act="mute""#,
        if s.is_muted(r) {
            "menu.unmute"
        } else {
            "menu.mute"
        },
        false,
    ));
    match r {
        ChatRef::Dm(u) => h.push_str(&btn(
            &format!(r#"data-act="nav" data-to="contact" data-id="{}""#, esc(u)),
            "warn.view",
            false,
        )),
        ChatRef::Group(g) => h.push_str(&btn(
            &format!(
                r#"data-act="nav" data-to="group_info" data-id="{}""#,
                esc(g)
            ),
            "group.info",
            false,
        )),
        ChatRef::Channel(c) => {
            if s.data.channels.get(c).is_some_and(|c| c.mine) {
                h.push_str(&btn(
                    &format!(
                        r#"data-act="nav" data-to="channel_info" data-id="{}""#,
                        esc(c)
                    ),
                    "chan.manage",
                    false,
                ));
            }
        }
    }
    h.push_str(&btn(
        &format!(
            r#"data-act="open_dialog" data-kind="clear_chat" data-id="{}""#,
            esc(&r.key())
        ),
        "menu.clear",
        true,
    ));
    h.push_str("</div>");
    if !matches!(r, ChatRef::Channel(_)) {
        let opts: String = TTL_CHOICES
            .iter()
            .map(|&t| {
                format!(
                    r#"<option value="{t}"{}>{}</option>"#,
                    if t == chat.ttl_s { " selected" } else { "" },
                    esc(tr(l, ttl_key(t)))
                )
            })
            .collect();
        h.push_str(&format!(
            r#"<label class="ttl">{}<span>{}</span><select data-change="set_ttl" data-key="ttl" aria-label="{1}">{}</select></label>"#,
            icon("clock"),
            esc(tr(l, "ttl.label")),
            opts
        ));
    }
    let shared: Vec<&crate::model::MediaRef> = chat
        .msgs
        .iter()
        .rev()
        .filter_map(|m| m.media.as_ref())
        .take(12)
        .collect();
    if !shared.is_empty() {
        h.push_str(&format!(
            r#"<h3>{}</h3><div class="grid">"#,
            esc(tr(l, "info.media"))
        ));
        for m in shared {
            h.push_str(&media_div(app, m, "thumb"));
        }
        h.push_str("</div>");
    }
    h.push_str("</div>");
    h
}

// ---- pages ----------------------------------------------------------------------

fn page_welcome(l: Lang) -> String {
    format!(
        r#"<div class="empty-main"><p>{}</p><p class="note">{}</p></div>"#,
        esc(tr(l, "main.pick")),
        esc(tr(l, "main.e2ee"))
    )
}

fn page_new_chat(l: Lang) -> String {
    let add_button = format!(
        r#"<button type="button" class="btn primary" data-act="add_contact" data-primary>{}</button>"#,
        esc(tr(l, "newchat.add"))
    );
    format!(
        r#"<div class="card" data-scope><h2>{}</h2><p class="note">{}</p>{}<div class="row">{}</div></div>"#,
        esc(tr(l, "nav.new_chat")),
        esc(tr(l, "newchat.note")),
        field(
            l,
            "username",
            "f.contact_username",
            "text",
            r#"class="mono" maxlength="32" autofocus"#
        ),
        add_button
    )
}

fn member_checks(l: Lang, s: &Session, skip: &[String]) -> String {
    let mut h = format!(
        r#"<div class="f"><span>{}</span><div class="checks">"#,
        esc(tr(l, "newgroup.members"))
    );
    let mut any = false;
    for c in s.data.contacts.values().filter(|c| !skip.contains(&c.u)) {
        any = true;
        h.push_str(&format!(
            r#"<label class="chk"><input type="checkbox" name="members[]" value="{}">{}<span>{} <span class="muted">@{}</span></span></label>"#,
            esc(&c.u),
            avatar(&c.ed, "a28"),
            disp(&c.name),
            esc(&c.u)
        ));
    }
    if !any {
        h.push_str(&format!(
            r#"<p class="muted">{}</p>"#,
            esc(tr(l, "newgroup.no_contacts"))
        ));
    }
    h.push_str("</div></div>");
    h
}

fn page_new_group(l: Lang, s: &Session) -> String {
    format!(
        r#"<div class="card" data-scope><h2>{}</h2><p class="note">{}</p>{}{}<div class="row"><button type="button" class="btn primary" data-act="create_group" data-primary>{}</button></div></div>"#,
        esc(tr(l, "nav.new_group")),
        esc(tr(l, "newgroup.note")),
        field(
            l,
            "title",
            "f.group_title",
            "text",
            r#"maxlength="64" autofocus"#
        ),
        member_checks(l, s, &[]),
        esc(tr(l, "newgroup.create"))
    )
}

fn page_new_channel(l: Lang, s: &Session) -> String {
    format!(
        r#"<div class="card" data-scope><h2>{}</h2><p class="note">{}</p>{}{}{}<div class="row"><button type="button" class="btn primary" data-act="create_channel" data-primary>{}</button></div></div>"#,
        esc(tr(l, "nav.new_channel")),
        esc(tr(l, "newchannel.note")),
        field(
            l,
            "title",
            "f.channel_title",
            "text",
            r#"maxlength="64" autofocus"#
        ),
        field(l, "about", "f.about", "text", r#"maxlength="140""#),
        member_checks(l, s, &[]),
        esc(tr(l, "newchannel.create"))
    )
}

fn page_channel_info(l: Lang, s: &Session, cid: &str) -> String {
    let Some(ch) = s.data.channels.get(cid) else {
        return String::new();
    };
    let mut h = format!(
        r#"<div class="card"><div class="ci-head">{}<div><h2>{}</h2><p class="muted">{}</p></div></div>"#,
        avatar(&id_key(cid), "a56"),
        esc(&chan_title(ch)),
        esc(&chan_status(l, ch))
    );
    if !ch.about.is_empty() {
        h.push_str(&format!(
            r#"<p class="about">{}</p>"#,
            esc(&clean_text(&ch.about))
        ));
    }
    if ch.mine {
        h.push_str(&format!(
            r#"<p class="note">{} {}/{}</p>"#,
            esc(tr(l, "chan.subs_n")),
            ch.subs.len(),
            aegis_core::channel::MAX_SUBSCRIBERS
        ));
        h.push_str(&format!(
            r#"<div data-scope>{}<div class="row"><button type="button" class="btn" data-act="invite_channel" data-primary>{}</button></div></div>"#,
            member_checks(l, s, &ch.subs),
            esc(tr(l, "chan.invite"))
        ));
    }
    if !ch.official {
        h.push_str(&format!(
            r#"<div class="row"><button type="button" class="btn danger" data-act="open_dialog" data-kind="leave_channel" data-id="{}">{}</button></div>"#,
            esc(cid),
            esc(tr(l, if ch.mine { "chan.delete" } else { "chan.leave" }))
        ));
    }
    h.push_str("</div>");
    h
}

fn page_contacts(l: Lang, s: &Session) -> String {
    let mut h = format!(
        r#"<div class="card"><h2>{}</h2><ul class="members">"#,
        esc(tr(l, "nav.contacts"))
    );
    for c in s.data.contacts.values() {
        h.push_str(&format!(
            r#"<li>{}<span class="cname">{} <span class="muted">@{}</span></span><span class="cbtns"><button type="button" class="link" data-act="nav" data-to="dm" data-id="{2}">{}</button><button type="button" class="link" data-act="nav" data-to="contact" data-id="{2}">{}</button></span></li>"#,
            avatar(&c.ed, "a36"),
            disp(&contact_name(c)),
            esc(&c.u),
            esc(tr(l, "contacts.chat")),
            esc(tr(l, "warn.view"))
        ));
    }
    if s.data.contacts.is_empty() {
        h.push_str(&format!(
            r#"<li class="muted">{}</li>"#,
            esc(tr(l, "newgroup.no_contacts"))
        ));
    }
    h.push_str("</ul></div>");
    for p in &s.data.pending {
        h.push_str(&request_card(l, p));
    }
    h
}

/// Spaced groups of four hex digits, for comparing a key by eye.
fn key_fingerprint(x: &[u8; 32]) -> String {
    let hx = aegis_core::hex::encode(x);
    hx.as_bytes()
        .chunks(4)
        .take(8)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A message from a key that is not a contact: nothing is trusted until the user chooses.
fn request_card(l: Lang, p: &Pending) -> String {
    let x = aegis_core::hex::encode(&p.x);
    format!(
        r#"<div class="card" data-scope><h2>{}</h2><p class="note">{}</p><p class="safety" aria-label="{}">{}</p><label class="fld"><span>{}</span><input name="username" type="text" autocomplete="off" spellcheck="false" maxlength="32"></label><div class="row"><button type="button" class="btn primary" data-act="accept_request" data-x="{}">{}</button><button type="button" class="btn ghost" data-act="block_request" data-x="{}">{}</button></div></div>"#,
        esc(tr(l, "req.title")),
        esc(tr(l, "req.note")),
        esc(tr(l, "req.fingerprint")),
        esc(&key_fingerprint(&p.x)),
        esc(tr(l, "req.username")),
        esc(&x),
        esc(tr(l, "req.accept")),
        esc(&x),
        esc(tr(l, "req.block"))
    )
}

fn page_contact(l: Lang, s: &Session, u: &str) -> String {
    let Some(c) = s.data.contacts.get(u) else {
        return String::new();
    };
    let sn = s.safety_number(u).unwrap_or_default();
    let mut h = format!(
        r#"<div class="card pcard">{}<div class="pav">{}</div><h2>{}</h2><p class="muted">@{}</p>"#,
        pbanner(&c.particles, false),
        avatar(&c.ed, "a72"),
        disp(&c.name),
        esc(&c.u)
    );
    let about = clean_text(&c.about);
    if !about.is_empty() {
        h.push_str(&format!(r#"<p class="about">{}</p>"#, esc(&about)));
    }
    if let Some(ch) = &c.changed {
        h.push_str(&format!(
            r#"<div class="banner"><p>{}</p><div class="row">"#,
            esc(tr(l, "warn.key_changed"))
        ));
        if ch.via_dm {
            h.push_str(&format!(
                r#"<button type="button" class="btn" data-act="accept_key" data-id="{}">{}</button>"#,
                esc(&c.u),
                esc(tr(l, "warn.accept"))
            ));
        }
        h.push_str(&format!(
            r#"<button type="button" class="btn ghost" data-act="dismiss_key" data-id="{}">{}</button></div></div>"#,
            esc(&c.u),
            esc(tr(l, "warn.dismiss"))
        ));
    }
    h.push_str(&format!(
        r#"<h3>{}</h3><p class="safety" aria-label="{}">{}</p><p class="note">{}</p>"#,
        esc(tr(l, "contact.safety")),
        esc(tr(l, "contact.safety")),
        esc(&sn),
        esc(tr(l, "contact.safety_note"))
    ));
    h.push_str(&format!(
        r#"<label class="chk"><input type="checkbox" data-change="verify" data-key="on"{}><span>{}</span></label>"#,
        if c.verified { " checked" } else { "" },
        esc(tr(l, "contact.mark_verified"))
    ));
    h.push_str(&format!(
        r#"<div class="row"><button type="button" class="btn danger" data-act="open_dialog" data-kind="delete_chat" data-id="{}">{}</button></div></div>"#,
        esc(&c.u),
        esc(tr(l, "contact.delete"))
    ));
    h
}

fn page_group_info(l: Lang, s: &Session, gid: &str) -> String {
    let Some(g) = s.data.groups.get(gid) else {
        return String::new();
    };
    let mut h = format!(
        r#"<div class="card"><div class="ci-head">{}<div><h2>{}</h2><p class="muted">{} {}</p></div></div><ul class="members">"#,
        avatar(&id_key(gid), "a56"),
        esc(&sanitize_display_text(&g.title)),
        g.members.len(),
        esc(tr(l, "group.members_n"))
    );
    for u in &g.members {
        let me = *u == s.data.username;
        let tags = format!(
            "{}{}",
            if me { tr(l, "group.you") } else { "" },
            if *u == g.creator {
                format!(" {}", tr(l, "group.creator"))
            } else {
                String::new()
            }
        );
        h.push_str(&format!(
            r#"<li>{}<span class="cname">{} <span class="muted">@{}</span></span><span class="muted">{}</span>"#,
            avatar(&if me { s.ed_public() } else { contact_key(s, u) }, "a28"),
            disp(&who(s, u)),
            esc(u),
            esc(tags.trim())
        ));
        if !me && s.data.contacts.contains_key(u) {
            h.push_str(&format!(
                r#"<button type="button" class="link" data-act="resend_invite" data-member="{}">{}</button>"#,
                esc(u),
                esc(tr(l, "group.resend"))
            ));
        }
        h.push_str("</li>");
    }
    h.push_str(&format!(
        r#"</ul><p class="note">{}</p><div class="row"><button type="button" class="btn danger" data-act="open_dialog" data-kind="leave_group" data-id="{}">{}</button></div></div>"#,
        esc(tr(l, "group.leave_note")),
        esc(gid),
        esc(tr(l, "group.leave"))
    ));
    h
}

fn tor_html(app: &App, l: Lang, on: bool) -> String {
    use crate::tor::Status;
    let (class, text) = match (&app.tor, on) {
        (_, false) => ("status", tr(l, "conn.tor_off").to_owned()),
        (Status::Ready, _) => ("status okc", tr(l, "conn.tor_ready").to_owned()),
        (Status::Starting(p), _) => ("status", format!("{} {p}%", tr(l, "conn.tor_start"))),
        (Status::Failed(e), _) => ("status badc", format!("{} {e}", tr(l, "conn.tor_failed"))),
        (Status::Off, _) => ("status", format!("{} 0%", tr(l, "conn.tor_start"))),
    };
    format!(r#"<p class="{class}">{}</p>"#, esc(&text))
}

fn conn_html(app: &App, l: Lang) -> String {
    match &app.conn {
        None => String::new(),
        Some(ConnTest::Running) => {
            format!(r#"<p class="status">{}</p>"#, esc(tr(l, "conn.running")))
        }
        Some(ConnTest::Reachable) => {
            format!(r#"<p class="status okc">{}</p>"#, esc(tr(l, "conn.ok")))
        }
        Some(ConnTest::Failed(f)) => format!(
            r#"<p class="status badc">{} {}</p>"#,
            esc(tr(l, f.key)),
            esc(&f.detail)
        ),
    }
}

fn sec_key(sec: &str) -> &'static str {
    match sec {
        "profile" => "acct.profile",
        "privacy" => "acct.privacy",
        "notifications" => "acct.notifications",
        "appearance" => "acct.appearance",
        "connection" => "acct.connection",
        _ => "acct.data",
    }
}

fn check(name: &str, label: &str, on: bool, disabled: bool) -> String {
    format!(
        r#"<label class="chk"><input type="checkbox" name="{name}"{}{}><span>{}</span></label>"#,
        if on { " checked" } else { "" },
        if disabled { " disabled" } else { "" },
        esc(label)
    )
}

/// The PIN section of the privacy page.
fn pin_card(app: &App, l: Lang) -> String {
    let pin_attrs = r#"inputmode="numeric" maxlength="6""#;
    let dis = if app.busy.is_some() { " disabled" } else { "" };
    let mut h = format!(r#"<section class="card" data-scope><h2>{}</h2>"#, esc(tr(l, "priv.pin")));
    if !app.pin_on {
        h.push_str(&field(l, "pin", "f.pin", "password", pin_attrs));
        h.push_str(&field(l, "confirm", "f.pin_confirm", "password", pin_attrs));
        h.push_str(&format!(
            r#"<div class="row"><button type="button" class="btn primary" data-act="pin_set"{dis}>{}</button></div>"#,
            esc(tr(l, "priv.set_pin"))
        ));
    } else {
        h.push_str(&format!(r#"<p class="note">{}</p>"#, esc(tr(l, "priv.pin_on"))));
        h.push_str(&field(l, "pin", "f.pin_current", "password", pin_attrs));
        h.push_str(&field(l, "duress", "f.duress", "password", pin_attrs));
        h.push_str(&format!(
            r#"<div class="row"><button type="button" class="btn" data-act="duress_set"{dis}>{}</button><button type="button" class="btn danger" data-act="pin_remove"{dis}>{}</button>"#,
            esc(tr(l, "priv.set_duress")),
            esc(tr(l, "priv.remove_pin"))
        ));
        if app.duress_on {
            h.push_str(&format!(
                r#"<button type="button" class="btn" data-act="duress_clear"{dis}>{}</button>"#,
                esc(tr(l, "priv.clear_duress"))
            ));
        }
        h.push_str("</div>");
        if app.duress_on {
            h.push_str(&format!(r#"<p class="note">{}</p>"#, esc(tr(l, "priv.duress_on"))));
        }
    }
    h.push_str(&format!(r#"<p class="note">{}</p></section>"#, esc(tr(l, "priv.pin_note"))));
    h
}

fn cover_options(l: Lang, cur: u8) -> String {
    [(0u8, "off", "conn.cover_off"), (1, "std", "conn.cover_std"), (2, "high", "conn.cover_high")]
        .iter()
        .map(|(n, v, k)| {
            format!(
                r#"<option value="{v}"{}>{}</option>"#,
                if *n == cur { " selected" } else { "" },
                esc(tr(l, k))
            )
        })
        .collect()
}

fn save_row(l: Lang, act: &str) -> String {
    format!(
        r#"<div class="row"><button type="button" class="btn primary" data-act="{act}" data-primary>{}</button></div>"#,
        esc(tr(l, "common.save"))
    )
}

fn page_account(app: &App, s: &Session, sec: &str) -> String {
    let l = app.lang();
    let st = &s.data.settings;
    let val = |v: &str| format!(r#"value="{}""#, esc(v));
    let mut nav = String::new();
    for id in crate::engine::SECTIONS {
        nav.push_str(&format!(
            r#"<button type="button" class="cn{}" data-act="nav" data-to="account" data-id="{id}">{}</button>"#,
            if id == sec { " on" } else { "" },
            esc(tr(l, sec_key(id)))
        ));
    }
    nav.push_str(&format!(
        r#"<button type="button" class="cn" data-act="lock">{}</button>"#,
        esc(tr(l, "nav.lock"))
    ));
    let body = match sec {
        "profile" => {
            let cur = pfx(&s.data.particles);
            let opts: String = ["none", "dust", "snow", "embers", "orbit", "rain"]
                .iter()
                .map(|p| {
                    format!(
                        r#"<option value="{p}"{}>{}</option>"#,
                        if *p == cur { " selected" } else { "" },
                        esc(tr(l, &format!("pfx.{p}")))
                    )
                })
                .collect();
            format!(
                r#"<section class="card pcard" data-scope>{}<div class="pav">{}</div><h2>{}</h2><p class="muted">@{}</p>{}{}<label class="f"><span>{}</span><select name="particles" data-live="particles">{}</select></label><p class="note">{}</p>{}</section>"#,
                pbanner(cur, true),
                avatar(&s.ed_public(), "a72"),
                disp(&s.data.display),
                esc(&s.data.username),
                field(
                    l,
                    "display",
                    "f.display",
                    "text",
                    &format!(r#"maxlength="64" {}"#, val(&s.data.display))
                ),
                field(
                    l,
                    "about",
                    "f.about",
                    "text",
                    &format!(r#"maxlength="140" {}"#, val(&s.data.about))
                ),
                esc(tr(l, "f.particles")),
                opts,
                esc(tr(l, "profile.note")),
                save_row(l, "save_profile")
            )
        }
        "privacy" => format!(
            r#"<section class="card" data-scope><h2>{}</h2>{}{}<p class="note">{}</p>{}</section>{}{}"#,
            esc(tr(l, "acct.privacy")),
            field(
                l,
                "idle_min",
                "f.idle",
                "text",
                &format!(
                    r#"inputmode="numeric" maxlength="4" {}"#,
                    val(&st.idle_min.to_string())
                )
            ),
            check("protect", tr(l, "priv.protect"), st.protect, false),
            esc(tr(l, "priv.protect_note")),
            save_row(l, "save_privacy"),
            invite::hidden_card(st, l),
            pin_card(app, l)
        ),
        "notifications" => format!(
            r#"<section class="card" data-scope><h2>{}</h2>{}{}<p class="note">{}</p>{}</section>"#,
            esc(tr(l, "acct.notifications")),
            check("on", tr(l, "notify.on"), st.flash_taskbar, false),
            check("name", tr(l, "notify.name"), st.notify_name, false),
            esc(tr(l, "notify.note")),
            save_row(l, "save_notify")
        ),
        "appearance" => format!(
            r#"<section class="card"><h2>{}</h2><div class="row">{}</div><p class="note">{}</p></section>"#,
            esc(tr(l, "set.language")),
            lang_select(l),
            esc(tr(l, "set.lang_note"))
        ),
        "connection" => {
            let socks = format!(r#"placeholder="127.0.0.1:9050" {}"#, val(&st.socks5));
            let cover_field = format!(
                r#"{}<label class="f"><span>{}</span><select name="cover">{}</select></label>"#,
                check("tor", tr(l, "conn.tor"), st.tor, false),
                esc(tr(l, "conn.cover")),
                cover_options(l, st.cover)
            );
            let status_html = format!("{}{}", tor_html(app, l, st.tor), conn_html(app, l));
            format!(
            r#"<section class="card" data-scope><h2>{}</h2>{}{}<p class="note">{}</p>{}<p class="note">{}</p><div class="row"><button type="button" class="btn primary" data-act="save_connection" data-primary>{}</button><button type="button" class="btn" data-act="test_conn">{}</button></div>{}</section>"#,
            esc(tr(l, "acct.connection")),
            field(l, "endpoint", "f.endpoint", "text", &val(&st.endpoint)),
            field(
                l,
                "socks5",
                "f.socks5",
                "text",
                &socks
            ),
            esc(tr(l, "set.conn_note")),
            cover_field,
            esc(&[tr(l, "conn.tor_note"), tr(l, "conn.cover_note")].join(" ")),
            esc(tr(l, "common.save")),
            esc(tr(l, "set.test")),
            status_html
            )
        }
        _ => format!(
            r#"<section class="card" data-scope><h2>{}</h2><p class="note">{}</p>{}<div class="row"><button type="button" class="btn" data-act="export" data-primary>{}</button></div></section><section class="card"><h2>{}</h2><p class="note">{}</p><div class="row"><button type="button" class="btn danger" data-act="open_dialog" data-kind="delete_account">{}</button></div></section><section class="card"><h2>{}</h2><p class="note">{}</p><p class="note">{}</p><p class="note">{}</p></section>"#,
            esc(tr(l, "set.backup")),
            esc(tr(l, "set.backup_note")),
            field(
                l,
                "path",
                "f.export_path",
                "text",
                r#"placeholder="C:\Users\...\backup.vault""#
            ),
            esc(tr(l, "set.export")),
            esc(tr(l, "set.danger")),
            esc(tr(l, "set.delete_note")),
            esc(tr(l, "set.delete")),
            esc(tr(l, "set.about")),
            esc(tr(l, "set.about_text")),
            esc(tr(l, "main.e2ee")),
            esc(tr(l, "set.about_font"))
        ),
    };
    format!(
        r#"<div class="cab"><div class="cabnav">{nav}</div><div class="cabbody">{body}</div></div>"#
    )
}

pub fn page(app: &App) -> String {
    let l = app.lang();
    let Some(s) = &app.session else {
        return String::new();
    };
    match &app.route {
        Route::Chat(_) => String::new(),
        Route::Welcome => page_welcome(l),
        Route::NewChat => page_new_chat(l) + &invite::cards(app, l),
        Route::NewGroup => page_new_group(l, s),
        Route::NewChannel => page_new_channel(l, s),
        Route::ChannelInfo(c) => page_channel_info(l, s, c),
        Route::Contacts => page_contacts(l, s),
        Route::Contact(u) => page_contact(l, s, u),
        Route::GroupInfo(g) => page_group_info(l, s, g),
        Route::Account(sec) => page_account(app, s, sec),
    }
}

pub fn overlay(app: &App) -> String {
    let l = app.lang();
    if app.key_alert && app.session.is_some() {
        if app.key_reset_ask {
            return format!(
                r#"<div class="scrim"></div><div class="dialog" role="alertdialog" aria-modal="true"><h2>{}</h2><p>{}</p><div class="row end"><button type="button" class="btn" data-act="key_reset" data-step="cancel" data-primary>{}</button><button type="button" class="btn danger" data-act="key_reset" data-step="do">{}</button></div></div>"#,
                esc(tr(l, "key.reset_title")),
                esc(tr(l, "key.reset_warn")),
                esc(tr(l, "common.cancel")),
                esc(tr(l, "key.reset_do"))
            );
        }
        return format!(
            r#"<div class="scrim"></div><div class="dialog" role="alertdialog" aria-modal="true"><h2>{}</h2><p>{}</p><div class="row end"><button type="button" class="btn" data-act="key_reset" data-step="ask">{}</button><button type="button" class="btn danger" data-act="lock" data-primary>{}</button></div></div>"#,
            esc(tr(l, "key.title")),
            esc(tr(l, "key.text")),
            esc(tr(l, "key.reset")),
            esc(tr(l, "key.lock"))
        );
    }
    let Some(s) = &app.session else {
        return String::new();
    };
    let Some(d) = &app.dialog else {
        return String::new();
    };
    let (title, text, act, label, input) = match d {
        Dialog::DeleteChat(u) => (
            tr(l, "dlg.delete_chat"),
            format!("{} @{}", tr(l, "dlg.delete_chat_text"), u),
            "delete_chat",
            tr(l, "contact.delete"),
            String::new(),
        ),
        Dialog::LeaveGroup(_) => (
            tr(l, "group.leave"),
            tr(l, "group.leave_note").to_owned(),
            "leave_group",
            tr(l, "group.leave"),
            String::new(),
        ),
        Dialog::LeaveChannel(_) => (
            tr(l, "chan.leave"),
            tr(l, "chan.leave_note").to_owned(),
            "leave_channel",
            tr(l, "chan.leave"),
            String::new(),
        ),
        Dialog::ClearChat(_) => (
            tr(l, "menu.clear"),
            tr(l, "dlg.clear_text").to_owned(),
            "clear_chat",
            tr(l, "menu.clear"),
            String::new(),
        ),
        Dialog::DeleteAccount => (
            tr(l, "set.delete"),
            format!("{} @{}", tr(l, "dlg.delete_account_text"), s.data.username),
            "delete_account",
            tr(l, "set.delete"),
            field(l, "confirm", "f.confirm_name", "text", "autofocus"),
        ),
    };
    format!(
        r#"<div class="scrim" data-act="close_dialog"></div><div class="dialog" role="dialog" aria-modal="true" data-scope><h2>{}</h2><p>{}</p>{}<div class="row end"><button type="button" class="btn" data-act="close_dialog">{}</button><button type="button" class="btn danger" data-act="{act}" data-primary>{}</button></div></div>"#,
        esc(title),
        esc(&text),
        input,
        esc(tr(l, "common.cancel")),
        esc(label)
    )
}

pub fn toast(app: &App) -> String {
    let l = app.lang();
    if app.session.is_none() {
        return String::new();
    }
    let mut h = flash_html(app, l);
    if let Some(k) = app.busy {
        h.push_str(&format!(
            r#"<div class="flash" role="status">{}</div>"#,
            esc(tr(l, k))
        ));
    }
    h
}

/// Everything the page needs to draw the current state.
pub fn view(app: &App) -> Value {
    let l = app.lang();
    let logged_in = app.session.is_some();
    let chat = matches!(app.route, Route::Chat(_)) && logged_in;
    let pkey = format!("{logged_in}:{:?}:{:?}", app.route, app.tab);
    let info_html = info(app);
    json!({
        "lang": l.code(),
        "authed": logged_in,
        "auth": if logged_in { String::new() } else { auth(app) },
        "drawer": drawer(app),
        "tabs": tabs(app),
        "sidefoot": sidefoot(app),
        "list": list(app),
        "head": head(app),
        "msgs": msgs(app),
        "page": page(app),
        "bar": bar(app),
        "info": info_html,
        "chat": chat,
        "compose": chat && compose(app),
        "overlay": overlay(app),
        "toast": toast(app),
        "pkey": pkey,
        "ph_msg": tr(l, "chat.placeholder"),
        "ph_filter": tr(l, "list.filter"),
        "ph_msgq": tr(l, "chat.search"),
        "lbl_send": tr(l, "chat.send"),
        "lbl_attach": tr(l, "chat.attach"),
        "lbl_menu": tr(l, "menu.more"),
        "lbl_lookup": tr(l, "list.lookup"),
        "lbl_today": tr(l, "date.today"),
        "lbl_yesterday": tr(l, "date.yesterday"),
        "hint": tr(l, "chat.hint"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::{Changed, MediaRef};
    use aegis_core::net::DirEntry;

    const PAYLOADS: [&str; 6] = [
        r#"<img src=x onerror=alert(1)>"#,
        r#""><script>alert(1)</script>"#,
        r#"javascript:alert(1)"#,
        r#"' onmouseover='alert(1)"#,
        r#"</div><svg/onload=alert(1)>"#,
        "<a href=\"javascript:alert(1)\">x</a>",
    ];

    /// Walks the markup and returns the opening tags with their attribute text.
    fn tags(html: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = html;
        while let Some(i) = rest.find('<') {
            let after = &rest[i + 1..];
            // Quoted attribute values never contain a raw '>' or '"' because of escaping.
            let end = after.find('>').unwrap_or(after.len());
            out.push(after[..end].to_owned());
            rest = &after[end..];
        }
        out
    }

    fn check_html(html: &str) {
        for t in tags(html) {
            let name: String = t
                .trim_start_matches('/')
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            assert!(
                [
                    "div", "span", "button", "label", "input", "select", "option", "p", "h1", "h2",
                    "h3", "ul", "li", "strong", "time", "svg", "path", "circle", "rect", "section",
                    "br"
                ]
                .contains(&name.as_str()),
                "unexpected tag {name:?} in {t:?}"
            );
            assert!(!t.contains("<"), "raw '<' inside tag: {t}");
            let attrs = t.strip_prefix(name.as_str()).unwrap_or(&t);
            let chars = attrs.chars();
            // attribute names must be from the fixed set used by the templates
            let mut in_q = false;
            let mut word = String::new();
            for c in chars {
                if c == '"' {
                    in_q = !in_q;
                    word.clear();
                    continue;
                }
                if in_q {
                    continue;
                }
                if c.is_whitespace() || c == '=' || c == '/' {
                    let w = word.to_ascii_lowercase();
                    assert!(
                        !w.starts_with("on")
                            && w != "href"
                            && w != "src"
                            && w != "style"
                            && w != "srcdoc",
                        "forbidden attribute {w:?} in {t:?}"
                    );
                    word.clear();
                } else {
                    word.push(c);
                }
            }
            assert!(!in_q, "unbalanced quote in {t:?}");
        }
        assert!(!html.contains("<script"));
        assert!(!html.contains("<img"));
        assert!(!html.contains("<video"));
        // hostile payloads may only appear escaped: no verbatim copy with markup characters
        for p in PAYLOADS.iter().filter(|p| p.contains(['<', '"', '\''])) {
            assert!(!html.contains(*p), "unescaped payload {p:?}");
        }
    }

    fn app_with_payloads() -> App {
        let mut app = App::new();
        let mut s =
            Session::fresh("alice", PAYLOADS[0], Lang::En, "pw-pw-pw-pw-pw").expect("session");
        let mut ids = Vec::new();
        for (i, p) in PAYLOADS.iter().enumerate() {
            let u = format!("bob{i}");
            let e = DirEntry {
                u: u.clone(),
                title: (*p).to_owned(),
                x: [i as u8 + 1; 32],
                ed: [i as u8 + 9; 32],
            };
            s.add_contact(&e, 1);
            if let Some(c) = s.data.contacts.get_mut(&u) {
                c.name = (*p).to_owned();
                c.about = (*p).to_owned();
                c.particles = (*p).to_owned();
                c.changed = Some(Changed {
                    x: None,
                    ed: [3; 32],
                    via_dm: i % 2 == 0,
                });
            }
            if let Some(ch) = s.data.dms.get_mut(&u) {
                ch.push(Msg {
                    id: format!("{i}"),
                    from: u.clone(),
                    ts_ms: 5,
                    ttl_s: 0,
                    text: (*p).to_owned(),
                    out: false,
                    state: MsgState::Sent,
                    media: None,
                });
                ch.push(Msg {
                    id: format!("m{i}"),
                    from: u.clone(),
                    ts_ms: 6,
                    ttl_s: 0,
                    text: (*p).to_owned(),
                    out: false,
                    state: MsgState::Sent,
                    media: Some(MediaRef {
                        video: i % 2 == 0,
                        w: 10,
                        h: 10,
                        dur_ms: 61_000,
                        file: (*p).to_owned(),
                    }),
                });
            }
            ids.push(u);
        }
        s.data.about = PAYLOADS[1].to_owned();
        s.data.particles = PAYLOADS[2].to_owned();
        let (gid, _) = s.prepare_group(PAYLOADS[1], &ids, 10).expect("group");
        if let Some(g) = s.data.groups.get_mut(&gid) {
            g.chat.push(Msg {
                id: "g1".into(),
                from: "bob1".into(),
                ts_ms: 11,
                ttl_s: 60,
                text: PAYLOADS[4].to_owned(),
                out: false,
                state: MsgState::Sent,
                media: None,
            });
        }
        let cid = s
            .create_channel(PAYLOADS[3], PAYLOADS[0], 12)
            .expect("channel");
        if let Some(c) = s.data.channels.get_mut(&cid) {
            c.warn = true;
            c.chat.push(Msg {
                id: "c1".into(),
                from: "alice".into(),
                ts_ms: 13,
                ttl_s: 0,
                text: PAYLOADS[5].to_owned(),
                out: true,
                state: MsgState::Sent,
                media: None,
            });
        }
        app.session = Some(s);
        app
    }

    #[test]
    fn hostile_values_never_become_markup() {
        let mut app = app_with_payloads();
        let ids: Vec<String> = app
            .session
            .as_ref()
            .map(|s| s.data.contacts.keys().cloned().collect())
            .unwrap_or_default();
        let gid: String = app
            .session
            .as_ref()
            .and_then(|s| s.data.groups.keys().next().cloned())
            .unwrap_or_default();
        let chans: Vec<String> = app
            .session
            .as_ref()
            .map(|s| s.data.channels.keys().cloned().collect())
            .unwrap_or_default();
        let mut routes = vec![
            Route::Welcome,
            Route::NewChat,
            Route::NewGroup,
            Route::NewChannel,
            Route::Contacts,
        ];
        for sec in crate::engine::SECTIONS {
            routes.push(Route::Account(sec));
        }
        for u in &ids {
            routes.push(Route::Chat(ChatRef::Dm(u.clone())));
            routes.push(Route::Contact(u.clone()));
        }
        for c in &chans {
            routes.push(Route::Chat(ChatRef::Channel(c.clone())));
            routes.push(Route::ChannelInfo(c.clone()));
        }
        routes.push(Route::Chat(ChatRef::Group(gid.clone())));
        routes.push(Route::GroupInfo(gid.clone()));
        for lang in [Lang::En, Lang::Ru] {
            if let Some(s) = app.session.as_mut() {
                s.data.settings.lang = lang;
            }
            for r in &routes {
                app.route = r.clone();
                for info in [false, true] {
                    app.info = info;
                    for d in [
                        None,
                        Some(Dialog::DeleteAccount),
                        Some(Dialog::LeaveGroup(gid.clone())),
                        Some(Dialog::LeaveChannel(chans[0].clone())),
                        Some(Dialog::ClearChat(ChatRef::Group(gid.clone()))),
                        Some(Dialog::DeleteChat(ids[0].clone())),
                    ] {
                        app.dialog = d;
                        let v = view(&app);
                        for k in [
                            "drawer", "tabs", "sidefoot", "list", "head", "msgs", "page", "bar",
                            "info", "overlay", "toast",
                        ] {
                            let h = v[k].as_str().unwrap_or_default();
                            check_html(h);
                            assert!(!h.contains("??"), "missing translation in {k}: {h}");
                        }
                        for k in [
                            "ph_msg",
                            "ph_filter",
                            "ph_msgq",
                            "lbl_send",
                            "lbl_attach",
                            "lbl_menu",
                            "lbl_lookup",
                            "lbl_today",
                            "lbl_yesterday",
                            "hint",
                        ] {
                            assert_ne!(v[k].as_str(), Some("??"), "missing translation {k}");
                        }
                    }
                }
            }
        }
        // the payload text is present, but only in escaped form
        app.route = Route::Chat(ChatRef::Dm(ids[0].clone()));
        let m = msgs(&app);
        assert!(m.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(!m.contains("<img"));
    }

    #[test]
    fn media_uses_relative_session_urls_only() {
        let mut app = app_with_payloads();
        app.route = Route::Chat(ChatRef::Dm("bob0".into()));
        let m = msgs(&app);
        assert!(m.contains(r#"data-media="/media/"#));
        assert!(m.contains(r#"data-video="1""#));
        assert!(!m.contains("onerror=alert(1)\" "));
        // the stored file name is never exposed to the page
        assert!(!m.contains("alert(1)</script>"));
    }

    #[test]
    fn unknown_particles_fall_back_to_none() {
        assert_eq!(pfx("rain"), "rain");
        assert_eq!(pfx("\"><x>"), "none");
    }

    #[test]
    fn subscriber_gets_bar_not_composer() {
        let mut app = app_with_payloads();
        let id = aegis_core::official::official_channel_id();
        app.route = Route::Chat(ChatRef::Channel(id));
        assert!(!compose(&app));
        assert!(bar(&app).contains("mutebar"));
        let own = app
            .session
            .as_ref()
            .and_then(|s| {
                s.data
                    .channels
                    .values()
                    .find(|c| c.mine)
                    .map(|c| c.id.clone())
            })
            .unwrap_or_default();
        app.route = Route::Chat(ChatRef::Channel(own));
        assert!(compose(&app));
        assert!(bar(&app).is_empty());
    }

    #[test]
    fn official_channel_is_first_in_list() {
        let app = app_with_payloads();
        let rs = rows(&app);
        assert!(rs.first().is_some_and(|r| r.official && r.pinned));
    }

    #[test]
    fn avatar_is_a_grayscale_circle() {
        let a = avatar(&[5; 32], "a48");
        assert!(a.starts_with("<svg"));
        assert!(a.contains("<circle"));
        assert!(!a.contains("style"));
    }

    #[test]
    fn auth_screens_are_clean_in_both_languages() {
        for lang in [Lang::En, Lang::Ru] {
            for tab in [AuthTab::Unlock, AuthTab::Create, AuthTab::Import] {
                let mut app = App::new();
                app.pre_lang = lang;
                app.tab = tab;
                app.busy = Some("busy.create");
                let h = auth(&app);
                check_html(&h);
                assert!(!h.contains("??"));
            }
        }
    }

    #[test]
    fn esc_covers_markup_characters() {
        assert_eq!(esc(r#"<>&"'`"#), "&lt;&gt;&amp;&quot;&#39;&#96;");
    }
}
