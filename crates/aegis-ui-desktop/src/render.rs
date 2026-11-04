//! HTML for each screen region. Every value that did not come from a string
//! literal in this file passes through [`esc`] before it is placed in markup.

use crate::engine::{App, AuthTab, ConnTest, Dialog, Route};
use crate::i18n::{tr, Lang};
use crate::model::{clean_text, Chat, Contact, Msg, MsgState};
use crate::session::{ChatRef, Session, TTL_CHOICES};
use aegis_core::text::sanitize_display_text;
use serde_json::{json, Value};

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
    h.push_str(r#"<div class="auth-bg" aria-hidden="true"><span class="orb o1"></span><span class="orb o2"></span></div><div class="auth-wrap"><section class="hero">"#);
    h.push_str(&format!(
        r#"<div class="brandrow rise r0">{}<span class="brand">AEGIS</span></div>"#,
        icon("shield")
    ));
    let headline = tr(l, "auth.headline")
        .split('\n')
        .map(esc)
        .collect::<Vec<_>>()
        .join("<br>");
    h.push_str(&format!(
        r#"<h1 class="rise r1">{headline}</h1><p class="sub rise r2">{}</p><ul class="pts mono rise r3">"#,
        esc(tr(l, "auth.tagline"))
    ));
    for k in ["auth.pt1", "auth.pt2", "auth.pt3"] {
        h.push_str(&format!("<li>{}</li>", esc(tr(l, k))));
    }
    h.push_str(
        r#"</ul></section><section class="auth-card rise r2"><div class="tabs" role="tablist">"#,
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
            h.push_str(&field(l, "password", "f.password", "password", ""));
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
        r#"</section><div class="auth-foot rise r4"><span class="muted">{}</span>{}</div></div>"#,
        esc(tr(l, "auth.alpha")),
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

// ---- sidebar ------------------------------------------------------------------

pub fn sidetop(app: &App) -> String {
    let l = app.lang();
    if app.session.is_none() {
        return String::new();
    }
    let mut h = format!(
        r#"<div class="brandrow">{}<span class="brand">AEGIS</span></div><div class="tools">"#,
        icon("shield")
    );
    for (to, ic, key) in [
        ("new_chat", "edit", "nav.new_chat"),
        ("new_group", "users", "nav.new_group"),
        ("settings", "settings", "nav.settings"),
    ] {
        h.push_str(&format!(
            r#"<button type="button" class="ib" data-act="nav" data-to="{to}" title="{0}" aria-label="{0}">{1}</button>"#,
            esc(tr(l, key)),
            icon(ic)
        ));
    }
    h.push_str("</div>");
    h
}

/// Signed-in user line under the logo.
pub fn sideme(app: &App) -> String {
    let Some(s) = &app.session else {
        return String::new();
    };
    format!(
        r#"<div class="me-name">{}</div><div class="me-u mono muted">@{}</div>"#,
        disp(&s.data.display),
        esc(&s.data.username)
    )
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
        r#"<span class="conn" title="{0}"><span class="dot {cls}" role="img" aria-label="{0}"></span><span class="host mono">{1}</span></span><button type="button" class="link lockbtn" data-act="lock">{2}{3}</button>"#,
        esc(tr(l, key)),
        esc(&host_of(&s.data.settings.endpoint)),
        icon("lock"),
        esc(tr(l, "nav.lock"))
    )
}

fn preview(m: Option<&Msg>) -> String {
    m.map_or_else(String::new, |m| {
        let t: String = clean_text(&m.text)
            .replace('\n', " ")
            .chars()
            .take(48)
            .collect();
        t
    })
}

pub fn list(app: &App) -> String {
    let l = app.lang();
    let Some(s) = &app.session else {
        return String::new();
    };
    struct Row<'a> {
        last: u64,
        kind: &'static str,
        id: &'a str,
        title: String,
        chat: &'a Chat,
    }
    let mut rows: Vec<Row<'_>> = Vec::new();
    for (u, chat) in &s.data.dms {
        if let Some(c) = s.data.contacts.get(u) {
            rows.push(Row {
                last: chat.last_ms(),
                kind: "dm",
                id: u,
                title: contact_name(c),
                chat,
            });
        }
    }
    for (id, g) in &s.data.groups {
        rows.push(Row {
            last: g.chat.last_ms(),
            kind: "group",
            id,
            title: sanitize_display_text(&g.title),
            chat: &g.chat,
        });
    }
    rows.sort_by(|a, b| b.last.cmp(&a.last).then_with(|| a.id.cmp(b.id)));
    if rows.is_empty() {
        return format!(r#"<p class="empty muted">{}</p>"#, esc(tr(l, "list.empty")));
    }
    let mut h = String::new();
    for r in rows {
        let active = matches!(&app.route, Route::Chat(ChatRef::Dm(u)) if r.kind == "dm" && u == r.id)
            || matches!(&app.route, Route::Chat(ChatRef::Group(g)) if r.kind == "group" && g == r.id);
        let letter: String = r
            .title
            .chars()
            .next()
            .map(|c| c.to_uppercase().collect())
            .unwrap_or_default();
        let unread = if r.chat.unread > 0 && !active {
            format!(r#"<span class="badge">{}</span>"#, r.chat.unread.min(99))
        } else {
            String::new()
        };
        let q = format!("{} {}", r.title, r.id).to_lowercase();
        h.push_str(&format!(
            r#"<button type="button" class="item{}" data-act="nav" data-to="{}" data-id="{}" data-q="{}"><span class="av{}">{}</span><span class="it-body"><span class="it-top"><span class="it-name">{}</span>{}</span><span class="it-prev muted">{}</span></span>{}</button>"#,
            if active { " on" } else { "" },
            r.kind,
            esc(r.id),
            esc(&q),
            if r.kind == "group" { " grp" } else { "" },
            esc(&letter),
            esc(&r.title),
            if r.chat.msgs.is_empty() { String::new() } else { time_tag(r.chat.last_ms()) },
            esc(&preview(r.chat.msgs.last())),
            unread
        ));
    }
    h
}

// ---- main pane ----------------------------------------------------------------

pub fn head(app: &App) -> String {
    let l = app.lang();
    let Some(s) = &app.session else {
        return String::new();
    };
    let plain = |key: &str| format!(r#"<span class="title static">{}</span>"#, esc(tr(l, key)));
    match &app.route {
        Route::Welcome => plain("main.welcome_title"),
        Route::NewChat => plain("nav.new_chat"),
        Route::NewGroup => plain("nav.new_group"),
        Route::Settings => plain("nav.settings"),
        Route::Contact(u) => format!(
            r#"<button type="button" class="ib" data-act="nav" data-to="dm" data-id="{}" aria-label="{}">{}</button>{}"#,
            esc(u),
            esc(tr(l, "common.back")),
            icon("back"),
            plain("contact.title")
        ),
        Route::GroupInfo(g) => format!(
            r#"<button type="button" class="ib" data-act="nav" data-to="group" data-id="{}" aria-label="{}">{}</button>{}"#,
            esc(g),
            esc(tr(l, "common.back")),
            icon("back"),
            plain("group.info")
        ),
        Route::Chat(r) => {
            let Some(chat) = s.chat(r) else {
                return String::new();
            };
            let (title, sub, to, id) = match r {
                ChatRef::Dm(u) => {
                    let c = s.data.contacts.get(u);
                    let name = c.map_or_else(|| u.clone(), contact_name);
                    let v = if c.is_some_and(|c| c.verified) {
                        tr(l, "contact.key_verified")
                    } else {
                        tr(l, "contact.unverified")
                    };
                    (name, v.to_owned(), "contact", u.as_str())
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
                        "group_info",
                        g.as_str(),
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
            let (ic, label) = match r {
                ChatRef::Dm(_) => ("shield-sm", "warn.view"),
                ChatRef::Group(_) => ("users", "group.info"),
            };
            format!(
                r#"<button type="button" class="title" data-act="nav" data-to="{to}" data-id="{0}"><span class="t1">{1}</span><span class="t2 muted">{2}</span></button><label class="ttl" title="{3}">{4}<select data-change="set_ttl" data-key="ttl" aria-label="{3}">{5}</select></label><button type="button" class="btn ghost safetybtn" data-act="nav" data-to="{to}" data-id="{0}">{6}{7}</button>"#,
                esc(id),
                esc(&title),
                esc(&sub),
                esc(tr(l, "ttl.label")),
                icon("clock"),
                opts,
                icon(ic),
                esc(tr(l, label))
            )
        }
    }
}

fn msg_html(s: &Session, l: Lang, m: &Msg, group: bool) -> String {
    let mut h = format!(
        r#"<div class="m {}" data-mid="{}">"#,
        if m.out { "out" } else { "in" },
        esc(&m.id)
    );
    h.push_str(r#"<div class="bubble">"#);
    if group && !m.out {
        h.push_str(&format!(
            r#"<div class="who">{}</div>"#,
            disp(&who(s, &m.from))
        ));
    }
    h.push_str(&format!(
        r#"<div class="t">{}</div><div class="meta">"#,
        esc(&clean_text(&m.text))
    ));
    if m.ttl_s != 0 {
        h.push_str(icon("clock"));
    }
    h.push_str(&time_tag(m.ts_ms));
    match (m.out, m.state) {
        (true, MsgState::Sending) => {
            h.push_str(&format!(
                r#"<span class="st">{}</span>"#,
                esc(tr(l, "msg.sending"))
            ));
        }
        (true, MsgState::Failed) => {
            h.push_str(&format!(
                r#"<span class="st bad">{}</span><button type="button" class="link" data-act="retry" data-id="{}">{}</button>"#,
                esc(tr(l, "msg.failed")),
                esc(&m.id),
                esc(tr(l, "msg.retry"))
            ));
        }
        _ => {}
    }
    h.push_str("</div></div></div>");
    h
}

fn banner(l: Lang, c: &Contact, with_accept: bool) -> String {
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
    let group = matches!(r, ChatRef::Group(_));
    match r {
        ChatRef::Dm(u) => {
            if let Some(c) = s.data.contacts.get(u).filter(|c| c.changed.is_some()) {
                h.push_str(&banner(l, c, c.changed.as_ref().is_some_and(|x| x.via_dm)));
            }
        }
        ChatRef::Group(g) => {
            if let Some(grp) = s.data.groups.get(g) {
                for u in &grp.members {
                    if let Some(c) = s.data.contacts.get(u).filter(|c| c.changed.is_some()) {
                        h.push_str(&banner(l, c, c.changed.as_ref().is_some_and(|x| x.via_dm)));
                    }
                }
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
    for m in &chat.msgs {
        h.push_str(&msg_html(s, l, m, group));
    }
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

fn page_new_group(l: Lang, s: &Session) -> String {
    let mut h = format!(
        r#"<div class="card" data-scope><h2>{}</h2><p class="note">{}</p>{}"#,
        esc(tr(l, "nav.new_group")),
        esc(tr(l, "newgroup.note")),
        field(
            l,
            "title",
            "f.group_title",
            "text",
            r#"maxlength="64" autofocus"#
        )
    );
    h.push_str(&format!(
        r#"<div class="f"><span>{}</span><div class="checks">"#,
        esc(tr(l, "newgroup.members"))
    ));
    if s.data.contacts.is_empty() {
        h.push_str(&format!(
            r#"<p class="muted">{}</p>"#,
            esc(tr(l, "newgroup.no_contacts"))
        ));
    }
    for c in s.data.contacts.values() {
        h.push_str(&format!(
            r#"<label class="chk"><input type="checkbox" name="members[]" value="{}"><span>{} <span class="muted">@{}</span></span></label>"#,
            esc(&c.u),
            disp(&c.name),
            esc(&c.u)
        ));
    }
    h.push_str("</div></div>");
    h.push_str(&format!(
        r#"<div class="row"><button type="button" class="btn primary" data-act="create_group" data-primary>{}</button></div></div>"#,
        esc(tr(l, "newgroup.create"))
    ));
    h
}

fn page_contact(l: Lang, s: &Session, u: &str) -> String {
    let Some(c) = s.data.contacts.get(u) else {
        return String::new();
    };
    let sn = s.safety_number(u).unwrap_or_default();
    let mut h = format!(
        r#"<div class="card"><h2>{}</h2><p class="muted">@{}</p>"#,
        disp(&c.name),
        esc(&c.u)
    );
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
        r#"<div class="card"><h2>{}</h2><p class="muted">{} {}</p><ul class="members">"#,
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
            r#"<li><span>{} <span class="muted">@{}</span></span><span class="muted">{}</span>"#,
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

fn page_settings(app: &App, s: &Session) -> String {
    let l = app.lang();
    let st = &s.data.settings;
    let val = |v: &str| format!(r#"value="{}""#, esc(v));
    let mut h = String::from(r#"<div class="stack">"#);
    h.push_str(&format!(
        r#"<section class="card" data-scope><h2>{}</h2>{}<div class="row"><button type="button" class="btn" data-act="update_display" data-primary>{}</button></div></section>"#,
        esc(tr(l, "set.profile")),
        field(l, "display", "f.display", "text", &format!(r#"maxlength="64" {}"#, val(&s.data.display))),
        esc(tr(l, "common.save"))
    ));
    h.push_str(&format!(
        r#"<section class="card" data-scope><h2>{}</h2>{}{}<p class="note">{}</p>"#,
        esc(tr(l, "set.connection")),
        field(l, "endpoint", "f.endpoint", "text", &val(&st.endpoint)),
        field(
            l,
            "socks5",
            "f.socks5",
            "text",
            &format!(r#"placeholder="127.0.0.1:9050" {}"#, val(&st.socks5))
        ),
        esc(tr(l, "set.conn_note"))
    ));
    h.push_str(&format!(
        r#"{}<label class="chk"><input type="checkbox" name="flash"{}><span>{}</span></label><div class="row"><button type="button" class="btn primary" data-act="save_settings">{}</button><button type="button" class="btn" data-act="test_conn">{}</button></div>{}</section>"#,
        field(l, "idle_min", "f.idle", "text", &format!(r#"inputmode="numeric" maxlength="4" {}"#, val(&st.idle_min.to_string()))),
        if st.flash_taskbar { " checked" } else { "" },
        esc(tr(l, "set.flash")),
        esc(tr(l, "common.save")),
        esc(tr(l, "set.test")),
        conn_html(app, l)
    ));
    h.push_str(&format!(
        r#"<section class="card"><h2>{}</h2><div class="row">{}</div><p class="note">{}</p></section>"#,
        esc(tr(l, "set.language")),
        lang_select(l),
        esc(tr(l, "set.lang_note"))
    ));
    h.push_str(&format!(
        r#"<section class="card" data-scope><h2>{}</h2><p class="note">{}</p>{}<div class="row"><button type="button" class="btn" data-act="export" data-primary>{}</button><button type="button" class="btn" data-act="lock">{}</button></div></section>"#,
        esc(tr(l, "set.backup")),
        esc(tr(l, "set.backup_note")),
        field(l, "path", "f.export_path", "text", r#"placeholder="C:\Users\...\backup.vault""#),
        esc(tr(l, "set.export")),
        esc(tr(l, "nav.lock"))
    ));
    h.push_str(&format!(
        r#"<section class="card"><h2>{}</h2><p class="note">{}</p><div class="row"><button type="button" class="btn danger" data-act="open_dialog" data-kind="delete_account">{}</button></div></section>"#,
        esc(tr(l, "set.danger")),
        esc(tr(l, "set.delete_note")),
        esc(tr(l, "set.delete"))
    ));
    h.push_str(&format!(
        r#"<section class="card"><h2>{}</h2><p class="note">{}</p><p class="note">{}</p></section></div>"#,
        esc(tr(l, "set.about")),
        esc(tr(l, "set.about_text")),
        esc(tr(l, "main.e2ee"))
    ));
    h
}

pub fn page(app: &App) -> String {
    let l = app.lang();
    let Some(s) = &app.session else {
        return String::new();
    };
    match &app.route {
        Route::Chat(_) => String::new(),
        Route::Welcome => page_welcome(l),
        Route::NewChat => page_new_chat(l),
        Route::NewGroup => page_new_group(l, s),
        Route::Contact(u) => page_contact(l, s, u),
        Route::GroupInfo(g) => page_group_info(l, s, g),
        Route::Settings => page_settings(app, s),
    }
}

pub fn overlay(app: &App) -> String {
    let l = app.lang();
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
    let ttl = match (&app.session, &app.route) {
        (Some(s), Route::Chat(r)) => s.chat(r).map_or(0, |c| c.ttl_s),
        _ => 0,
    };
    let pkey = format!("{logged_in}:{:?}:{:?}", app.route, app.tab);
    json!({
        "lang": l.code(),
        "authed": logged_in,
        "auth": if logged_in { String::new() } else { auth(app) },
        "sidetop": sidetop(app),
        "sideme": sideme(app),
        "sidefoot": sidefoot(app),
        "list": list(app),
        "head": head(app),
        "msgs": msgs(app),
        "page": page(app),
        "chat": chat,
        "ttl": ttl,
        "overlay": overlay(app),
        "toast": toast(app),
        "pkey": pkey,
        "ph_msg": tr(l, "chat.placeholder"),
        "ph_filter": tr(l, "list.filter"),
        "lbl_send": tr(l, "chat.send"),
        "hint": tr(l, "chat.hint"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::Changed;
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
                });
            }
            ids.push(u);
        }
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
        let mut routes = vec![
            Route::Welcome,
            Route::NewChat,
            Route::NewGroup,
            Route::Settings,
        ];
        for u in &ids {
            routes.push(Route::Chat(ChatRef::Dm(u.clone())));
            routes.push(Route::Contact(u.clone()));
        }
        routes.push(Route::Chat(ChatRef::Group(gid.clone())));
        routes.push(Route::GroupInfo(gid.clone()));
        for lang in [Lang::En, Lang::Ru] {
            if let Some(s) = app.session.as_mut() {
                s.data.settings.lang = lang;
            }
            for r in &routes {
                app.route = r.clone();
                for d in [
                    None,
                    Some(Dialog::DeleteAccount),
                    Some(Dialog::LeaveGroup(gid.clone())),
                    Some(Dialog::DeleteChat(ids[0].clone())),
                ] {
                    app.dialog = d;
                    let v = view(&app);
                    for k in [
                        "sidetop", "sideme", "sidefoot", "list", "head", "msgs", "page", "overlay",
                        "toast",
                    ] {
                        let h = v[k].as_str().unwrap_or_default();
                        check_html(h);
                        assert!(!h.contains("??"), "missing translation in {k}: {h}");
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
