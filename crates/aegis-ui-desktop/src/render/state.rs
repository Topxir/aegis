//! Plain state for the redesigned shell: the page draws everything itself from this.

use super::{chan_title, key_fingerprint, contact_name, invite::qr_svg, timer_line, tr, App, Lang, Route};
use crate::model::{Chat, Msg, MsgState, UNDECRYPTABLE};
use crate::session::{ChatRef, Session};
use aegis_core::hex::encode as hex;
use serde_json::{json, Value};

fn msg(app: &App, s: &Session, l: Lang, m: &Msg) -> Value {
    let sys = timer_line(s, l, m);
    let text = if m.text == UNDECRYPTABLE {
        tr(l, "chat.undecryptable").to_owned()
    } else if sys.is_some() {
        String::new()
    } else {
        m.text.clone()
    };
    let base = if m.base_ms != 0 { m.base_ms } else { m.ts_ms };
    json!({
        "id": m.id,
        "out": m.out,
        "from": m.from,
        "ts": m.ts_ms,
        "ttl": m.ttl_s,
        "exp": if m.ttl_s > 0 { base + m.ttl_s * 1000 } else { 0 },
        "text": text,
        "sys": sys,
        "state": match m.state { MsgState::Sent => "sent", MsgState::Sending => "sending", MsgState::Failed => "failed" },
        "media": m.media.as_ref().map(|r| json!({
            "url": format!("/media/{}", crate::media::session_id(&app.media_secret, &r.file)),
            "video": r.video, "w": r.w, "h": r.h, "dur": r.dur_ms,
        })),
    })
}

fn chat(app: &App, s: &Session, l: Lang, r: &ChatRef, c: &Chat, open: bool, extra: Value) -> Value {
    let msgs: Vec<Value> = if open {
        c.msgs.iter().map(|m| msg(app, s, l, m)).collect()
    } else {
        c.msgs.last().map(|m| msg(app, s, l, m)).into_iter().collect()
    };
    let mut v = json!({
        "id": r.key(),
        "pinned": s.is_pinned(r),
        "muted": s.is_muted(r),
        "ttl": c.ttl_s,
        "unread": c.unread,
        "last": c.last_ms(),
        "full": open,
        "msgs": msgs,
    });
    if let (Some(o), Value::Object(e)) = (v.as_object_mut(), extra) {
        o.extend(e);
    }
    v
}

pub(super) fn model(app: &App) -> Value {
    let Some(s) = app.session.as_ref() else { return Value::Null };
    let l = app.lang();
    let d = &s.data;
    let cur = match &app.route {
        Route::Chat(r) => Some(r.key()),
        _ => None,
    };
    let is = |r: &ChatRef| cur.as_deref() == Some(r.key().as_str());
    let mut chats = Vec::new();
    for (u, c) in &d.dms {
        let r = ChatRef::Dm(u.clone());
        chats.push(chat(app, s, l, &r, c, is(&r), json!({ "kind": "dm", "peer": u })));
    }
    if let Route::Chat(r @ ChatRef::Dm(u)) = &app.route {
        if !d.dms.contains_key(u) && d.contacts.contains_key(u) {
            chats.push(chat(app, s, l, r, &Chat::default(), true, json!({ "kind": "dm", "peer": u })));
        }
    }
    for (id, g) in &d.groups {
        let r = ChatRef::Group(id.clone());
        let extra = json!({ "kind": "group", "title": g.title, "owner": g.creator, "members": g.members });
        chats.push(chat(app, s, l, &r, &g.chat, is(&r), extra));
    }
    for (id, ch) in &d.channels {
        let r = ChatRef::Channel(id.clone());
        let extra = json!({
            "kind": if ch.official { "official" } else { "channel" },
            "title": chan_title(ch), "about": ch.about, "owner": ch.owner,
            "mine": ch.mine, "subs": ch.subs, "warn": ch.warn,
        });
        chats.push(chat(app, s, l, &r, &ch.chat, is(&r), extra));
    }
    let st = &d.settings;
    let contacts: Vec<Value> = d
        .contacts
        .values()
        .map(|c| json!({
            "u": c.u, "name": contact_name(c), "ed": hex(&c.ed), "x": hex(&c.x), "verified": c.verified,
            "sn": s.safety_number(&c.u), "fp": key_fingerprint(&c.x),
            "about": c.about, "changed": c.changed.is_some(),
        }))
        .collect();
    let (tor, p) = match &app.tor {
        crate::tor::Status::Off => ("off", 0),
        crate::tor::Status::Starting(p) => ("start", *p),
        crate::tor::Status::Ready => ("ready", 100),
        crate::tor::Status::Failed(_) => ("fail", 0),
    };
    let invite = app.invite.as_ref().map(|k| json!({ "link": k.as_str(), "qr": qr_svg(k) }));
    json!({
        "me": { "u": d.username, "display": d.display, "about": d.about, "particles": d.particles, "ed": hex(&s.ed_public()), "x": hex(&s.x_public()), "fp": key_fingerprint(&s.x_public()) },
        "version": env!("CARGO_PKG_VERSION"),
        "route": cur.unwrap_or_default(),
        "busy": app.busy.is_some(),
        "pin": app.pin_on,
        "duress": app.duress_on,
        "invite": invite,
        "update": format!("{:?}", app.update.status),
        "requests": d.pending.iter().map(|p| json!({ "x": hex(&p.x), "first": p.first_ms })).collect::<Vec<_>>(),
        "tor": { "state": tor, "p": p },
        "set": {
            "idle": st.idle_min, "lock": st.app_lock, "lockMin": st.lock_min, "protect": st.protect,
            "hidden": st.hidden, "taskbar": st.flash_taskbar, "notifyName": st.notify_name,
            "tor": st.tor, "bridges": st.bridges, "bridgeLines": st.bridge_lines, "cover": st.cover,
            "autoUpd": st.auto_update, "server": st.endpoint, "socks": st.socks5,
        },
        "contacts": contacts,
        "chats": chats,
    })
}
