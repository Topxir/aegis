//! Invite cards on the new chat page and the hidden profile switch.

use super::{check, esc, field, tr, App, Lang};
use crate::model::Settings;
use qrcode::{Color, QrCode};

/// A QR code as inline SVG: one path, dark modules on a light quiet zone.
pub(super) fn qr_svg(text: &str) -> String {
    let Ok(code) = QrCode::new(text.as_bytes()) else {
        return String::new();
    };
    let w = code.width();
    let mut d = String::new();
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == Color::Dark {
            d.push_str(&format!("M{} {}h1v1h-1z", i % w + 4, i / w + 4));
        }
    }
    let side = w + 8;
    format!(
        r##"<svg class="qr" viewBox="0 0 {side} {side}" shape-rendering="crispEdges" aria-hidden="true"><rect width="{side}" height="{side}" fill="#fff"/><path d="{d}" fill="#000"/></svg>"##
    )
}

pub(super) fn cards(app: &App, l: Lang) -> String {
    let dis = if app.busy.is_some() { " disabled" } else { "" };
    let mut h = format!(
        r#"<div class="card" data-scope><h2>{}</h2><p class="note">{}</p>"#,
        esc(tr(l, "inv.title")),
        esc(tr(l, "inv.note"))
    );
    if let Some(link) = &app.invite {
        h.push_str(&qr_svg(link));
        h.push_str(&format!(
            r#"<div class="row"><input class="mono" type="text" readonly value="{}"><button type="button" class="btn" data-ui="copy">{}</button></div>"#,
            esc(link),
            esc(tr(l, "inv.copy"))
        ));
    }
    h.push_str(&format!(
        r#"<div class="row"><button type="button" class="btn" data-act="create_invite"{dis}>{}</button></div></div>"#,
        esc(tr(l, if app.invite.is_some() { "inv.another" } else { "inv.create" }))
    ));
    let prefill = app
        .link_in
        .as_ref()
        .map(|v| format!(r#"value="{}""#, esc(v)))
        .unwrap_or_default();
    h.push_str(&format!(
        r#"<div class="card" data-scope><h2>{}</h2><p class="note">{}</p>{}<div class="row"><button type="button" class="btn primary" data-act="redeem_invite"{dis}>{}</button></div></div>"#,
        esc(tr(l, "inv.open_title")),
        esc(tr(l, "inv.open_note")),
        field(
            l,
            "link",
            "f.invite_link",
            "text",
            &format!(r#"class="mono" maxlength="200" {prefill}"#)
        ),
        esc(tr(l, "inv.open"))
    ));
    h
}

pub(super) fn hidden_card(st: &Settings, l: Lang) -> String {
    format!(
        r#"<section class="card" data-scope><h2>{}</h2>{}<p class="note">{}</p><div class="row"><button type="button" class="btn primary" data-act="save_hidden">{}</button></div></section>"#,
        esc(tr(l, "priv.lookup")),
        check("hidden", tr(l, "priv.hidden"), st.hidden, false),
        esc(tr(l, "priv.hidden_note")),
        esc(tr(l, "common.save"))
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn qr_is_one_path_with_a_quiet_zone() {
        let svg = qr_svg("aegis://invite/0000000000000000000000000000000000000000000000000000000000000000");
        assert!(svg.starts_with("<svg class=\"qr\""));
        assert_eq!(svg.matches("<path").count(), 1);
        assert!(svg.contains("M4 4h1v1h-1z"), "finder pattern starts at the quiet zone");
    }
}
