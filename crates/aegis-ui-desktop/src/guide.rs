//! The first-run tour: a few cards that point at the real controls. It opens once per account
//! and again from the About section.

use crate::engine::App;
use crate::i18n::tr;
use crate::render::esc;

/// Steps: name used in the string keys, the element to point at, and the settings section
/// the step can open.
pub const STEPS: [(&str, &str, &str); 6] = [
    ("welcome", "", ""),
    ("settings", "#burger", ""),
    ("security", "[data-guide=lock]", "privacy"),
    ("tor", "[data-guide=tor]", "connection"),
    ("contacts", "#filter", ""),
    ("appearance", "#burger", "appearance"),
];

/// The step after `action` ("next", "back", "show", "skip" or "done"); None closes the tour.
pub fn step(cur: u8, action: &str) -> Option<u8> {
    let last = (STEPS.len() - 1) as u8;
    match action {
        "show" => Some(0),
        "next" if cur < last => Some(cur + 1),
        "back" => Some(cur.saturating_sub(1)),
        "next" | "skip" | "done" => None,
        _ => Some(cur.min(last)),
    }
}

/// The step on screen, if the tour is open.
pub fn current(app: &App) -> Option<u8> {
    let s = app.session.as_ref()?;
    match app.guide {
        Some(n) => Some(n.min((STEPS.len() - 1) as u8)),
        None if !s.data.settings.guide_done => Some(0),
        None => None,
    }
}

pub fn html(app: &App) -> String {
    let Some(n) = current(app) else {
        return String::new();
    };
    let l = app.lang();
    let (name, target, sec) = STEPS[usize::from(n)];
    let last = usize::from(n) == STEPS.len() - 1;
    let mut dots = String::new();
    for i in 0..STEPS.len() {
        dots.push_str(if i == usize::from(n) { r#"<span class="on"></span>"# } else { "<span></span>" });
    }
    let open = if sec.is_empty() {
        String::new()
    } else {
        format!(
            r#"<button type="button" class="btn ghost" data-act="nav" data-to="account" data-id="{sec}">{}</button>"#,
            esc(tr(l, "guide.open"))
        )
    };
    let back = if n == 0 {
        String::new()
    } else {
        format!(
            r#"<button type="button" class="btn ghost" data-act="guide" data-step="back">{}</button>"#,
            esc(tr(l, "guide.back"))
        )
    };
    format!(
        r#"<div class="gscrim"></div><span class="gring" aria-hidden="true"></span><section class="gcard" role="dialog" aria-modal="true" data-target="{target}"><p class="gstep mono">{} / {}</p><h2>{}</h2><p class="gtext">{}</p><div class="gdots" aria-hidden="true">{dots}</div><div class="row"><button type="button" class="link" data-act="guide" data-step="skip">{}</button><span class="gsp"></span>{open}{back}<button type="button" class="btn primary" data-act="guide" data-step="{}" data-primary>{}</button></div></section>"#,
        n + 1,
        STEPS.len(),
        esc(tr(l, &format!("guide.{name}"))),
        esc(tr(l, &format!("guide.{name}_text"))),
        esc(tr(l, "guide.skip")),
        if last { "done" } else { "next" },
        esc(tr(l, if last { "guide.done" } else { "guide.next" }))
    )
}
