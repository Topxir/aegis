#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Appearance settings: stored form, defaults, edits from the page and the window layout.

use aegis_ui_desktop::guide;
use aegis_ui_desktop::i18n::Lang;
use aegis_ui_desktop::look::{self, Bubble, ListPos, Look, Motion};
use aegis_ui_desktop::model::Settings;
use serde_json::{json, Value};

fn stored_without_look() -> Value {
    let mut v = serde_json::to_value(Settings::new(Lang::En)).unwrap();
    let m = v.as_object_mut().unwrap();
    m.remove("look").unwrap();
    m.remove("guide_done").unwrap();
    v
}

#[test]
fn defaults_are_quiet() {
    let l = Look::default();
    assert_eq!(l.theme, "mono");
    assert_eq!(l.motion, Motion::Subtle);
    assert!(!l.depth);
    assert!(!l.animated);
    assert_eq!(l.list, ListPos::Left);
    assert_eq!(l.list_width, look::WIDTH_DEFAULT);
    assert_eq!(l.font, look::FONT_DEFAULT);
    assert_eq!(Settings::new(Lang::Ru).look, l);
    assert!(!Settings::new(Lang::Ru).guide_done);
}

#[test]
fn old_settings_load_with_default_look() {
    let s: Settings = serde_json::from_value(stored_without_look()).unwrap();
    assert_eq!(s.look, Look::default());
    assert!(!s.guide_done);
}

#[test]
fn round_trip_keeps_every_field() {
    let mut s = Settings::new(Lang::En);
    for (k, v) in [
        ("c1", "#112233"),
        ("c2", "#445566"),
        ("c3", "#778899"),
        ("animated", "true"),
        ("motion", "full"),
        ("depth", "on"),
        ("list", "right"),
        ("list_width", "400"),
        ("density", "compact"),
        ("bubble", "sharp"),
        ("radius", "8"),
        ("font", "16"),
        ("wallpaper", "gradient"),
        ("avatar", "square"),
    ] {
        assert!(s.look.set(k, v), "{k}");
    }
    s.guide_done = true;
    let text = serde_json::to_string(&s).unwrap();
    let back: Settings = serde_json::from_str(&text).unwrap();
    assert_eq!(back, s);
    assert_eq!(back.look.theme, "custom");
    assert_eq!(back.look.custom, ["#112233", "#445566", "#778899"]);
}

#[test]
fn broken_look_falls_back_without_losing_settings() {
    let mut v = stored_without_look();
    v["look"] = json!(42);
    let s: Settings = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(s.look, Look::default());

    v["look"] = json!({
        "theme": "neon",
        "custom": ["red", "#ABCDEF"],
        "motion": "wild",
        "list": "bottom",
        "list_width": 9000,
        "radius": 90,
        "font": 2,
        "bubble": "sharp"
    });
    let s: Settings = serde_json::from_value(v).unwrap();
    let d = Look::default();
    assert_eq!(s.look.theme, "mono");
    assert_eq!(s.look.custom, d.custom);
    assert_eq!(s.look.motion, Motion::Subtle);
    assert_eq!(s.look.list, ListPos::Left);
    assert_eq!(s.look.list_width, look::WIDTH_MAX);
    assert_eq!(s.look.radius, look::RADIUS_MAX);
    assert_eq!(s.look.font, look::FONT_MIN);
    assert_eq!(s.look.bubble, Bubble::Sharp);
}

#[test]
fn colors_are_checked() {
    assert_eq!(look::color("#A1b2C3").as_deref(), Some("#a1b2c3"));
    for bad in ["", "#fff", "a1b2c3", "#a1b2c3d4", "#ggg000", "url(x)", "#a1b2c3;x"] {
        assert_eq!(look::color(bad), None, "{bad}");
    }
    let mut l = Look::default();
    assert!(!l.set("c1", "javascript:x"));
    assert_eq!(l, Look::default());
    assert!(!l.set("c3", "#zzzzzz"));
    assert!(l.set("c3", "#000000"));
    assert_eq!(l.custom.len(), 3);
    assert!(l.set("c3", ""));
    assert_eq!(l.custom.len(), 2);
}

#[test]
fn page_values_are_parsed() {
    let mut l = Look::default();
    assert!(l.set("theme", "aurora"));
    assert_eq!(l.stops().0.len(), 3);
    assert!(!l.set("theme", "neon"));
    assert_eq!(l.theme, "aurora");
    assert!(!l.set("motion", "fast"));
    assert!(!l.set("nope", "1"));
    assert!(!l.set("depth", "maybe"));
    assert!(l.set("list_width", "100"));
    assert_eq!(l.list_width, look::WIDTH_MIN);
    assert!(l.set("font", "99"));
    assert_eq!(l.font, look::FONT_MAX);
    assert!(!l.set("radius", "-1"));
}

#[test]
fn text_reads_on_the_gradient() {
    let light = vec!["#f4f4f6".to_owned(), "#cfd0d6".to_owned()];
    let dark = vec!["#2563eb".to_owned(), "#0ea5b7".to_owned()];
    assert_eq!(look::ink(&light), "#0a0a0b");
    assert_eq!(look::ink(&dark), "#ffffff");
    for (id, b, a) in look::PRESETS {
        assert!(b.len() >= 2 && a.len() >= 2, "{id}");
        assert!(b.iter().chain(a.iter()).all(|c| look::color(c).as_deref() == Some(*c)), "{id}");
    }
}

#[test]
fn grid_places_every_area_once() {
    for pos in ListPos::ALL {
        for info in [false, true] {
            let (cols, rows, areas) = look::shell_grid(*pos, info);
            let names: Vec<&str> = areas.split('"').filter(|s| !s.trim().is_empty()).collect();
            let width = names[0].split(' ').count();
            assert!(names.iter().all(|r| r.split(' ').count() == width), "{areas}");
            assert_eq!(cols.matches("minmax").count() + cols.matches("min(").count(), width, "{cols}");
            assert_eq!(rows.split(' ').filter(|s| *s == "auto" || s.starts_with("minmax")).count(), names.len(), "{rows}");
            for a in ["side", "main"] {
                assert!(areas.contains(a), "{areas}");
            }
            assert_eq!(areas.contains("info"), info, "{areas}");
        }
    }
    let (_, _, a) = look::shell_grid(ListPos::Right, false);
    assert_eq!(a, r#""main side""#);
    let (_, r, a) = look::shell_grid(ListPos::Top, true);
    assert_eq!(r, "auto minmax(0, 1fr)");
    assert_eq!(a, r#""side side" "main info""#);
}

#[test]
fn json_for_the_page() {
    let mut l = Look::default();
    l.set("list", "top");
    let v = l.to_json(false);
    for k in ["bubble", "accent", "ink", "on_accent", "motion", "list", "width", "density", "shape", "radius", "font", "wall", "avatar", "cols", "rows", "areas"] {
        assert!(v.get(k).is_some(), "{k}");
    }
    assert_eq!(v["list"], "top");
    assert_eq!(v["motion"], "subtle");
    assert_eq!(v["depth"], false);
}

#[test]
fn settings_page_has_every_string() {
    for lang in [Lang::En, Lang::Ru] {
        let mut l = Look::default();
        l.set("c3", "#123456");
        let h = look::page(lang, &l);
        assert!(!h.contains("??"), "{h}");
        assert!(!h.contains("style="));
        assert!(h.contains(r#"data-act="reset_look""#));
        assert!(h.contains(r#"data-look="radius""#));
    }
}

#[test]
fn tour_steps() {
    let last = (guide::STEPS.len() - 1) as u8;
    assert_eq!(guide::step(3, "show"), Some(0));
    assert_eq!(guide::step(0, "next"), Some(1));
    assert_eq!(guide::step(0, "back"), Some(0));
    assert_eq!(guide::step(2, "back"), Some(1));
    assert_eq!(guide::step(last, "next"), None);
    assert_eq!(guide::step(last, "done"), None);
    assert_eq!(guide::step(1, "skip"), None);
    assert_eq!(guide::step(1, "bogus"), Some(1));
    assert_eq!(guide::step(200, "bogus"), Some(last));
}
