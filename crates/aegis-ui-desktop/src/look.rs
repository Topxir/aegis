//! Appearance settings: theme gradient, motion, depth, layout and message style. Stored per
//! account in the vault settings. Every field has a default and unknown or broken values fall
//! back to it, so older vaults and hand-edited ones load unchanged.

use crate::i18n::{tr, Lang};
use crate::render::esc;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};

pub const WIDTH_MIN: u16 = 260;
pub const WIDTH_MAX: u16 = 520;
pub const WIDTH_DEFAULT: u16 = 340;
pub const RADIUS_MAX: u8 = 22;
pub const RADIUS_DEFAULT: u8 = 16;
pub const FONT_MIN: u8 = 12;
pub const FONT_MAX: u8 = 18;
pub const FONT_DEFAULT: u8 = 14;
pub const DIM_MAX: u8 = 85;
pub const DIM_DEFAULT: u8 = 45;
/// Base64 of the cleaned wallpaper JPEG; anything longer is dropped.
pub const PHOTO_MAX: usize = 4 << 20;

/// Preset themes: id, gradient for outgoing bubbles and the header, gradient for buttons and badges.
pub const PRESETS: [(&str, &[&str], &[&str]); 6] = [
    ("mono", &["#2c2d32", "#222327"], &["#f4f4f6", "#cfd0d6"]),
    ("ocean", &["#2563eb", "#0ea5b7"], &["#2563eb", "#0ea5b7"]),
    ("dusk", &["#6d4aff", "#d9467e"], &["#6d4aff", "#d9467e"]),
    ("aurora", &["#0f9f7a", "#2b6fe0", "#7c4dff"], &["#0f9f7a", "#2b6fe0", "#7c4dff"]),
    ("ember", &["#f0662e", "#d42f4f"], &["#f0662e", "#d42f4f"]),
    ("slate", &["#4b5a73", "#2d3646"], &["#8fa3c2", "#5d6f8c"]),
];

macro_rules! choice {
    ($name:ident { $first:ident = $fs:literal $(, $v:ident = $s:literal)* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub enum $name {
            #[default]
            $first,
            $($v,)*
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.id())
            }
        }

        /// Unknown names read as the default.
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let v = Value::deserialize(d)?;
                Ok(v.as_str().and_then(Self::parse).unwrap_or_default())
            }
        }

        impl $name {
            pub const ALL: &'static [$name] = &[$name::$first $(, $name::$v)*];

            pub fn id(self) -> &'static str {
                match self {
                    $name::$first => $fs,
                    $($name::$v => $s,)*
                }
            }

            pub fn parse(s: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.id() == s)
            }
        }
    };
}

choice!(ListPos { Left = "left", Right = "right", Top = "top" });
choice!(Density { Comfortable = "comfortable", Compact = "compact" });
choice!(Motion { Subtle = "subtle", Off = "off", Full = "full" });
choice!(Bubble { Rounded = "rounded", Sharp = "sharp", Minimal = "minimal" });
choice!(Wallpaper { None = "none", Solid = "solid", Gradient = "gradient", Photo = "photo" });
choice!(Effect { None = "none", Rain = "rain", Snow = "snow", Dust = "dust", Embers = "embers", Stars = "stars" });
choice!(Scope { Chat = "chat", Full = "full" });
choice!(AvatarShape { Circle = "circle", Rounded = "rounded", Square = "square" });

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Look {
    /// A preset id from `PRESETS` or "custom".
    pub theme: String,
    /// Two or three `#rrggbb` colors used when `theme` is "custom".
    pub custom: Vec<String>,
    pub animated: bool,
    pub motion: Motion,
    pub depth: bool,
    pub list: ListPos,
    pub list_width: u16,
    pub density: Density,
    pub bubble: Bubble,
    pub radius: u8,
    pub font: u8,
    pub wallpaper: Wallpaper,
    pub avatar: AvatarShape,
    /// Where the wallpaper shows: behind the messages or behind the whole window.
    pub wall_scope: Scope,
    /// How much the wallpaper photo is darkened, in percent.
    pub wall_dim: u8,
    /// The wallpaper photo: a cleaned JPEG in base64, empty when none was picked.
    pub photo: String,
    pub effect: Effect,
    pub effect_scope: Scope,
}

impl Default for Look {
    fn default() -> Self {
        Self {
            theme: "mono".to_owned(),
            custom: vec!["#6d4aff".to_owned(), "#0ea5b7".to_owned()],
            animated: false,
            motion: Motion::Subtle,
            depth: false,
            list: ListPos::Left,
            list_width: WIDTH_DEFAULT,
            density: Density::Comfortable,
            bubble: Bubble::Rounded,
            radius: RADIUS_DEFAULT,
            font: FONT_DEFAULT,
            wallpaper: Wallpaper::None,
            avatar: AvatarShape::Circle,
            wall_scope: Scope::Chat,
            wall_dim: DIM_DEFAULT,
            photo: String::new(),
            effect: Effect::None,
            effect_scope: Scope::Chat,
        }
    }
}

/// Reads the stored look; anything that does not parse gives the default instead of failing
/// the whole vault.
pub fn lenient<'de, D: Deserializer<'de>>(d: D) -> Result<Look, D::Error> {
    let v = Value::deserialize(d)?;
    let mut l: Look = serde_json::from_value(v).unwrap_or_default();
    l.sanitize();
    Ok(l)
}

/// `#rrggbb` in lowercase, or None.
pub fn color(s: &str) -> Option<String> {
    let h = s.trim().strip_prefix('#')?;
    (h.len() == 6 && h.bytes().all(|b| b.is_ascii_hexdigit())).then(|| format!("#{}", h.to_ascii_lowercase()))
}

fn rgb(c: &str) -> (f32, f32, f32) {
    let n = u32::from_str_radix(c.trim_start_matches('#'), 16).unwrap_or(0);
    let f = |s: u32| ((n >> s) & 0xff) as f32 / 255.0;
    (f(16), f(8), f(0))
}

/// Relative luminance of a `#rrggbb` color.
pub fn luma(c: &str) -> f32 {
    let lin = |v: f32| {
        if v <= 0.04045 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    let (r, g, b) = rgb(c);
    0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

/// Text color that reads on top of a gradient.
pub fn ink(stops: &[String]) -> &'static str {
    let n = stops.len().max(1) as f32;
    let avg = stops.iter().map(|c| luma(c)).sum::<f32>() / n;
    if avg > 0.4 {
        "#0a0a0b"
    } else {
        "#ffffff"
    }
}

/// Grid of the main window: column sizes, row sizes and area names for the side list, the
/// conversation and the info panel. `var(--listw)` is the list width, set by the page.
pub fn shell_grid(pos: ListPos, info: bool) -> (String, String, String) {
    let info_w = "minmax(240px, 300px)";
    let side = "min(var(--listw), 45vw)";
    match (pos, info) {
        (ListPos::Left, false) => (format!("{side} minmax(0, 1fr)"), "minmax(0, 1fr)".into(), r#""side main""#.into()),
        (ListPos::Left, true) => (
            format!("{side} minmax(0, 1fr) {info_w}"),
            "minmax(0, 1fr)".into(),
            r#""side main info""#.into(),
        ),
        (ListPos::Right, false) => (format!("minmax(0, 1fr) {side}"), "minmax(0, 1fr)".into(), r#""main side""#.into()),
        (ListPos::Right, true) => (
            format!("minmax(0, 1fr) {info_w} {side}"),
            "minmax(0, 1fr)".into(),
            r#""main info side""#.into(),
        ),
        (ListPos::Top, false) => ("minmax(0, 1fr)".into(), "auto minmax(0, 1fr)".into(), r#""side" "main""#.into()),
        (ListPos::Top, true) => (
            format!("minmax(0, 1fr) {info_w}"),
            "auto minmax(0, 1fr)".into(),
            r#""side side" "main info""#.into(),
        ),
    }
}

impl Look {
    pub fn sanitize(&mut self) {
        if self.theme != "custom" && !PRESETS.iter().any(|p| p.0 == self.theme) {
            self.theme = "mono".to_owned();
        }
        let mut cs: Vec<String> = self.custom.iter().filter_map(|c| color(c)).take(3).collect();
        if cs.len() < 2 {
            cs = Look::default().custom;
        }
        self.custom = cs;
        self.list_width = self.list_width.clamp(WIDTH_MIN, WIDTH_MAX);
        self.radius = self.radius.min(RADIUS_MAX);
        self.font = self.font.clamp(FONT_MIN, FONT_MAX);
        self.wall_dim = self.wall_dim.min(DIM_MAX);
        if self.photo.len() > PHOTO_MAX
            || !self.photo.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        {
            self.photo.clear();
        }
        if self.wallpaper == Wallpaper::Photo && self.photo.is_empty() {
            self.wallpaper = Wallpaper::None;
        }
    }

    /// Short tag that changes with the photo, so the page loads the new one.
    pub fn photo_tag(&self) -> String {
        let h = self
            .photo
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325_u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3));
        format!("{h:016x}")
    }

    /// Stores a cleaned JPEG as the wallpaper and switches to it.
    pub fn set_photo(&mut self, jpeg: &[u8]) {
        self.photo = b64(jpeg);
        self.wallpaper = Wallpaper::Photo;
        self.sanitize();
    }

    pub fn photo_bytes(&self) -> Option<Vec<u8>> {
        if self.photo.is_empty() {
            None
        } else {
            unb64(&self.photo)
        }
    }

    /// Gradient stops for bubbles and the header, and for buttons and badges.
    pub fn stops(&self) -> (Vec<String>, Vec<String>) {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        match PRESETS.iter().find(|p| p.0 == self.theme) {
            Some((_, b, a)) => (own(b), own(a)),
            None => (self.custom.clone(), self.custom.clone()),
        }
    }

    /// Applies one change from the settings page. Returns false for an unknown key or value.
    pub fn set(&mut self, key: &str, value: &str) -> bool {
        let num = |v: &str| v.trim().parse::<u32>().ok();
        let flag = |v: &str| match v {
            "true" | "on" => Some(true),
            "false" | "off" => Some(false),
            _ => None,
        };
        let ok = match key {
            "theme" if value == "custom" || PRESETS.iter().any(|p| p.0 == value) => {
                self.theme = value.to_owned();
                true
            }
            "c1" | "c2" | "c3" => {
                let i = usize::from(key.as_bytes()[1] - b'1');
                match (color(value), value.is_empty()) {
                    (Some(c), _) if i <= self.custom.len() => {
                        if i == self.custom.len() {
                            self.custom.push(c);
                        } else {
                            self.custom[i] = c;
                        }
                        self.theme = "custom".to_owned();
                        true
                    }
                    (None, true) if i == 2 => {
                        self.custom.truncate(2);
                        true
                    }
                    _ => false,
                }
            }
            "animated" => flag(value).map(|f| self.animated = f).is_some(),
            "depth" => flag(value).map(|f| self.depth = f).is_some(),
            "motion" => Motion::parse(value).map(|v| self.motion = v).is_some(),
            "list" => ListPos::parse(value).map(|v| self.list = v).is_some(),
            "density" => Density::parse(value).map(|v| self.density = v).is_some(),
            "bubble" => Bubble::parse(value).map(|v| self.bubble = v).is_some(),
            "wallpaper" => Wallpaper::parse(value).map(|v| self.wallpaper = v).is_some(),
            "avatar" => AvatarShape::parse(value).map(|v| self.avatar = v).is_some(),
            "wall_scope" => Scope::parse(value).map(|v| self.wall_scope = v).is_some(),
            "wall_dim" => num(value).map(|n| self.wall_dim = n.min(255) as u8).is_some(),
            "effect" => Effect::parse(value).map(|v| self.effect = v).is_some(),
            "effect_scope" => Scope::parse(value).map(|v| self.effect_scope = v).is_some(),
            "photo" if value.is_empty() => {
                self.photo.clear();
                true
            }
            "list_width" => num(value).map(|n| self.list_width = n.min(u32::from(u16::MAX)) as u16).is_some(),
            "radius" => num(value).map(|n| self.radius = n.min(255) as u8).is_some(),
            "font" => num(value).map(|n| self.font = n.min(255) as u8).is_some(),
            _ => false,
        };
        self.sanitize();
        ok
    }

    /// What the page applies to the document: CSS variables and data attributes.
    pub fn to_json(&self, info: bool) -> Value {
        let (bubble, accent) = self.stops();
        let (cols, rows, areas) = shell_grid(self.list, info);
        json!({
            "bubble": bubble,
            "accent": accent,
            "ink": ink(&bubble),
            "on_accent": ink(&accent),
            "animated": self.animated,
            "motion": self.motion.id(),
            "depth": self.depth,
            "list": self.list.id(),
            "width": self.list_width,
            "density": self.density.id(),
            "shape": self.bubble.id(),
            "radius": self.radius,
            "font": self.font,
            "wall": self.wallpaper.id(),
            "avatar": self.avatar.id(),
            "wall_scope": self.wall_scope.id(),
            "dim": self.wall_dim,
            "photo": if self.wallpaper == Wallpaper::Photo { format!("/wall/{}", self.photo_tag()) } else { String::new() },
            "fx": self.effect.id(),
            "fx_scope": self.effect_scope.id(),
            "cols": cols,
            "rows": rows,
            "areas": areas,
        })
    }
}

fn seg<T: Copy + PartialEq>(l: Lang, key: &str, all: &[T], cur: T, id: impl Fn(T) -> &'static str) -> String {
    let mut h = format!(r#"<div class="f"><span>{}</span><div class="seg" role="group">"#, esc(tr(l, &format!("look.{key}"))));
    for v in all {
        h.push_str(&format!(
            r#"<button type="button" class="sg{}" aria-pressed="{}" data-act="set_look" data-key="{key}" data-value="{}">{}</button>"#,
            if *v == cur { " on" } else { "" },
            *v == cur,
            id(*v),
            esc(tr(l, &format!("look.{key}_{}", id(*v))))
        ));
    }
    h.push_str("</div></div>");
    h
}

fn toggle(l: Lang, key: &str, on: bool) -> String {
    format!(
        r#"<label class="chk"><input type="checkbox" data-look="{key}"{}><span>{}</span></label><p class="note">{}</p>"#,
        if on { " checked" } else { "" },
        esc(tr(l, &format!("look.{key}"))),
        esc(tr(l, &format!("look.{key}_note")))
    )
}

fn range(l: Lang, key: &str, min: u32, max: u32, cur: u32) -> String {
    format!(
        r#"<label class="f"><span>{}<strong class="rv">{cur}</strong></span><input type="range" min="{min}" max="{max}" step="1" value="{cur}" data-look="{key}"></label>"#,
        esc(tr(l, &format!("look.{key}")))
    )
}

/// The Appearance section of the settings page, below the language card.
pub fn page(l: Lang, look: &Look) -> String {
    let mut sw = String::new();
    for (id, b, _) in PRESETS {
        sw.push_str(&format!(
            r#"<button type="button" class="sw{}" aria-pressed="{}" data-act="set_look" data-key="theme" data-value="{id}" data-stops="{}" title="{}"><span class="swc"></span><span class="swl">{}</span></button>"#,
            if look.theme == id { " on" } else { "" },
            look.theme == id,
            b.join(" "),
            esc(tr(l, &format!("look.theme_{id}"))),
            esc(tr(l, &format!("look.theme_{id}")))
        ));
    }
    let custom_on = look.theme == "custom";
    sw.push_str(&format!(
        r#"<button type="button" class="sw{}" aria-pressed="{custom_on}" data-act="set_look" data-key="theme" data-value="custom" data-stops="{}"><span class="swc"></span><span class="swl">{}</span></button>"#,
        if custom_on { " on" } else { "" },
        look.custom.join(" "),
        esc(tr(l, "look.theme_custom"))
    ));
    let mut picks = String::new();
    for i in 0..3 {
        let v = look.custom.get(i).cloned().unwrap_or_else(|| "#ffffff".to_owned());
        picks.push_str(&format!(
            r#"<label class="pick{}"><input type="color" value="{v}" data-look="c{}" aria-label="{} {}"></label>"#,
            if i >= look.custom.len() { " unset" } else { "" },
            i + 1,
            esc(tr(l, "look.color")),
            i + 1
        ));
    }
    if look.custom.len() == 3 {
        picks.push_str(&format!(
            r#"<button type="button" class="btn ghost" data-act="set_look" data-key="c3" data-value="">{}</button>"#,
            esc(tr(l, "look.two_colors"))
        ));
    }
    let preview = format!(
        r#"<div class="pv" aria-hidden="true"><div class="pvhead"><span class="pvav"></span><span class="pvname">{}</span></div><div class="pvmsgs"><div class="m in first last"><div class="bubble"><div class="t">{}</div></div></div><div class="m out first last"><div class="bubble"><div class="t">{}</div></div></div></div></div>"#,
        esc(tr(l, "look.pv_name")),
        esc(tr(l, "look.pv_in")),
        esc(tr(l, "look.pv_out"))
    );
    format!(
        r#"<section class="card"><h2>{}</h2>{preview}<div class="f"><span>{}</span><div class="sws">{sw}</div></div><div class="picks">{picks}</div><p class="note">{}</p>{}</section><section class="card"><h2>{}</h2>{}{}{}</section><section class="card"><h2>{}</h2>{}{}{}</section><section class="card"><h2>{}</h2>{}{}{}{}</section>{}<section class="card"><div class="row"><button type="button" class="btn" data-act="reset_look">{}</button></div></section>"#,
        esc(tr(l, "look.title")),
        esc(tr(l, "look.theme")),
        esc(tr(l, "look.custom_note")),
        toggle(l, "animated", look.animated),
        esc(tr(l, "look.motion_title")),
        seg(l, "motion", Motion::ALL, look.motion, Motion::id),
        p_note(l, "look.motion_note"),
        toggle(l, "depth", look.depth),
        esc(tr(l, "look.layout")),
        seg(l, "list", ListPos::ALL, look.list, ListPos::id),
        seg(l, "density", Density::ALL, look.density, Density::id),
        p_note(l, "look.width_note"),
        esc(tr(l, "look.messages")),
        seg(l, "bubble", Bubble::ALL, look.bubble, Bubble::id),
        range(l, "radius", 0, u32::from(RADIUS_MAX), u32::from(look.radius)),
        range(l, "font", u32::from(FONT_MIN), u32::from(FONT_MAX), u32::from(look.font)),
        seg(l, "avatar", AvatarShape::ALL, look.avatar, AvatarShape::id),
        backdrop(l, look),
        esc(tr(l, "look.reset"))
    )
}

fn p_note(l: Lang, key: &str) -> String {
    format!(r#"<p class="note">{}</p>"#, esc(tr(l, key)))
}

/// Wallpaper and screen effects.
fn backdrop(l: Lang, look: &Look) -> String {
    let remove = if look.photo.is_empty() {
        String::new()
    } else {
        format!(
            r#"<button type="button" class="btn ghost" data-act="set_look" data-key="photo" data-value="">{}</button>"#,
            esc(tr(l, "look.photo_remove"))
        )
    };
    format!(
        r#"<section class="card"><h2>{}</h2>{}<div class="row"><button type="button" class="btn" data-act="pick_wall">{}</button>{remove}</div>{}{}<p class="note">{}</p>{}{}{}</section>"#,
        esc(tr(l, "look.backdrop")),
        seg(l, "wallpaper", Wallpaper::ALL, look.wallpaper, Wallpaper::id),
        esc(tr(l, "look.photo_pick")),
        seg(l, "wall_scope", Scope::ALL, look.wall_scope, Scope::id),
        range(l, "wall_dim", 0, u32::from(DIM_MAX), u32::from(look.wall_dim)),
        esc(tr(l, "look.photo_note")),
        seg(l, "effect", Effect::ALL, look.effect, Effect::id),
        seg(l, "effect_scope", Scope::ALL, look.effect_scope, Scope::id),
        p_note(l, "look.effect_note")
    )
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(c.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(c.get(2).copied().unwrap_or(0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in s.trim_end_matches('=').bytes() {
        let v = B64.iter().position(|&x| x == b)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod backdrop_tests {
    use super::*;

    #[test]
    fn base64_round_trip() {
        for n in 0..20u8 {
            let v: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(unb64(&b64(&v)).unwrap(), v);
        }
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64(b"fo"), "Zm8=");
    }

    #[test]
    fn photo_and_effects() {
        let mut l = Look::default();
        l.set("wallpaper", "photo");
        assert_eq!(l.wallpaper, Wallpaper::None);
        l.set_photo(&[0xff, 0xd8, 0xff]);
        assert_eq!(l.wallpaper, Wallpaper::Photo);
        assert_eq!(l.photo_bytes().unwrap(), vec![0xff, 0xd8, 0xff]);
        assert!(l.set("photo", ""));
        assert_eq!(l.wallpaper, Wallpaper::None);
        assert!(l.set("effect", "snow") && l.set("effect_scope", "full"));
        assert_eq!(l.to_json(false)["fx"], "snow");
        assert!(!l.set("effect", "fire"));
    }
}
