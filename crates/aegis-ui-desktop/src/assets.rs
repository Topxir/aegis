//! Static files compiled into the binary and the headers they are served with.

pub const CSP: &str = "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self' data:; media-src 'self'; script-src 'self'; connect-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

static INDEX: &[u8] = include_bytes!("../assets/index.html");
static CSS: &[u8] = include_bytes!("../assets/app.css");
static JS: &[u8] = include_bytes!("../assets/app.js");
static GEIST: &[u8] = include_bytes!("../assets/fonts/Geist-Variable.woff2");
static GEIST_MONO: &[u8] = include_bytes!("../assets/fonts/GeistMono-Variable.woff2");

/// Content type and bytes for a request path.
pub fn lookup(path: &str) -> Option<(&'static str, &'static [u8])> {
    match path {
        "/" | "/index.html" => Some(("text/html; charset=utf-8", INDEX)),
        "/app.css" => Some(("text/css; charset=utf-8", CSS)),
        "/app.js" => Some(("text/javascript; charset=utf-8", JS)),
        "/fonts/Geist-Variable.woff2" => Some(("font/woff2", GEIST)),
        "/fonts/GeistMono-Variable.woff2" => Some(("font/woff2", GEIST_MONO)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(path: &str) -> String {
        lookup(path)
            .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    }

    #[test]
    fn pages_have_no_inline_script_or_style() {
        let html = text("/");
        assert!(!html.is_empty());
        for bad in [
            "onclick",
            "onload",
            "onerror",
            "style=",
            "javascript:",
            "<style",
        ] {
            assert!(!html.contains(bad), "{bad}");
        }
        for s in html.split("<script").skip(1) {
            let tag = s.split('>').next().unwrap_or_default();
            assert!(tag.contains("src=\"/app.js\""), "inline script: {tag}");
        }
    }

    #[test]
    fn script_avoids_dynamic_code_and_network() {
        let js = text("/app.js");
        for bad in [
            "eval(",
            "new Function",
            "fetch(",
            "XMLHttpRequest",
            "WebSocket",
            "document.write",
            "setAttribute('style'",
        ] {
            assert!(!js.contains(bad), "{bad}");
        }
    }

    #[test]
    fn unknown_paths_are_not_served() {
        assert!(lookup("/../Cargo.toml").is_none());
        assert!(lookup("/fonts/").is_none());
        assert!(lookup("/app.js/").is_none());
    }

    #[test]
    fn font_routes_serve_woff2() {
        for p in [
            "/fonts/Geist-Variable.woff2",
            "/fonts/GeistMono-Variable.woff2",
        ] {
            let (mime, bytes) = lookup(p).unwrap_or(("", b""));
            assert!(!bytes.is_empty(), "{p}");
            assert_eq!(mime, "font/woff2");
            assert!(bytes.starts_with(b"wOF2"));
        }
        assert!(lookup("/fonts/OFL.txt").is_none());
        assert!(lookup("/fonts/Geist-Variable.woff").is_none());
        assert!(lookup("/fonts/../app.js").is_none());
    }

    #[test]
    fn csp_is_strict() {
        assert!(CSP.contains("font-src 'self';"));
        assert!(CSP.starts_with("default-src 'none'"));
        assert!(!CSP.contains("unsafe"));
        assert!(CSP.contains("connect-src 'none'"));
        assert!(CSP.contains("media-src 'self';"));
        assert!(CSP.contains("img-src 'self' data:;"));
        assert!(!CSP.contains('*'));
    }
}
