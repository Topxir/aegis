//! Profile card body, `PF1` (spec section 22).

use crate::{Error, Result};

pub const MAX_NAME: usize = 64;
pub const MAX_ABOUT: usize = 140;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Particles {
    None,
    Dust,
    Snow,
    Embers,
    Orbit,
    Rain,
}

impl Particles {
    pub fn as_str(self) -> &'static str {
        match self {
            Particles::None => "none",
            Particles::Dust => "dust",
            Particles::Snow => "snow",
            Particles::Embers => "embers",
            Particles::Orbit => "orbit",
            Particles::Rain => "rain",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "none" => Particles::None,
            "dust" => Particles::Dust,
            "snow" => Particles::Snow,
            "embers" => Particles::Embers,
            "orbit" => Particles::Orbit,
            "rain" => Particles::Rain,
            _ => return Err(Error::InvalidEnvelope("particles")),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub about: String,
    pub particles: Particles,
}

/// Bidi controls and zero-width characters, which let a name read as another one.
pub fn is_spoofing_char(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

fn check(s: &str, max: usize, what: &'static str) -> Result<()> {
    if s.chars().count() > max || s.chars().any(|c| c.is_control() || is_spoofing_char(c)) {
        return Err(Error::InvalidEnvelope(what));
    }
    Ok(())
}

impl Profile {
    fn validate(&self) -> Result<()> {
        check(&self.name, MAX_NAME, "profile name")?;
        check(&self.about, MAX_ABOUT, "profile about")
    }

    /// The 4-line envelope body (before percent-encoding).
    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        Ok(format!("PF1\n{}\n{}\n{}", self.name, self.about, self.particles.as_str()))
    }

    /// Strict parser: exactly four lines, header `PF1`, no control characters, known particles.
    pub fn parse(body: &str) -> Result<Self> {
        let lines: Vec<&str> = body.split('\n').collect();
        let [hdr, name, about, particles] = lines.as_slice() else {
            return Err(Error::InvalidEnvelope("profile lines"));
        };
        if *hdr != "PF1" {
            return Err(Error::InvalidEnvelope("profile header"));
        }
        let p = Profile {
            name: (*name).to_owned(),
            about: (*about).to_owned(),
            particles: Particles::parse(particles)?,
        };
        p.validate()?;
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> Profile {
        Profile { name: "Alice \u{00e9}".into(), about: "hi %41 <b>".into(), particles: Particles::Snow }
    }

    #[test]
    fn roundtrip_and_strict() {
        assert_eq!(Profile::parse(&p().encode().unwrap()).unwrap(), p());
        let empty = Profile { name: String::new(), about: String::new(), particles: Particles::None };
        assert_eq!(Profile::parse(&empty.encode().unwrap()).unwrap(), empty);
        let long_name = format!("PF1\n{}\nx\nnone", "n".repeat(65));
        let long_about = format!("PF1\nn\n{}\nnone", "a".repeat(141));
        let bad = [
            "PF2\nn\nx\nnone",
            "PF1\nn\nx\nsparkle",
            "PF1\nn\nx\nSnow",
            "PF1\nn\nx",
            "PF1\nn\nx\nnone\nextra",
            "PF1\nPF1\nn\nx\nnone",
            "PF1\nn\u{7}\nx\nnone",
            "PF1\nn\nx\ty\nnone",
            "PF1\nn\nx\r\nnone",
            "PF1\nn\nx\u{85}\nnone",
            "PF1\nadmin\u{202E}\nx\nnone",
            "PF1\nn\nx\u{2066}y\nnone",
            "PF1\nad\u{200B}min\nx\nnone",
            "PF1\n\u{FEFF}n\nx\nnone",
            "PF1\nn\nx\u{2064}\nnone",
            &long_name,
            &long_about,
            "",
        ];
        for b in bad {
            assert!(Profile::parse(b).is_err(), "{b:?}");
        }
        let ok_about = format!("PF1\nn\n{}\nnone", "a".repeat(140));
        assert!(Profile::parse(&ok_about).is_ok());
        let mut q = p();
        q.about = "a\nb".into();
        assert!(q.encode().is_err());
    }

    #[test]
    fn in_envelope() {
        use crate::envelope::tests::dm;
        use crate::envelope::{Envelope, Kind};
        let e = Envelope { kind: Kind::Prof, body: p().encode().unwrap(), ..dm() };
        let d = Envelope::decode(&e.encode().unwrap()).unwrap();
        assert_eq!(Profile::parse(&d.body).unwrap(), p());
        assert!(Envelope { group_id: "ab".repeat(32), ..e }.encode().is_err());
    }
}
