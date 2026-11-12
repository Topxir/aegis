//! Default avatars generated from the identity key (spec section 17).

use crate::sha256;

/// 5x5 grid plus two gray levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Avatar {
    pub cells: [[bool; 5]; 5],
    pub bg: u8,
    pub fg: u8,
}

impl Avatar {
    /// Derives the avatar of `ed_pk`.
    pub fn from_ed_pk(ed_pk: &[u8; 32]) -> Self {
        let h = sha256(&[b"aegis-v2 avatar", ed_pk]);
        let mut cells = [[false; 5]; 5];
        for (r, row) in cells.iter_mut().enumerate() {
            for c in 0..3 {
                let k = r * 3 + c;
                let on = (h[k / 8] >> (k % 8)) & 1 == 1;
                row[c] = on;
                row[4 - c] = on;
            }
        }
        Avatar {
            cells,
            bg: 0x1c + h[2] % 0x18,
            fg: 0xa0 + h[3] % 0x50,
        }
    }

    /// Row-major 25-character string of `0`/`1` (used by the test vectors).
    pub fn mask_string(&self) -> String {
        self.cells
            .iter()
            .flatten()
            .map(|&on| if on { '1' } else { '0' })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_and_in_range() {
        for i in 0..=255u8 {
            let a = Avatar::from_ed_pk(&[i; 32]);
            for row in &a.cells {
                assert_eq!(row[0], row[4]);
                assert_eq!(row[1], row[3]);
            }
            assert!((0x1c..0x1c + 0x18).contains(&a.bg));
            assert!((0xa0..0xa0 + 0x50).contains(&a.fg));
            assert_eq!(a.mask_string().len(), 25);
        }
        assert_ne!(Avatar::from_ed_pk(&[1; 32]), Avatar::from_ed_pk(&[2; 32]));
    }
}
