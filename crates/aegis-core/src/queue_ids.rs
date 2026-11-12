//! Queue id derivations.

use crate::{hex, hkdf32, sha256, Result};

/// Inbox queue of a user: `SHA256("aegis-v2 inbox" || x_pk)`.
pub fn inbox_queue(x_pk: &[u8; 32]) -> [u8; 32] {
    sha256(&[b"aegis-v2 inbox", x_pk])
}

/// Group queue: `HKDF(G, "", "aegis-v2 group-queue", 32)`.
pub fn group_queue(g: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(*hkdf32(g, b"", b"aegis-v2 group-queue")?)
}

/// Channel queue: `HKDF(G, "", "aegis-v2 channel-queue", 32)`.
pub fn channel_queue(g: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(*hkdf32(g, b"", b"aegis-v2 channel-queue")?)
}

pub fn queue_hex(q: &[u8; 32]) -> String {
    hex::encode(q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_and_stable() {
        let k = [5u8; 32];
        assert_eq!(inbox_queue(&k), inbox_queue(&k));
        assert_ne!(inbox_queue(&k), group_queue(&k).unwrap());
        assert_eq!(queue_hex(&inbox_queue(&k)).len(), 64);
    }
}
