#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A chunk size near usize::MAX is rejected instead of overflowing the length arithmetic.
use std::io::Cursor;
use std::time::{Duration, Instant};

#[test]
fn chunked_huge_size_does_not_panic() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nffffffffffffffff\r\nxx\r\n0\r\n\r\n".to_vec();
    let r = std::panic::catch_unwind(|| {
        aegis_core::net::read_response(&mut Cursor::new(raw), Instant::now() + Duration::from_secs(5))
    });
    assert!(r.is_ok(), "client response parser panicked on a crafted chunk size");
    assert!(r.unwrap().is_err());
}
