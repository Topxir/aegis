//! Aegis protocol v2 server: user directory and anonymous frame queues.
//!
//! The server stores no IP addresses and keeps no request log.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod http;
mod state;

pub use http::{read_request, serve, write_response, HttpError, Request, Response};
pub use state::{
    default_data_dir_from, persist_now, Config, ServerError, ServerState,
    DEFAULT_QUEUE_TTL_SECS, STATE_FILE,
};
