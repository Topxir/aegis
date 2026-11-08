//! Aegis protocol v2 server: user directory and anonymous frame queues.
//!
//! The server stores no IP addresses and keeps no request log.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod blob;
mod http;
mod state;
mod update;

pub use blob::{BlobStore, MAX_BLOB_BYTES};
pub use http::{read_request, serve, write_response, BlobReply, HttpError, Request, Response};
pub use state::{
    default_data_dir_from, handle_blob, persist_now, KEY_FILE, Config, ServerError, ServerState,
    DEFAULT_QUEUE_TTL_SECS, NOP_BURST_SECS, STATE_FILE,
};
pub use update::{handle_update, MANIFEST_FILE, UPDATE_DIR};
