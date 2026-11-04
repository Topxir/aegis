//! Native window: tao + wry, assets served from memory over a custom protocol.
//! There is no network listener and the page cannot leave the app origin.

use crate::assets::{lookup, CSP};
use crate::config::Config;
use crate::controller::Controller;
use crate::engine::{Engine, Job};
use crate::ipc;
use crate::render;
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::{UserAttentionType, WindowBuilder};
use wry::http::{header, Request, Response, StatusCode};
use wry::{
    NewWindowResponse, PermissionResponse, WebContext, WebViewBuilder, WebViewBuilderExtWindows,
};

#[derive(Debug, Clone, Copy)]
enum UiEvent {
    Refresh,
}

fn respond(
    status: StatusCode,
    mime: &str,
    body: Cow<'static, [u8]>,
) -> Response<Cow<'static, [u8]>> {
    let mut b = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, mime)
        .header("Content-Security-Policy", CSP)
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("Cache-Control", "no-store");
    if mime.starts_with("text/html") {
        b = b.header("X-Frame-Options", "DENY");
    }
    b.body(body)
        .unwrap_or_else(|_| Response::new(Cow::Borrowed(&[][..])))
}

fn serve(req: &Request<Vec<u8>>) -> Response<Cow<'static, [u8]>> {
    if req.method() != wry::http::Method::GET {
        return respond(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain",
            Cow::Borrowed(b""),
        );
    }
    match lookup(req.uri().path()) {
        Some((mime, bytes)) => respond(StatusCode::OK, mime, Cow::Borrowed(bytes)),
        None => respond(StatusCode::NOT_FOUND, "text/plain", Cow::Borrowed(b"")),
    }
}

fn jitter_ms() -> u64 {
    aegis_core::random_bytes::<2>().map_or(2500, |b| u64::from(u16::from_le_bytes(b)) % 5000)
}

/// Runs the application until the window is closed.
pub fn run(cfg: Config) -> Result<(), String> {
    let event_loop = EventLoopBuilder::<UiEvent>::with_user_event().build();
    let proxy = Mutex::new(event_loop.create_proxy());
    let pending = Arc::new(AtomicBool::new(false));
    let pending_tx = Arc::clone(&pending);
    let web_dir = cfg.data_dir.join("webview");
    std::fs::create_dir_all(&web_dir).map_err(|e| format!("data directory: {e}"))?;

    let engine = Engine::new(cfg, move || {
        if !pending_tx.swap(true, Ordering::AcqRel) {
            if let Ok(p) = proxy.lock() {
                let _ = p.send_event(UiEvent::Refresh);
            }
        }
    });
    let (jobs_tx, jobs_rx) = channel::<Job>();
    let ctl = Controller::new(Arc::clone(&engine), jobs_tx.clone());

    let worker_engine = Arc::clone(&engine);
    std::thread::spawn(move || {
        while let Ok(job) = jobs_rx.recv() {
            if matches!(job, Job::Stop) {
                break;
            }
            worker_engine.exec(job);
        }
    });

    let (kick_tx, kick_rx) = channel::<()>();
    engine.set_kick(kick_tx);
    let poll_engine = Arc::clone(&engine);
    let poll_ctl = ctl.clone();
    std::thread::spawn(move || {
        let mut next = Instant::now() + Duration::from_secs(5);
        loop {
            match kick_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => next = Instant::now(),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            if poll_engine.idle_expired() {
                poll_ctl.lock();
            }
            if Instant::now() >= next {
                poll_engine.poll_once();
                next = Instant::now() + Duration::from_millis(5000 + jitter_ms());
            } else {
                poll_engine.sweep();
            }
        }
    });

    let window = WindowBuilder::new()
        .with_title("Aegis")
        .with_inner_size(LogicalSize::new(1040.0, 720.0))
        .with_min_inner_size(LogicalSize::new(560.0, 420.0))
        .build(&event_loop)
        .map_err(|e| format!("window: {e}"))?;

    let mut context = WebContext::new(Some(web_dir));
    let ipc_ctl = ctl.clone();
    let builder = WebViewBuilder::new_with_web_context(&mut context)
        .with_https_scheme(true)
        .with_incognito(true)
        .with_devtools(cfg!(debug_assertions))
        .with_browser_accelerator_keys(false)
        .with_default_context_menus(false)
        .with_custom_protocol("aegis".into(), |_, req| serve(&req))
        .with_ipc_handler(move |req| {
            let origin = req.uri().to_string();
            if let Ok(cmd) = ipc::parse(&origin, req.body()) {
                ipc_ctl.handle(cmd);
            }
        })
        .with_navigation_handler(|url| ipc::origin_allowed(&url))
        .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
        .with_permission_handler(|_| PermissionResponse::Deny)
        .with_download_started_handler(|_, _| false)
        .with_url("aegis://localhost/");
    let webview = builder
        .build(&window)
        .map_err(|e| format!("webview: {e}"))?;

    let flush_engine = Arc::clone(&engine);
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(UiEvent::Refresh) => {
                pending.store(false, Ordering::Release);
                let json = render::view(&engine.app()).to_string();
                let _ =
                    webview.evaluate_script(&format!("window.aegis&&window.aegis.render({json})"));
                if engine.take_attention() && !window.is_focused() {
                    window.request_user_attention(Some(UserAttentionType::Informational));
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if let Some(s) = flush_engine.detach() {
                    flush_engine.persist(s);
                }
                let _ = jobs_tx.send(Job::Stop);
                *flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });
}
