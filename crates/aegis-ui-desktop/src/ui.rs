//! Native window: tao + wry, assets served from memory over a custom protocol.
//! There is no network listener and the page cannot leave the app origin.

use crate::assets::{lookup, CSP};
use crate::config::Config;
use crate::controller::Controller;
use crate::engine::cover;
use crate::engine::{Engine, Job, Route};
use crate::ipc;
use crate::media;
use crate::render;
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::platform::windows::WindowExtWindows;
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

/// Answers `/media/<id>` for photos and videos kept in the encrypted store.
fn media_response(r: media::Reply) -> Response<Cow<'static, [u8]>> {
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::NOT_FOUND);
    let mut b = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, r.mime)
        .header("Content-Security-Policy", CSP)
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("Cache-Control", "no-store")
        .header("Accept-Ranges", "bytes");
    if let Some(cr) = r.content_range {
        b = b.header("Content-Range", cr);
    }
    b.body(Cow::Owned(r.body))
        .unwrap_or_else(|_| Response::new(Cow::Borrowed(&[][..])))
}

pub fn serve_media(
    engine: &Engine,
    req: &Request<Vec<u8>>,
) -> Option<Response<Cow<'static, [u8]>>> {
    let sid = req.uri().path().strip_prefix("/media/")?;
    if req.method() != wry::http::Method::GET {
        return Some(respond(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain",
            Cow::Borrowed(b""),
        ));
    }
    let range = req
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok());
    Some(media_response(engine.media_reply(sid, range)))
}

fn serve(engine: &Engine, req: &Request<Vec<u8>>) -> Response<Cow<'static, [u8]>> {
    if let Some(r) = serve_media(engine, req) {
        return r;
    }
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
    let worker_engine = Arc::clone(&engine);
    std::thread::spawn(move || {
        while let Some(go) = worker_engine.gate.wait_poll(Duration::from_secs(1)) {
            if go {
                worker_engine.poll_once();
                worker_engine.gate.poll_done();
            }
        }
    });
    let poll_engine = Arc::clone(&engine);
    let poll_ctl = ctl.clone();
    std::thread::spawn(move || {
        let t0 = Instant::now();
        let ms = move || u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut cover = cover::Driver::new();
        let mut next = Instant::now() + Duration::from_secs(5);
        loop {
            let kicked = match kick_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => true,
                Err(RecvTimeoutError::Timeout) => false,
                Err(RecvTimeoutError::Disconnected) => {
                    poll_engine.gate.close();
                    break;
                }
            };
            if poll_engine.idle_expired() {
                poll_ctl.lock();
            }
            // While cover traffic runs, its slots decide when to poll and when to send a dummy.
            let active = poll_engine.cover_active();
            poll_engine.gate.set_on(active.is_some_and(|l| l > 0));
            let queued = poll_engine.gate.queued();
            let sizes = poll_engine.gate.take_sizes();
            let resps = poll_engine.gate.take_resps();
            match cover.step(ms(), active.is_some(), active.unwrap_or(0), queued, &sizes, &resps) {
                cover::Step::Plain => {
                    if kicked {
                        next = Instant::now();
                    }
                    if Instant::now() >= next {
                        poll_engine.poll_once();
                        next = Instant::now() + Duration::from_millis(5000 + jitter_ms());
                    } else {
                        poll_engine.sweep();
                    }
                }
                cover::Step::Wait => poll_engine.sweep(),
                cover::Step::Real => poll_engine.gate.grant(),
                cover::Step::Poll => {
                    // The cycle runs on its own thread so that its later requests can wait for
                    // slots that this loop hands out.
                    if !poll_engine.gate.start_poll() {
                        poll_engine.send_dummy(64, 1024);
                    }
                    next = Instant::now() + Duration::from_millis(5000 + jitter_ms());
                }
                cover::Step::Dummy { req_len, resp_len } => poll_engine.send_dummy(req_len, resp_len),
            }
        }
    });

    let window = WindowBuilder::new()
        .with_title("Aegis")
        .with_inner_size(LogicalSize::new(1040.0, 720.0))
        .with_min_inner_size(LogicalSize::new(560.0, 420.0))
        .build(&event_loop)
        .map_err(|e| format!("window: {e}"))?;
    let hwnd = window.hwnd();
    crate::shield::protect(hwnd, true);
    let mut tray = crate::tray::Tray::new(hwnd);

    let mut context = WebContext::new(Some(web_dir));
    let ipc_ctl = ctl.clone();
    let media_engine = Arc::clone(&engine);
    let drop_engine = Arc::clone(&engine);
    let drop_jobs = jobs_tx.clone();
    let builder = WebViewBuilder::new_with_web_context(&mut context)
        .with_https_scheme(true)
        .with_incognito(true)
        .with_devtools(cfg!(debug_assertions))
        .with_browser_accelerator_keys(false)
        .with_default_context_menus(false)
        .with_custom_protocol("aegis".into(), move |_, req| serve(&media_engine, &req))
        .with_drag_drop_handler(move |ev| {
            if let wry::DragDropEvent::Drop { paths, .. } = ev {
                let chat = match &drop_engine.app().route {
                    Route::Chat(r) => Some(r.clone()),
                    _ => None,
                };
                if let Some(chat) = chat {
                    for path in paths.into_iter().take(4) {
                        let _ = drop_jobs.send(Job::SendMedia {
                            chat: chat.clone(),
                            path,
                        });
                    }
                }
            }
            true
        })
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
    let min_ctl = ctl.clone();
    let mut protected: Option<bool> = None;
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::Wait;
        match event {
            Event::UserEvent(UiEvent::Refresh) => {
                pending.store(false, Ordering::Release);
                let (json, protect, locked) = {
                    let app = engine.app();
                    let protect = app.session.as_ref().is_none_or(|s| s.data.settings.protect);
                    (render::view(&app).to_string(), protect, app.session.is_none())
                };
                if protected != Some(protect) {
                    crate::shield::protect(hwnd, protect);
                    protected = Some(protect);
                }
                if locked {
                    tray.clear();
                }
                let _ =
                    webview.evaluate_script(&format!("window.aegis&&window.aegis.render({json})"));
                if let Some(n) = engine.take_note() {
                    if !window.is_focused() {
                        window.request_user_attention(Some(UserAttentionType::Informational));
                        tray.show(&n.title, &n.body);
                    }
                }
            }
            Event::WindowEvent {
                event: WindowEvent::Resized(_) | WindowEvent::Focused(_),
                ..
            } => {
                let minimized = window.is_minimized();
                engine.set_visible(!minimized);
                if window.is_focused() {
                    tray.clear();
                }
                if minimized && engine.lock_on_minimize() {
                    min_ctl.lock();
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                tray.clear();
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
