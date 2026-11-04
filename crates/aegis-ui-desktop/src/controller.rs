//! Turns parsed page commands into state changes and background jobs.

use crate::engine::{AuthTab, Dialog, Engine, Flash, Job, Route};
use crate::i18n::Lang;
use crate::ipc::Cmd;
use crate::session::{ChatRef, Failure};
use std::sync::mpsc::Sender;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Controller {
    engine: Arc<Engine>,
    jobs: Sender<Job>,
}

impl Controller {
    pub fn new(engine: Arc<Engine>, jobs: Sender<Job>) -> Self {
        Self { engine, jobs }
    }

    fn job(&self, j: Job) {
        let _ = self.jobs.send(j);
    }

    fn logged_in(&self) -> bool {
        self.engine.app().session.is_some()
    }

    fn is_busy(&self) -> bool {
        self.engine.app().busy.is_some()
    }

    fn current_chat(&self) -> Option<ChatRef> {
        match &self.engine.app().route {
            Route::Chat(r) => Some(r.clone()),
            _ => None,
        }
    }

    /// Saves in the background after a local change and refreshes the page.
    fn local_change(&self) {
        self.job(Job::Flush);
        self.engine.changed();
    }

    pub fn handle(&self, cmd: Cmd) {
        let e = &*self.engine;
        match &cmd {
            Cmd::Ping {} => {
                e.touch();
                return;
            }
            Cmd::Ready { .. } | Cmd::AuthTab { .. } | Cmd::SetLang { .. } => {}
            Cmd::Create { .. } | Cmd::Unlock { .. } | Cmd::Import { .. } => {
                if self.logged_in() {
                    return;
                }
            }
            _ => {
                if !self.logged_in() {
                    return;
                }
            }
        }
        e.touch();
        match cmd {
            Cmd::Ping {} => {}
            Cmd::Ready { lang } => {
                let has = e.has_vaults();
                let mut app = e.app();
                if app.session.is_none() {
                    if let Some(l) = Lang::from_code(&lang) {
                        app.pre_lang = l;
                    }
                    app.tab = if has {
                        AuthTab::Unlock
                    } else {
                        AuthTab::Create
                    };
                }
                drop(app);
                e.changed();
            }
            Cmd::AuthTab { tab } => {
                let mut app = e.app();
                if app.session.is_none() && app.busy.is_none() {
                    app.tab = match tab.as_str() {
                        "create" => AuthTab::Create,
                        "import" => AuthTab::Import,
                        _ => AuthTab::Unlock,
                    };
                    app.flash = None;
                }
                drop(app);
                e.changed();
            }
            Cmd::SetLang { lang } => {
                if let Some(l) = Lang::from_code(&lang) {
                    e.set_lang(l);
                    self.local_change();
                }
            }
            Cmd::Create {
                username,
                display,
                password,
                confirm,
            } => {
                if !self.is_busy() {
                    self.job(Job::Create {
                        username,
                        display,
                        password,
                        confirm,
                    });
                }
            }
            Cmd::Unlock { username, password } => {
                if !self.is_busy() {
                    self.job(Job::Unlock { username, password });
                }
            }
            Cmd::Import { path, password } => {
                if !self.is_busy() {
                    self.job(Job::Import { path, password });
                }
            }
            Cmd::Lock {} => self.lock(),
            Cmd::Nav { to, id } => self.nav(&to, &id),
            Cmd::OpenDialog { kind, id } => {
                let d = match kind.as_str() {
                    "delete_chat" => Dialog::DeleteChat(id),
                    "leave_group" => Dialog::LeaveGroup(id),
                    "delete_account" => Dialog::DeleteAccount,
                    _ => return,
                };
                e.app().dialog = Some(d);
                e.changed();
            }
            Cmd::CloseDialog {} => {
                e.app().dialog = None;
                e.changed();
            }
            Cmd::DismissFlash {} => {
                e.app().flash = None;
                e.changed();
            }
            Cmd::AddContact { username } => {
                if !self.is_busy() {
                    self.job(Job::AddContact(username));
                }
            }
            Cmd::Send { text } => {
                if let Some(chat) = self.current_chat() {
                    self.job(Job::Send { chat, text });
                }
            }
            Cmd::Retry { id } => {
                if let Some(chat) = self.current_chat() {
                    self.job(Job::Retry { chat, id });
                }
            }
            Cmd::SetTtl { ttl } => {
                if let Some(chat) = self.current_chat() {
                    e.mutate(|s| s.set_ttl(&chat, ttl));
                    self.local_change();
                }
            }
            Cmd::Verify { on } => {
                let target = match &e.app().route {
                    Route::Contact(u) => Some(u.clone()),
                    _ => None,
                };
                if let Some(u) = target {
                    e.mutate(|s| s.set_verified(&u, on));
                    self.local_change();
                }
            }
            Cmd::AcceptKey { id } => {
                e.mutate(|s| s.accept_new_keys(&id));
                self.local_change();
            }
            Cmd::DismissKey { id } => {
                e.mutate(|s| s.dismiss_warning(&id));
                self.local_change();
            }
            Cmd::CreateGroup { title, members } => {
                if !self.is_busy() {
                    self.job(Job::CreateGroup { title, members });
                }
            }
            Cmd::ResendInvite { member } => {
                let gid = match &e.app().route {
                    Route::GroupInfo(g) => Some(g.clone()),
                    _ => None,
                };
                if let Some(group) = gid {
                    self.job(Job::ResendInvite { group, member });
                }
            }
            Cmd::LeaveGroup {} => {
                let gid = match e.app().dialog.take() {
                    Some(Dialog::LeaveGroup(g)) => Some(g),
                    _ => None,
                };
                if let Some(g) = gid {
                    e.mutate(|s| s.leave_group(&g));
                    e.app().route = Route::Welcome;
                    self.local_change();
                }
            }
            Cmd::DeleteChat {} => {
                let u = match e.app().dialog.take() {
                    Some(Dialog::DeleteChat(u)) => Some(u),
                    _ => None,
                };
                if let Some(u) = u {
                    e.mutate(|s| s.delete_contact_chat(&u));
                    e.app().route = Route::Welcome;
                    self.local_change();
                }
            }
            Cmd::SaveSettings {
                endpoint,
                socks5,
                idle_min,
                flash,
            } => {
                let idle = idle_min.trim().parse::<u32>().ok();
                let r = match idle {
                    Some(n) => e.apply_settings(&endpoint, &socks5, n, flash),
                    None => Err(Failure::new("err.generic")),
                };
                e.app().flash = Some(match r {
                    Ok(()) => Flash {
                        ok: true,
                        key: "ok.saved",
                        detail: String::new(),
                    },
                    Err(f) => Flash {
                        ok: false,
                        key: f.key,
                        detail: f.detail,
                    },
                });
                e.app().conn = None;
                self.local_change();
            }
            Cmd::TestConn { endpoint, socks5 } => {
                self.job(Job::TestConnection { endpoint, socks5 });
            }
            Cmd::UpdateDisplay { display } => {
                if !self.is_busy() {
                    self.job(Job::UpdateDisplay(display));
                }
            }
            Cmd::Export { path } => self.job(Job::Export(path)),
            Cmd::DeleteAccount { confirm } => {
                e.app().dialog = None;
                self.job(Job::DeleteAccount(confirm));
            }
        }
    }

    pub fn lock(&self) {
        if let Some(s) = self.engine.detach() {
            self.job(Job::Persist(Box::new(s)));
        }
        self.engine.changed();
    }

    fn nav(&self, to: &str, id: &str) {
        let e = &*self.engine;
        let route = {
            let app = e.app();
            let Some(s) = app.session.as_ref() else {
                return;
            };
            match to {
                "welcome" => Some(Route::Welcome),
                "settings" => Some(Route::Settings),
                "new_chat" => Some(Route::NewChat),
                "new_group" => Some(Route::NewGroup),
                "dm" if s.data.contacts.contains_key(id) => {
                    Some(Route::Chat(ChatRef::Dm(id.to_owned())))
                }
                "group" if s.data.groups.contains_key(id) => {
                    Some(Route::Chat(ChatRef::Group(id.to_owned())))
                }
                "contact" if s.data.contacts.contains_key(id) => {
                    Some(Route::Contact(id.to_owned()))
                }
                "group_info" if s.data.groups.contains_key(id) => {
                    Some(Route::GroupInfo(id.to_owned()))
                }
                _ => None,
            }
        };
        let Some(route) = route else {
            return;
        };
        {
            let mut app = e.app();
            if let Route::Chat(r) = &route {
                let r = r.clone();
                if let Some(s) = app.session.as_mut() {
                    s.mark_read(&r);
                }
            }
            app.route = route;
            app.dialog = None;
            app.flash = None;
            app.conn = None;
        }
        self.local_change();
    }
}
