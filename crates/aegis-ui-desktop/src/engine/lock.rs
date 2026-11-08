//! App lock settings. Unlocking always needs the password or PIN, since the vault key comes
//! from it; these only decide when an open account locks again.

use super::*;

impl Engine {
    /// `on` enables the idle lock, `minimized` also locks when the window is minimized.
    pub fn set_lock(&self, on: bool, minimized: bool) -> Result<(), Failure> {
        self.mutate(|s| {
            s.data.settings.app_lock = on;
            s.data.settings.lock_min = on && minimized;
        })
        .ok_or(Failure::new("err.locked"))
    }

    pub fn lock_on_minimize(&self) -> bool {
        self.app()
            .session
            .as_ref()
            .is_some_and(|s| s.data.settings.app_lock && s.data.settings.lock_min)
    }
}
