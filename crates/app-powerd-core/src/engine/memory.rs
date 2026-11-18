//! Low-memory killer.
//!
//! When `MemAvailable` or PSI crosses the configured line, the least recently
//! used background application is SIGTERMed, then SIGKILLed after `kill_grace`.
//! A protected application is never chosen, and neither is one who is playing audio,
//! using the camera or fullscreen.

use std::time::{Duration, Instant};

use nix::sys::signal::Signal;
use tracing::{debug, info};

use super::*;
use crate::config::{Action, GuardAction, GuardsConfig, ReclaimAmount};
use crate::system::memory::{self, PressureSample};

/// A kill that has been started and may still need to be escalated.
pub(crate) struct PendingKill {
    handles: Vec<ProcessHandle>,
    deadline: Instant,
}

/// One tracked application, reduced to what the ranking decision needs.
pub(crate) struct VictimSnap<'a> {
    pub id: &'a str,
    pub state: AppState,
    pub action: Action,
    pub protected: bool,
    pub last_active: Instant,
}

/// Background apps that may be killed, oldest focus first.
pub(crate) fn rank_victims<'a>(apps: &'a [VictimSnap<'a>], pending: &[&str]) -> Vec<&'a str> {
    let mut ranked: Vec<_> = apps
        .iter()
        .filter(|app| {
            matches!(
                app.state,
                AppState::Background | AppState::Throttled | AppState::Frozen
            ) && app.action != Action::Ignore
                && !app.protected
                && !pending.iter().any(|id| *id == app.id)
        })
        .collect();
    ranked.sort_by_key(|app| app.last_active);
    ranked.into_iter().map(|app| app.id).collect()
}

impl Engine {
    pub(crate) async fn handle_memory_check(&mut self) {
        self.drop_finished_kills();
        self.escalate_kills();

        let memory = self.rules_engine.config().defaults.memory.clone();
        if !memory.killer_enabled() || !self.should_manage() {
            return;
        }

        let base = self.cgroup_mgr.base_path().to_path_buf();
        let sample = tokio::task::spawn_blocking(move || memory::sample(&base))
            .await
            .unwrap_or(PressureSample {
                available: None,
                psi_some_avg10: None,
            });
        if !memory::pressure_tripped(sample, memory.available_min, memory.psi_some_avg10) {
            return;
        }

        let ranked = self.ranked_victim_ids();
        for id in ranked.into_iter().take(4) {
            if self.guard_holds(&id).await {
                debug!(app_id = %id, "memory pressure: skipping app held by a guard");
                continue;
            }
            self.begin_kill(&id, memory.kill_grace, sample);
            break;
        }
    }

    /// One-shot `memory.reclaim` for an app that just left
    /// the foreground.
    pub(crate) fn apply_background_memory(&mut self, app_id: &AppId) {
        if !self.cgroup_mgr.supports_memory_control() {
            return;
        }
        let (path, high, reclaim, already) = {
            let Some(entry) = self.registry.get(app_id) else {
                return;
            };
            let Some(path) = entry.cgroup_path.clone() else {
                return;
            };
            (
                path,
                entry.policy.memory_high,
                entry.policy.memory_reclaim,
                entry.memory_reclaimed,
            )
        };

        if let Some(bytes) = high {
            if let Err(e) = self.cgroup_mgr.set_memory_high(&path, bytes) {
                debug!(app_id = %app_id, error = %e, "failed to set memory.high");
            }
        }
        if already {
            return;
        }
        let Some(amount) = reclaim else {
            return;
        };
        let result = match amount {
            ReclaimAmount::Bytes(n) => self.cgroup_mgr.reclaim(&path, n),
            ReclaimAmount::Current => self.cgroup_mgr.reclaim_current(&path),
        };
        match result {
            Ok(()) => {
                METRICS
                    .memory_reclaims_total
                    .fetch_add(1, Ordering::Relaxed);
                if let Some(entry) = self.registry.get_mut(app_id) {
                    entry.memory_reclaimed = true;
                }
            }
            Err(e) => debug!(app_id = %app_id, error = %e, "memory.reclaim failed"),
        }
    }

    /// Drop the background memory cap when the app is focused again.
    pub(crate) fn clear_background_memory(&mut self, app_id: &AppId) {
        if !self.cgroup_mgr.supports_memory_control() {
            return;
        }
        let Some(path) = self
            .registry
            .get(app_id)
            .and_then(|entry| entry.cgroup_path.clone())
        else {
            return;
        };
        self.cgroup_mgr.reset_memory_high(&path);
    }

    fn ranked_victim_ids(&self) -> Vec<AppId> {
        let pending: Vec<String> = self
            .pending_kills
            .keys()
            .map(|id| id.as_str().to_string())
            .collect();
        let rows: Vec<_> = self
            .registry
            .iter()
            .map(|(id, entry)| {
                (
                    id.clone(),
                    entry.state(),
                    entry.policy().action,
                    entry.window_info().clone(),
                    entry.last_active,
                )
            })
            .collect();
        let snaps: Vec<VictimSnap> = rows
            .iter()
            .map(|(id, state, action, window, last_active)| VictimSnap {
                id: id.as_str(),
                state: *state,
                action: *action,
                protected: self.protection_verdict(window).is_some(),
                last_active: *last_active,
            })
            .collect();
        let pending_refs: Vec<&str> = pending.iter().map(String::as_str).collect();
        rank_victims(&snaps, &pending_refs)
            .into_iter()
            .filter_map(|name| {
                rows.iter()
                    .find(|(id, ..)| id.as_str() == name)
                    .map(|(id, ..)| id.clone())
            })
            .collect()
    }

    async fn guard_holds(&mut self, app_id: &AppId) -> bool {
        let Some((pids, fullscreen)) = self
            .registry
            .get(app_id)
            .map(|entry| (entry.pids(), entry.window_info().is_fullscreen))
        else {
            return true;
        };
        // These three are unconditional: a profile that ignores the audio guard
        // for suspend must still not be killed while it is playing.
        let guards = GuardsConfig {
            audio_active: GuardAction::Check,
            mic_active: GuardAction::Check,
            camera_active: GuardAction::Check,
            fullscreen: GuardAction::Check,
            input_idle: None,
        };
        guards::check_guards(&pids, &guards, fullscreen).await != GuardResult::Allow
    }

    fn begin_kill(&mut self, app_id: &AppId, grace: Duration, sample: PressureSample) {
        let Some(entry) = self.registry.get(app_id) else {
            return;
        };
        if entry.killing {
            return;
        }
        let state = entry.state();
        let path = entry.cgroup_path.clone();
        // shortcut: signal the window owners only, expand the tree if orphaned
        // helpers keep the memory after the main process is gone.
        let handles = entry.roots().handles().to_vec();

        if state == AppState::Frozen {
            let report = freeze::thaw_app(&self.cgroup_mgr, path.as_deref(), &handles);
            self.warn_partial_failure(app_id, "kill-thaw", &report);
        }
        if let Some(entry) = self.registry.get_mut(app_id) {
            entry.cancel_all_timers();
            entry.killing = true;
        }

        for handle in &handles {
            if handle.is_alive() {
                let _ = signal_process(handle.pid, Signal::SIGTERM);
            }
        }
        info!(
            app_id = %app_id,
            available = ?sample.available,
            psi_some_avg10 = ?sample.psi_some_avg10,
            grace_ms = grace.as_millis(),
            "memory pressure: sent SIGTERM to the least recently used background app"
        );
        METRICS.apps_killed_total.fetch_add(1, Ordering::Relaxed);
        self.pending_kills.insert(
            app_id.clone(),
            PendingKill {
                handles,
                deadline: Instant::now() + grace,
            },
        );
    }

    fn escalate_kills(&mut self) {
        let due: Vec<AppId> = self
            .pending_kills
            .iter()
            .filter(|(_, pending)| pending.deadline <= Instant::now())
            .map(|(id, _)| id.clone())
            .collect();
        for app_id in due {
            let Some(pending) = self.pending_kills.remove(&app_id) else {
                continue;
            };
            let mut alive = false;
            for handle in &pending.handles {
                if handle.is_alive() {
                    alive = true;
                    let _ = signal_process(handle.pid, Signal::SIGKILL);
                }
            }
            if alive {
                info!(app_id = %app_id, "memory pressure: SIGKILL after grace period");
            }
        }
    }

    fn drop_finished_kills(&mut self) {
        self.pending_kills.retain(|app_id, pending| {
            let focused = self
                .registry
                .get(app_id)
                .is_some_and(|entry| entry.state() == AppState::Active);
            if focused {
                return false;
            }
            pending.handles.iter().any(ProcessHandle::is_alive)
        });
    }
}

fn signal_process(pid: u32, signal: Signal) -> Result<(), crate::error::SystemError> {
    match signal {
        Signal::SIGTERM => freeze::signal_term(pid),
        Signal::SIGKILL => freeze::signal_kill(pid),
        _ => freeze::signal_term(pid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap<'a>(
        id: &'a str,
        state: AppState,
        action: Action,
        protected: bool,
        age: Duration,
    ) -> VictimSnap<'a> {
        VictimSnap {
            id,
            state,
            action,
            protected,
            last_active: Instant::now() - age,
        }
    }

    #[test]
    fn oldest_background_app_is_first() {
        let apps = [
            snap(
                "new",
                AppState::Background,
                Action::Freeze,
                false,
                Duration::from_secs(5),
            ),
            snap(
                "old",
                AppState::Frozen,
                Action::Freeze,
                false,
                Duration::from_secs(50),
            ),
            snap(
                "active",
                AppState::Active,
                Action::Freeze,
                false,
                Duration::from_secs(100),
            ),
            snap(
                "protected",
                AppState::Background,
                Action::Freeze,
                true,
                Duration::from_secs(200),
            ),
            snap(
                "ignored",
                AppState::Throttled,
                Action::Ignore,
                false,
                Duration::from_secs(300),
            ),
        ];
        assert_eq!(rank_victims(&apps, &[]), vec!["old", "new"]);
    }

    #[test]
    fn pending_kill_is_not_chosen_again() {
        let apps = [snap(
            "old",
            AppState::Frozen,
            Action::Freeze,
            false,
            Duration::from_secs(50),
        )];
        assert!(rank_victims(&apps, &["old"]).is_empty());
    }
}
