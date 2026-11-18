use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::cgroup_base_path;
use super::systemd_dbus::SystemdManager;
use crate::error::SystemError;

/// CPU period in microseconds for cgroup cpu.max (100ms).
const CPU_PERIOD_US: u32 = 100_000;

/// Cgroup capability tier (auto-detected).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupCapability {
    /// systemd transient scopes via D-Bus.
    SystemdTransient,
    /// Direct write to delegated cgroup subtree.
    DirectWrite,
    /// No cgroup access — use SIGSTOP/SIGCONT.
    SignalOnly,
}

impl std::fmt::Display for CgroupCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SystemdTransient => write!(f, "SystemdTransient"),
            Self::DirectWrite => write!(f, "DirectWrite"),
            Self::SignalOnly => write!(f, "SignalOnly"),
        }
    }
}

/// What the kernel actually lets this daemon do, established once at startup.
///
/// Being able to create a sub-cgroup does not imply being able to use it: the
/// `cpu` controller has to be enabled in the parent's `subtree_control`, which
/// on a system without delegation it is not. Probing only the directory creation
/// is why `cpu_weight` and `cpu_quota` could be configured, accepted, and then
/// silently do nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupCapabilities {
    pub tier: CgroupCapability,
    /// `cgroup.freeze` is usable, so freezing need not fall back to SIGSTOP.
    pub freezer: bool,
    /// The `cpu` controller is delegated, so `cpu.weight` / `cpu.max` work.
    pub cpu_control: bool,
    /// The `memory` controller is delegated, so `memory.high` / `memory.reclaim` work.
    pub memory_control: bool,
}

/// Leaf the daemon moves itself into so the parent cgroup can enable controllers.
const DAEMON_LEAF: &str = "daemon";

/// Controllers app cgroups need.
const WANTED_CONTROLLERS: [&str; 2] = ["cpu", "memory"];

/// The process's previous cgroup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Origin {
    /// `starttime` of the process, so a recycled PID is not sent "home" to a
    /// stranger's cgroup.
    starttime: u64,
    /// The app cgroup the process was moved into.
    app_cgroup: PathBuf,
    /// The cgroup it came from.
    origin: PathBuf,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OriginFile {
    version: u32,
    origins: HashMap<u32, Origin>,
}

const ORIGIN_FILE_VERSION: u32 = 1;

#[derive(Debug, Default)]
struct OriginStore {
    /// Persistence target; `None` keeps the store in memory only (tests).
    path: Option<PathBuf>,
    by_pid: HashMap<u32, Origin>,
}

impl OriginStore {
    fn load(path: PathBuf) -> Self {
        let by_pid = match fs::read(&path) {
            Ok(data) => match serde_json::from_slice::<OriginFile>(&data) {
                Ok(file) if file.version == ORIGIN_FILE_VERSION => file.origins,
                Ok(file) => {
                    warn!(path = %path.display(), version = file.version, "ignoring cgroup origin file of unknown version");
                    HashMap::new()
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "ignoring unreadable cgroup origin file");
                    HashMap::new()
                }
            },
            Err(_) => HashMap::new(),
        };
        Self {
            path: Some(path),
            by_pid,
        }
    }

    fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Err(e) = self.write(path) {
            warn!(path = %path.display(), error = %e, "failed to persist cgroup origins");
        }
    }

    fn write(&self, path: &Path) -> std::io::Result<()> {
        if self.by_pid.is_empty() {
            return match fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        }
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let file = OriginFile {
            version: ORIGIN_FILE_VERSION,
            origins: self.by_pid.clone(),
        };
        let json = serde_json::to_vec_pretty(&file)?;
        let tmp = path.with_extension("json.tmp");
        let mut handle = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        handle.write_all(&json)?;
        handle.sync_all()?;
        drop(handle);
        fs::rename(&tmp, path)
    }

    /// Where the process should be returned to.
    fn home_for(&self, pid: u32, starttime: Option<u64>, app_cgroup: &Path) -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        if let Some(own) = self.by_pid.get(&pid) {
            if Some(own.starttime) == starttime {
                candidates.push(own.origin.clone());
            }
        }
        for origin in self.by_pid.values() {
            if origin.app_cgroup == app_cgroup && !candidates.contains(&origin.origin) {
                candidates.push(origin.origin.clone());
            }
        }
        candidates
    }
}

/// Result of returning an app to where they came from.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EvacuationReport {
    /// Processes moved back to their original cgroup.
    pub returned: usize,
    /// Processes that are still in the app cgroup.
    pub stuck: usize,
}

/// Manages cgroup v2 operations.
pub struct CgroupManager {
    capabilities: CgroupCapabilities,
    base_path: PathBuf,
    systemd: Option<SystemdManager>,
    origins: Mutex<OriginStore>,
}

impl Default for CgroupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupManager {
    pub fn capability(&self) -> CgroupCapability {
        self.capabilities.tier
    }

    pub fn capabilities(&self) -> CgroupCapabilities {
        self.capabilities
    }

    /// Whether the cgroup freezer can be used instead of signals.
    pub fn supports_freezer(&self) -> bool {
        self.capabilities.freezer
    }

    /// Whether `cpu.weight` / `cpu.max` are actually enforced.
    pub fn supports_cpu_control(&self) -> bool {
        self.capabilities.cpu_control
    }

    /// Whether `memory.high` / `memory.reclaim` are actually enforced.
    pub fn supports_memory_control(&self) -> bool {
        self.capabilities.memory_control
    }

    /// Cgroup this manager creates app groups under.
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Detect available cgroup capability.
    pub fn new() -> Self {
        let self_cgroup = cgroup_base_path();
        // `DelegateSubgroup=daemon` (or a previous run) already lives in the leaf.
        // App cgroups belong next to that leaf, not inside it.
        let base_path = service_base(&self_cgroup);

        // Try DirectWrite first.
        if base_path.exists() {
            let probe = base_path.join("app-powerd-probe");
            let _ = fs::remove_dir(&probe);
            if fs::create_dir(&probe).is_ok() {
                let (cpu_control, memory_control) =
                    ensure_controllers(&base_path, &self_cgroup, std::process::id());
                let capabilities = CgroupCapabilities {
                    tier: CgroupCapability::DirectWrite,
                    freezer: probe.join("cgroup.freeze").exists(),
                    cpu_control,
                    memory_control,
                };
                let _ = fs::remove_dir(&probe);
                return Self {
                    capabilities,
                    base_path,
                    systemd: None,
                    origins: Mutex::default(),
                };
            }
        }

        // Try systemd transient scopes. Limits are applied later as scope
        // properties (`CPUWeight`, `CPUQuotaPerSecUSec`, `MemoryHigh`); the
        // flags are true because those properties are what this tier writes,
        // not because the daemon cgroup's `subtree_control` was probed.
        if let Some(mgr) = SystemdManager::try_connect() {
            return Self {
                capabilities: CgroupCapabilities {
                    tier: CgroupCapability::SystemdTransient,
                    freezer: true,
                    cpu_control: true,
                    memory_control: true,
                },
                base_path,
                systemd: Some(mgr),
                origins: Mutex::default(),
            };
        }

        Self {
            capabilities: CgroupCapabilities {
                tier: CgroupCapability::SignalOnly,
                freezer: false,
                cpu_control: false,
                memory_control: false,
            },
            base_path,
            systemd: None,
            origins: Mutex::default(),
        }
    }

    /// Persist the original cgroup of every moved process to `path`, loading
    /// what a previous run recorded there.
    pub fn persist_origins_at(&self, path: PathBuf) {
        *self.lock_origins() = OriginStore::load(path);
    }

    fn lock_origins(&self) -> std::sync::MutexGuard<'_, OriginStore> {
        self.origins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn is_app_cgroup(&self, path: &Path) -> bool {
        path.parent() == Some(self.base_path.as_path())
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("app-powerd-"))
    }

    /// Report the detected capabilities exactly once, at startup.
    ///
    /// Degraded operation is a warning because it silently changes what the
    /// configuration means: without the `cpu` controller the `cpu_weight` and
    /// `cpu_quota` of every throttle profile are inert, and the daemon falls
    /// back to signals for freezing. Previously this was an `info!` line about
    /// an enum name, which told the operator nothing about the consequences.
    pub fn report_capabilities(&self, cpu_profiles: &[String], memory_profiles: &[String]) {
        let caps = self.capabilities;
        if caps.tier == CgroupCapability::SignalOnly {
            warn!(
                mode = %caps.tier,
                "cgroup delegation unavailable: falling back to SIGSTOP/SIGCONT. \
                 cpu_weight and cpu_quota will NOT be applied; throttling is limited to nice. \
                 This is expected on systems without cgroup v2 delegation to the user session."
            );
        } else if !caps.cpu_control {
            warn!(
                mode = %caps.tier,
                "cgroup subtree available but the cpu controller is not delegated: \
                 cpu_weight and cpu_quota will NOT be applied; throttling is limited to nice."
            );
        } else {
            info!(
                mode = %caps.tier,
                freezer = caps.freezer,
                memory = caps.memory_control,
                "cgroup capability detected"
            );
        }

        if !caps.cpu_control && !cpu_profiles.is_empty() {
            warn!(
                profiles = %cpu_profiles.join(", "),
                "these profiles declare cpu_weight/cpu_quota that cannot be enforced in the current mode"
            );
        }
        if !caps.memory_control && !memory_profiles.is_empty() {
            warn!(
                profiles = %memory_profiles.join(", "),
                "these profiles declare memory_high/memory_reclaim that cannot be enforced in the current mode"
            );
        }
    }

    /// Create a cgroup for an application with initial PIDs.
    ///
    /// - **DirectWrite**: creates the directory; PIDs are moved separately by the caller.
    /// - **SystemdTransient**: creates a transient scope with PIDs via D-Bus.
    /// - **SignalOnly**: returns an error (no cgroup support).
    pub fn create_cgroup(&self, name: &str, pids: &[u32]) -> Result<PathBuf, SystemError> {
        match self.capabilities.tier {
            CgroupCapability::DirectWrite => {
                let sanitized = super::sanitize_unit_name(name);
                let path = self.base_path.join(format!("app-powerd-{sanitized}"));
                if !path.exists() {
                    fs::create_dir_all(&path).map_err(|e| SystemError::CgroupOperation {
                        operation: "create".into(),
                        path: path.display().to_string(),
                        source: e,
                    })?;
                    debug!(path = %path.display(), "created cgroup");
                }
                Ok(path)
            }
            CgroupCapability::SystemdTransient => {
                if let Some(ref mgr) = self.systemd {
                    mgr.start_transient_scope(name, pids, &format!("app-powerd managed: {name}"))
                } else {
                    Err(SystemError::CgroupError {
                        message: "systemd manager not available".into(),
                    })
                }
            }
            CgroupCapability::SignalOnly => Err(SystemError::NoCgroupCapability),
        }
    }

    /// Move a PID into a cgroup.
    pub fn move_pid(&self, cgroup_path: &Path, pid: u32) -> Result<(), SystemError> {
        let record = if self.capabilities.tier == CgroupCapability::DirectWrite {
            match (super::ProcessHandle::open(pid), process_cgroup(pid)) {
                (_, Some(current)) if current == cgroup_path => return Ok(()),
                (Some(handle), Some(current)) if !self.is_app_cgroup(&current) => Some(Origin {
                    starttime: handle.starttime,
                    app_cgroup: cgroup_path.to_path_buf(),
                    origin: current,
                }),
                _ => None,
            }
        } else {
            None
        };

        write_procs(cgroup_path, pid, "move_pid")?;
        debug!(pid, cgroup = %cgroup_path.display(), "moved pid to cgroup");

        if let Some(origin) = record {
            let mut store = self.lock_origins();
            store.by_pid.insert(pid, origin);
            store.persist();
        }
        Ok(())
    }

    /// Return every process in an app cgroup to the cgroup it came from.
    pub fn evacuate(&self, cgroup_path: &Path) -> EvacuationReport {
        let mut report = EvacuationReport::default();
        if self.capabilities.tier != CgroupCapability::DirectWrite {
            return report;
        }

        let mut store = self.lock_origins();
        for pid in cgroup_pids(cgroup_path) {
            let starttime = super::ProcessHandle::open(pid).map(|h| h.starttime);
            let homes = store.home_for(pid, starttime, cgroup_path);
            let returned = homes.iter().filter(|home| home.is_dir()).any(|home| {
                match write_procs(home, pid, "return_pid") {
                    Ok(()) => {
                        debug!(pid, cgroup = %home.display(), "returned pid to its original cgroup");
                        true
                    }
                    Err(e) => {
                        debug!(pid, cgroup = %home.display(), error = %e, "could not return pid");
                        false
                    }
                }
            });
            if returned {
                report.returned += 1;
                store.by_pid.remove(&pid);
            } else {
                report.stuck += 1;
            }
        }

        /// Filter out dead processes
        let still_here: Vec<u32> = cgroup_pids(cgroup_path);
        store
            .by_pid
            .retain(|pid, origin| origin.app_cgroup != cgroup_path || still_here.contains(pid));
        store.persist();

        if report.stuck > 0 {
            warn!(
                cgroup = %cgroup_path.display(),
                returned = report.returned,
                stuck = report.stuck,
                "some processes could not be returned to their original cgroup"
            );
        }
        report
    }

    /// Freeze a cgroup (cgroup v2 freezer).
    pub fn freeze(&self, cgroup_path: &Path) -> Result<(), SystemError> {
        let freeze_file = cgroup_path.join("cgroup.freeze");
        fs::write(&freeze_file, "1").map_err(|e| SystemError::CgroupOperation {
            operation: "freeze".into(),
            path: freeze_file.display().to_string(),
            source: e,
        })?;
        debug!(cgroup = %cgroup_path.display(), "cgroup frozen");
        Ok(())
    }

    /// Thaw (unfreeze) a cgroup.
    pub fn thaw(&self, cgroup_path: &Path) -> Result<(), SystemError> {
        let freeze_file = cgroup_path.join("cgroup.freeze");
        fs::write(&freeze_file, "0").map_err(|e| SystemError::CgroupOperation {
            operation: "thaw".into(),
            path: freeze_file.display().to_string(),
            source: e,
        })?;
        debug!(cgroup = %cgroup_path.display(), "cgroup thawed");
        Ok(())
    }

    /// Set cpu.weight for throttling.
    pub fn set_cpu_weight(&self, cgroup_path: &Path, weight: u32) -> Result<(), SystemError> {
        if let Some(unit) = self.scope_unit(cgroup_path) {
            return self
                .systemd
                .as_ref()
                .expect("scope unit implies a systemd manager")
                .set_u64_property(&unit, "CPUWeight", u64::from(weight));
        }
        let file = cgroup_path.join("cpu.weight");
        fs::write(&file, weight.to_string()).map_err(|e| SystemError::CgroupOperation {
            operation: "set_cpu_weight".into(),
            path: file.display().to_string(),
            source: e,
        })?;
        debug!(weight, cgroup = %cgroup_path.display(), "set cpu.weight");
        Ok(())
    }

    /// Set cpu.max for quota limiting. Format: "quota period" (microseconds).
    pub fn set_cpu_max(&self, cgroup_path: &Path, quota_pct: &str) -> Result<(), SystemError> {
        // Parse "40%" → "40000 100000"
        let pct: u32 =
            quota_pct
                .trim_end_matches('%')
                .parse()
                .map_err(|_| SystemError::CgroupError {
                    message: format!("invalid cpu quota: {quota_pct}"),
                })?;
        if pct == 0 || pct > 100 {
            return Err(SystemError::CgroupError {
                message: format!("cpu_quota must be 1-100%, got {pct}%"),
            });
        }
        let period = CPU_PERIOD_US;
        let quota = period * pct / 100;
        let value = format!("{quota} {period}");

        // systemd's property is microseconds of CPU time per second. 100% of
        // one CPU is 1_000_000, matching the percentage `cpu.max` encodes.
        if let Some(unit) = self.scope_unit(cgroup_path) {
            let usec = 1_000_000_u64 * u64::from(pct) / 100;
            return self
                .systemd
                .as_ref()
                .expect("scope unit implies a systemd manager")
                .set_u64_property(&unit, "CPUQuotaPerSecUSec", usec);
        }

        let file = cgroup_path.join("cpu.max");
        fs::write(&file, &value).map_err(|e| SystemError::CgroupOperation {
            operation: "set_cpu_max".into(),
            path: file.display().to_string(),
            source: e,
        })?;
        debug!(value, cgroup = %cgroup_path.display(), "set cpu.max");
        Ok(())
    }

    /// Set `memory.high` (bytes). The kernel reclaims this cgroup first once
    /// it crosses the line, which is what pushes a background app toward swap.
    pub fn set_memory_high(&self, cgroup_path: &Path, bytes: u64) -> Result<(), SystemError> {
        if let Some(unit) = self.scope_unit(cgroup_path) {
            return self
                .systemd
                .as_ref()
                .expect("scope unit implies a systemd manager")
                .set_u64_property(&unit, "MemoryHigh", bytes);
        }
        let file = cgroup_path.join("memory.high");
        fs::write(&file, bytes.to_string()).map_err(|e| SystemError::CgroupOperation {
            operation: "set_memory_high".into(),
            path: file.display().to_string(),
            source: e,
        })?;
        debug!(bytes, cgroup = %cgroup_path.display(), "set memory.high");
        Ok(())
    }

    /// Drop the high limit (`memory.high = max`, or systemd's infinity).
    pub fn reset_memory_high(&self, cgroup_path: &Path) {
        if let Some(unit) = self.scope_unit(cgroup_path) {
            if let Err(e) = self
                .systemd
                .as_ref()
                .expect("scope unit implies a systemd manager")
                .set_u64_property(&unit, "MemoryHigh", u64::MAX)
            {
                debug!(cgroup = %cgroup_path.display(), error = %e, "failed to reset MemoryHigh");
            }
            return;
        }
        let file = cgroup_path.join("memory.high");
        if let Err(e) = fs::write(&file, "max") {
            debug!(cgroup = %cgroup_path.display(), error = %e, "failed to reset memory.high");
        }
    }

    /// Ask the kernel to reclaim `bytes` from this cgroup (`memory.reclaim`).
    ///
    /// A short write is not a failure: the kernel returns `EAGAIN` when it
    /// reclaimed some of the request and stopped. That is the one-shot we want.
    pub fn reclaim(&self, cgroup_path: &Path, bytes: u64) -> Result<(), SystemError> {
        if bytes == 0 {
            return Ok(());
        }
        let file = cgroup_path.join("memory.reclaim");
        match fs::write(&file, bytes.to_string()) {
            Ok(()) => {
                debug!(bytes, cgroup = %cgroup_path.display(), "memory.reclaim");
                Ok(())
            }
            Err(e) if is_partial_reclaim(&e) => {
                debug!(bytes, cgroup = %cgroup_path.display(), "memory.reclaim partially satisfied");
                Ok(())
            }
            Err(e) => Err(SystemError::CgroupOperation {
                operation: "memory.reclaim".into(),
                path: file.display().to_string(),
                source: e,
            }),
        }
    }

    /// Reclaim whatever the cgroup currently holds.
    pub fn reclaim_current(&self, cgroup_path: &Path) -> Result<(), SystemError> {
        let current = fs::read_to_string(cgroup_path.join("memory.current"))
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .unwrap_or(0);
        self.reclaim(cgroup_path, current)
    }

    /// Systemd scope unit name when this path is one of our transient scopes.
    fn scope_unit(&self, cgroup_path: &Path) -> Option<String> {
        if self.systemd.is_none() {
            return None;
        }
        let name = cgroup_path.file_name()?.to_str()?;
        name.ends_with(".scope").then(|| name.to_string())
    }

    /// Reset cpu controls to defaults.
    ///
    /// Returns nothing on purpose: the previous signature promised a `Result`
    /// that was always `Ok`, which made callers believe they were checking
    /// something they were not.
    pub fn reset_cpu(&self, cgroup_path: &Path) {
        if let Some(unit) = self.scope_unit(cgroup_path) {
            let mgr = self
                .systemd
                .as_ref()
                .expect("scope unit implies a systemd manager");
            if let Err(e) = mgr.set_u64_property(&unit, "CPUWeight", 100) {
                debug!(cgroup = %cgroup_path.display(), error = %e, "failed to reset CPUWeight");
            }
            // u64::MAX is systemd's "infinity" for the quota property.
            if let Err(e) = mgr.set_u64_property(&unit, "CPUQuotaPerSecUSec", u64::MAX) {
                debug!(cgroup = %cgroup_path.display(), error = %e, "failed to reset CPUQuotaPerSecUSec");
            }
            return;
        }
        let weight_err = fs::write(cgroup_path.join("cpu.weight"), "100").err();
        let max_err = fs::write(cgroup_path.join("cpu.max"), format!("max {CPU_PERIOD_US}")).err();
        if let Some(e) = &weight_err {
            debug!(cgroup = %cgroup_path.display(), error = %e, "failed to reset cpu.weight");
        }
        if let Some(e) = &max_err {
            debug!(cgroup = %cgroup_path.display(), error = %e, "failed to reset cpu.max");
        }
    }

    /// Remove stale app-powerd cgroups left over from a previous run.
    pub fn cleanup_stale_cgroups(&self) {
        if self.capabilities.tier == CgroupCapability::SignalOnly {
            return;
        }
        let Ok(entries) = fs::read_dir(&self.base_path) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if name_str.starts_with("app-powerd-") {
                let path = entry.path();
                let _ = fs::write(path.join("cgroup.freeze"), "0");
                let report = self.evacuate(&path);
                if report.returned > 0 {
                    info!(path = %path.display(), returned = report.returned, "returned processes left by a previous run");
                }
                match fs::remove_dir(&path) {
                    Ok(()) => info!(path = %path.display(), "cleaned up stale cgroup"),
                    Err(e) => {
                        debug!(path = %path.display(), error = %e, "failed to clean up stale cgroup")
                    }
                }
            }
        }
    }

    /// Remove a cgroup (must be empty).
    pub fn remove_cgroup(&self, cgroup_path: &Path) -> Result<(), SystemError> {
        if cgroup_path.exists() {
            fs::remove_dir(cgroup_path).map_err(|e| SystemError::CgroupOperation {
                operation: "remove".into(),
                path: cgroup_path.display().to_string(),
                source: e,
            })?;
        }
        Ok(())
    }
}

fn write_procs(cgroup_path: &Path, pid: u32, operation: &str) -> Result<(), SystemError> {
    let procs_file = cgroup_path.join("cgroup.procs");
    fs::write(&procs_file, pid.to_string()).map_err(|e| SystemError::CgroupOperation {
        operation: format!("{operation}({pid})"),
        path: procs_file.display().to_string(),
        source: e,
    })
}

fn cgroup_pids(cgroup_path: &Path) -> Vec<u32> {
    fs::read_to_string(cgroup_path.join("cgroup.procs"))
        .map(|content| {
            content
                .lines()
                .filter_map(|l| l.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn process_cgroup(pid: u32) -> Option<PathBuf> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    parse_cgroup_v2_path(&content)
}

fn parse_cgroup_v2_path(content: &str) -> Option<PathBuf> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|path| PathBuf::from("/sys/fs/cgroup").join(path.trim().trim_start_matches('/')))
}

/// Whether `controller` is enabled for children of `path`.
///
/// A controller listed in a cgroup's `cgroup.subtree_control` is the only thing
/// that makes its interface files appear in child cgroups. Without this check a
/// sub-cgroup can be created successfully and still have no `cpu.max` to write.
fn controller_enabled(path: &Path, controller: &str) -> bool {
    controller_list(path, "cgroup.subtree_control")
        .iter()
        .any(|c| c == controller)
}

fn controller_list(path: &Path, file: &str) -> Vec<String> {
    fs::read_to_string(path.join(file))
        .map(|content| content.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Parent of the `daemon` leaf when this process already lives there.
fn service_base(self_cgroup: &Path) -> PathBuf {
    if self_cgroup.file_name().and_then(|n| n.to_str()) == Some(DAEMON_LEAF) {
        if let Some(parent) = self_cgroup.parent() {
            if parent.join("cgroup.controllers").is_file() {
                return parent.to_path_buf();
            }
        }
    }
    self_cgroup.to_path_buf()
}

/// Enable `cpu` and `memory` for children of `base` when the parent delegated
/// them but left `subtree_control` empty.
///
/// Returns `(cpu_enabled, memory_enabled)` after the attempt. A successful
/// write counts as enabled: the kernel rejects a bad enable instead of
/// dropping it, and a test hierarchy does not rewrite `+cpu` back to `cpu`.
fn ensure_controllers(base: &Path, self_cgroup: &Path, pid: u32) -> (bool, bool) {
    let available = controller_list(base, "cgroup.controllers");
    let missing: Vec<&str> = WANTED_CONTROLLERS
        .into_iter()
        .filter(|name| available.iter().any(|c| c == name) && !controller_enabled(base, name))
        .collect();

    let mut cpu = controller_enabled(base, "cpu");
    let mut memory = controller_enabled(base, "memory");
    if missing.is_empty() {
        return (cpu, memory);
    }

    match enable_missing(base, self_cgroup, pid, &missing) {
        Ok(()) => {
            if missing.contains(&"cpu") {
                cpu = true;
            }
            if missing.contains(&"memory") {
                memory = true;
            }
        }
        Err(e) => {
            warn!(
                error = %e,
                base = %base.display(),
                "could not enable cpu/memory controllers; cpu_weight, cpu_quota and memory limits will not be applied"
            );
            cpu = controller_enabled(base, "cpu");
            memory = controller_enabled(base, "memory");
        }
    }
    (cpu, memory)
}

fn enable_missing(
    base: &Path,
    self_cgroup: &Path,
    pid: u32,
    missing: &[&str],
) -> std::io::Result<()> {
    let leaf = base.join(DAEMON_LEAF);
    let already_there = self_cgroup == leaf;
    if !already_there {
        fs::create_dir_all(&leaf)?;
        fs::write(leaf.join("cgroup.procs"), pid.to_string())?;
    }
    let spec = missing
        .iter()
        .map(|name| format!("+{name}"))
        .collect::<Vec<_>>()
        .join(" ");
    fs::write(base.join("cgroup.subtree_control"), spec)
}

fn is_partial_reclaim(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock || error.raw_os_error() == Some(libc_eagain())
}

fn libc_eagain() -> i32 {
    // EAGAIN. `std::io::ErrorKind::WouldBlock` covers it on current Rust, but
    // the kernel's `memory.reclaim` documents the errno by name.
    11
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unified_cgroup_line() {
        let content = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/plasma-plasmashell.service\n";
        assert_eq!(
            parse_cgroup_v2_path(content),
            Some(PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/plasma-plasmashell.service"
            ))
        );
        assert_eq!(parse_cgroup_v2_path("1:name=systemd:/foo\n"), None);
    }

    fn origin(starttime: u64, app: &str, home: &str) -> Origin {
        Origin {
            starttime,
            app_cgroup: PathBuf::from(app),
            origin: PathBuf::from(home),
        }
    }

    #[test]
    fn home_prefers_own_record_then_siblings() {
        let mut store = OriginStore::default();
        store
            .by_pid
            .insert(10, origin(5, "/cg/app-powerd-a", "/cg/own.scope"));
        store
            .by_pid
            .insert(11, origin(6, "/cg/app-powerd-a", "/cg/parent.scope"));
        store
            .by_pid
            .insert(12, origin(7, "/cg/app-powerd-b", "/cg/other.scope"));

        let homes = store.home_for(10, Some(5), Path::new("/cg/app-powerd-a"));
        assert_eq!(homes.first(), Some(&PathBuf::from("/cg/own.scope")));
        assert!(!homes.contains(&PathBuf::from("/cg/other.scope")));

        let homes = store.home_for(99, Some(1), Path::new("/cg/app-powerd-a"));
        assert_eq!(homes.len(), 2);
    }

    #[test]
    fn recycled_pid_does_not_use_stale_record() {
        let mut store = OriginStore::default();
        store
            .by_pid
            .insert(10, origin(5, "/cg/app-powerd-a", "/cg/own.scope"));
        let homes = store.home_for(10, Some(42), Path::new("/cg/app-powerd-z"));
        assert!(homes.is_empty());
    }

    #[test]
    fn origin_file_round_trips() {
        let dir = std::env::temp_dir().join(format!("app-powerd-origins-{}", std::process::id()));
        let path = dir.join("cgroup-origins.json");
        let mut store = OriginStore {
            path: Some(path.clone()),
            by_pid: HashMap::new(),
        };
        store
            .by_pid
            .insert(10, origin(5, "/cg/app-powerd-a", "/cg/own.scope"));
        store.persist();

        let loaded = OriginStore::load(path.clone());
        assert_eq!(loaded.by_pid, store.by_pid);

        store.by_pid.clear();
        store.persist();
        assert!(!path.exists(), "an empty store removes its file");
        let _ = fs::remove_dir_all(dir);
    }

    fn fake_cgroup(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "app-powerd-cgroup-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn controller_enabled_reads_subtree_control() {
        let dir = fake_cgroup("enabled");
        fs::write(dir.join("cgroup.subtree_control"), "cpu memory pids\n").unwrap();
        assert!(controller_enabled(&dir, "cpu"));
        assert!(controller_enabled(&dir, "memory"));
        assert!(!controller_enabled(&dir, "io"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn controller_absent_when_file_missing_or_empty() {
        let dir = fake_cgroup("absent");
        assert!(!controller_enabled(&dir, "cpu"));
        fs::write(dir.join("cgroup.subtree_control"), "pids\n").unwrap();
        assert!(!controller_enabled(&dir, "cpu"));
        assert!(!controller_enabled(&dir, "memory"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn available_but_not_enabled_moves_into_leaf_and_enables() {
        let dir = fake_cgroup("enable");
        fs::write(dir.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        fs::write(dir.join("cgroup.subtree_control"), "pids\n").unwrap();

        let (cpu, memory) = ensure_controllers(&dir, &dir, 4242);

        assert!(cpu);
        assert!(memory);
        let procs = fs::read_to_string(dir.join("daemon").join("cgroup.procs")).unwrap();
        assert_eq!(procs, "4242");
        let subtree = fs::read_to_string(dir.join("cgroup.subtree_control")).unwrap();
        assert_eq!(subtree, "+cpu +memory");
        assert!(!dir.join("daemon").join("daemon").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn already_enabled_does_not_create_a_leaf() {
        let dir = fake_cgroup("noop");
        fs::write(dir.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        fs::write(dir.join("cgroup.subtree_control"), "cpu memory pids\n").unwrap();

        let (cpu, memory) = ensure_controllers(&dir, &dir, 4242);

        assert!(cpu);
        assert!(memory);
        assert!(!dir.join("daemon").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn controller_not_delegated_is_left_alone() {
        let dir = fake_cgroup("undelegated");
        fs::write(dir.join("cgroup.controllers"), "pids\n").unwrap();
        fs::write(dir.join("cgroup.subtree_control"), "pids\n").unwrap();

        let (cpu, memory) = ensure_controllers(&dir, &dir, 4242);

        assert!(!cpu);
        assert!(!memory);
        assert!(!dir.join("daemon").exists());
        let subtree = fs::read_to_string(dir.join("cgroup.subtree_control")).unwrap();
        assert_eq!(subtree, "pids\n");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn leaf_process_enables_controllers_on_the_parent() {
        let dir = fake_cgroup("leaf");
        fs::write(dir.join("cgroup.controllers"), "cpu memory\n").unwrap();
        fs::write(dir.join("cgroup.subtree_control"), "").unwrap();
        fs::create_dir_all(dir.join("daemon")).unwrap();

        let leaf = dir.join("daemon");
        let base = service_base(&leaf);
        assert_eq!(base, dir);
        let (cpu, memory) = ensure_controllers(&base, &leaf, 4242);

        assert!(cpu);
        assert!(memory);
        assert!(!dir.join("daemon").join("daemon").exists());
        assert_eq!(
            fs::read_to_string(dir.join("cgroup.subtree_control")).unwrap(),
            "+cpu +memory"
        );
        let _ = fs::remove_dir_all(dir);
    }
}
