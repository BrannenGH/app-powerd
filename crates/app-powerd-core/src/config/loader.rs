use std::path::{Path, PathBuf};

use inotify::{Inotify, WatchMask};
use tracing::{info, warn};

use super::Config;
use crate::error::ConfigError;

/// System-wide config, read when the per-user file does not exist.
pub const SYSTEM_CONFIG_PATH: &str = "/etc/app-powerd/config.yaml";

/// Per-user config path: `$XDG_CONFIG_HOME/app-powerd/config.yaml`.
pub fn user_config_path() -> PathBuf {
    let config_dir = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".config")
        });
    config_dir.join("app-powerd").join("config.yaml")
}

/// Get config file path.
pub fn config_path() -> PathBuf {
    resolve_config_path(&user_config_path(), Path::new(SYSTEM_CONFIG_PATH))
}

/// Pick between user config file and system config file.
pub fn resolve_config_path(user: &Path, system: &Path) -> PathBuf {
    if user.is_file() {
        return user.to_path_buf();
    }
    if system.is_file() {
        return system.to_path_buf();
    }
    user.to_path_buf()
}

/// Load and validate config from a path.
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    if !path.exists() {
        return Err(ConfigError::NotFound {
            path: path.to_path_buf(),
        });
    }

    let content = std::fs::read_to_string(path)?;
    let config: Config = serde_yaml_ng::from_str(&content).map_err(with_hint)?;
    validate(&config)?;

    info!(path = %path.display(), "config loaded");
    Ok(config)
}

/// YAML Rule.
const RULE_SHAPE: &str =
    "each rule is a mapping with exactly the keys `id`, `match` and `policy`, e.g.\n\
  - id: shell\n\
    match:\n\
      app_id: [plasmashell]\n\
    policy:\n\
      use_profile: ignore";

/// Attach a hint to the YAML error.
fn with_hint(error: serde_yaml_ng::Error) -> ConfigError {
    let message = error.to_string();
    let hint = if message.starts_with("rules") {
        if message.contains("expected field identifier") {
            Some(format!(
                "a mapping was found where a key name was expected; {RULE_SHAPE}"
            ))
        } else if message.contains("PolicyConfig") || message.contains("unknown field") {
            Some(RULE_SHAPE.to_string())
        } else {
            None
        }
    } else {
        None
    };
    match hint {
        Some(hint) => ConfigError::ParseHint {
            source: error,
            hint,
        },
        None => ConfigError::Parse(error),
    }
}

/// Load config or return defaults if file doesn't exist.
pub fn load_config_or_default(path: &Path) -> Config {
    match load_config(path) {
        Ok(config) => config,
        Err(ConfigError::NotFound { path }) => {
            warn!(path = %path.display(), "config not found, using defaults");
            Config::default()
        }
        Err(e) => {
            warn!(error = %e, "failed to load config, using defaults");
            Config::default()
        }
    }
}

fn validate(config: &Config) -> Result<(), ConfigError> {
    if config.version != 1 {
        return Err(ConfigError::Validation {
            message: format!("unsupported config version: {}", config.version),
        });
    }

    for rule in &config.rules {
        if rule.id.is_empty() {
            return Err(ConfigError::Validation {
                message: "rule id cannot be empty".into(),
            });
        }

        if let Some(ref profile_name) = rule.policy.use_profile {
            if !config.profiles.contains_key(profile_name) {
                return Err(ConfigError::UnknownProfile {
                    rule_id: rule.id.clone(),
                    profile: profile_name.clone(),
                });
            }
        }

        // Regex validation is deferred to RulesEngine::new() which compiles
        // and validates all regexes during rule compilation.
    }

    // Check for duplicate rule IDs
    let mut seen_ids = std::collections::HashSet::new();
    for rule in &config.rules {
        if !seen_ids.insert(&rule.id) {
            return Err(ConfigError::Validation {
                message: format!("duplicate rule id: '{}'", rule.id),
            });
        }
    }

    // Validate numeric ranges in profiles
    for (name, profile) in &config.profiles {
        validate_throttle_params(
            &format!("profile '{name}'"),
            profile.nice,
            profile.cpu_weight,
            profile.cpu_quota.as_deref(),
        )?;
    }

    if let Some(psi) = config.defaults.memory.psi_some_avg10 {
        if !(0.0..=100.0).contains(&psi) {
            return Err(ConfigError::Validation {
                message: format!("defaults.memory.psi_some_avg10 must be in 0..=100, got {psi}"),
            });
        }
    }

    // Validate numeric ranges in rule policies
    for rule in &config.rules {
        validate_throttle_params(
            &format!("rule '{}'", rule.id),
            rule.policy.nice,
            rule.policy.cpu_weight,
            rule.policy.cpu_quota.as_deref(),
        )?;
    }

    Ok(())
}

fn validate_throttle_params(
    ctx: &str,
    nice: Option<i32>,
    cpu_weight: Option<u32>,
    cpu_quota: Option<&str>,
) -> Result<(), ConfigError> {
    if let Some(nice) = nice {
        if !(-20..=19).contains(&nice) {
            return Err(ConfigError::Validation {
                message: format!("{ctx}: nice must be in -20..19, got {nice}"),
            });
        }
    }
    if let Some(weight) = cpu_weight {
        if !(1..=10000).contains(&weight) {
            return Err(ConfigError::Validation {
                message: format!("{ctx}: cpu_weight must be in 1..10000, got {weight}"),
            });
        }
    }
    if let Some(quota) = cpu_quota {
        let numeric = quota.strip_suffix('%').unwrap_or(quota);
        let value = numeric
            .parse::<u32>()
            .map_err(|_| ConfigError::Validation {
                message: format!(
                    "{ctx}: cpu_quota must be a number with optional '%' suffix, got '{quota}'"
                ),
            })?;
        if !(1..=100).contains(&value) {
            return Err(ConfigError::Validation {
                message: format!("{ctx}: cpu_quota must be in 1..=100, got {value}"),
            });
        }
    }
    Ok(())
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: 1,
            defaults: super::Defaults::default(),
            profiles: Default::default(),
            rules: Vec::new(),
        }
    }
}

/// How long to wait from the config file is saved to reloaded.
const RELOAD_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(250);

/// Mask for the config directory itself
fn dir_mask() -> WatchMask {
    WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::DELETE_SELF | WatchMask::MOVE_SELF
}

/// Mask for an ancestor while the config directory does not exist yet.
fn ancestor_mask() -> WatchMask {
    WatchMask::CREATE | WatchMask::MOVED_TO | WatchMask::DELETE_SELF | WatchMask::MOVE_SELF
}

/// What the watcher currently has its inotify watch on.
struct Armed {
    wd: inotify::WatchDescriptor,
    /// Whether the watch is on the config directory itself
    on_config_dir: bool,
}

/// Watch the config directory.
fn arm(watches: &mut inotify::Watches, dir: &Path) -> std::io::Result<Armed> {
    if dir.is_dir() {
        let wd = watches.add(dir, dir_mask())?;
        return Ok(Armed {
            wd,
            on_config_dir: true,
        });
    }
    let ancestor = dir
        .ancestors()
        .skip(1)
        .find(|a| a.is_dir())
        .unwrap_or(Path::new("/"));
    info!(
        dir = %dir.display(),
        watching = %ancestor.display(),
        "config directory does not exist yet; will start watching it once it is created"
    );
    let wd = watches.add(ancestor, ancestor_mask())?;
    if dir.is_dir() {
        let _ = watches.remove(wd);
        return arm(watches, dir);
    }
    Ok(Armed {
        wd,
        on_config_dir: false,
    })
}

/// Watch config file for changes using inotify. Returns an async stream.
pub async fn watch_config(path: &Path) -> Result<tokio::sync::mpsc::Receiver<()>, ConfigError> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);

    let dir = path
        .parent()
        .ok_or_else(|| ConfigError::Validation {
            message: "config path has no parent directory".into(),
        })?
        .to_path_buf();

    let filename = path
        .file_name()
        .ok_or_else(|| ConfigError::Validation {
            message: "config path has no filename".into(),
        })?
        .to_os_string();
    let config_file = path.to_path_buf();

    let inotify = Inotify::init()?;
    let mut stream = inotify.into_event_stream([0u8; 4096])?;
    let mut watches = stream.watches();
    let mut armed = arm(&mut watches, &dir)?;

    tokio::spawn(async move {
        use inotify::EventMask;
        use tokio_stream::StreamExt;

        let mut deadline: Option<tokio::time::Instant> = None;
        loop {
            let event = match deadline {
                Some(at) => tokio::select! {
                    event = stream.next() => event,
                    () = tokio::time::sleep_until(at) => {
                        deadline = None;
                        if tx.send(()).await.is_err() {
                            return;
                        }
                        continue;
                    }
                },
                None => stream.next().await,
            };
            let event = match event {
                Some(Ok(event)) => event,
                Some(Err(e)) => {
                    warn!(error = %e, "config watcher read failed; watching stopped");
                    return;
                }
                None => return,
            };
            if event.wd != armed.wd {
                continue;
            }

            let lost = event
                .mask
                .intersects(EventMask::DELETE_SELF | EventMask::MOVE_SELF | EventMask::IGNORED);
            let for_config_file = event.name.as_deref() == Some(filename.as_os_str());

            if armed.on_config_dir && !lost {
                if for_config_file {
                    deadline = Some(tokio::time::Instant::now() + RELOAD_DEBOUNCE);
                }
                continue;
            }

            let previous = armed.wd.clone();
            match arm(&mut watches, &dir) {
                Ok(next) => {
                    if next.wd != previous && !lost {
                        let _ = watches.remove(previous);
                    }
                    let found = next.on_config_dir && !armed.on_config_dir;
                    armed = next;
                    if found {
                        info!(dir = %dir.display(), "config directory appeared; watching it");
                        if config_file.exists() {
                            deadline = Some(tokio::time::Instant::now() + RELOAD_DEBOUNCE);
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, dir = %dir.display(), "config watcher lost its directory; watching stopped");
                    return;
                }
            }
        }
    });

    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, MatchCriteria, PolicyConfig, Rule};

    fn parse_error(yaml: &str) -> String {
        let error = serde_yaml_ng::from_str::<Config>(yaml).unwrap_err();
        with_hint(error).to_string()
    }

    #[test]
    fn map_in_key_position_gets_a_hint() {
        let message = parse_error("version: 1\nrules:\n  - {executable: [plasmashell]}: ignore\n");
        assert!(message.contains("expected field identifier"), "{message}");
        assert!(message.contains("hint:"), "{message}");
        assert!(message.contains("`id`, `match` and `policy`"), "{message}");
    }

    #[test]
    fn misplaced_policy_field_gets_a_hint() {
        let message = parse_error(
            "version: 1\nrules:\n  - id: x\n    match: {app_id: [x]}\n    use_profile: ignore\n",
        );
        assert!(message.contains("unknown field `use_profile`"), "{message}");
        assert!(message.contains("hint:"), "{message}");
    }

    #[test]
    fn errors_outside_rules_are_left_alone() {
        let message = parse_error("version: one\n");
        assert!(!message.contains("hint:"), "{message}");
    }

    async fn expect_reload(rx: &mut tokio::sync::mpsc::Receiver<()>, what: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for reload: {what}"))
            .expect("watcher alive");
    }

    async fn expect_quiet(rx: &mut tokio::sync::mpsc::Receiver<()>, what: &str) {
        let got = tokio::time::timeout(RELOAD_DEBOUNCE * 3, rx.recv()).await;
        assert!(got.is_err(), "unexpected extra reload: {what}");
    }

    fn temp_config_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("app-powerd-watch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[tokio::test]
    async fn truncate_then_write_reloads_once() {
        let root = temp_config_root("debounce");
        let path = root.join("config.yaml");
        std::fs::write(&path, "version: 1\n").unwrap();
        let mut rx = watch_config(&path).await.unwrap();

        // Two separate writes in quick succession, as a script would do.
        std::fs::File::create(&path).unwrap();
        std::fs::write(&path, "version: 1\n").unwrap();

        expect_reload(&mut rx, "after writes").await;
        expect_quiet(&mut rx, "both writes must collapse into one reload").await;
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn directory_created_after_start_is_watched() {
        let root = temp_config_root("late-dir");
        let path = root.join("nested").join("app-powerd").join("config.yaml");
        let mut rx = watch_config(&path)
            .await
            .expect("watcher starts without the directory");

        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        std::fs::write(&path, "version: 1\n").unwrap();
        expect_reload(&mut rx, "file written in a newly created directory").await;

        std::fs::write(&path, "version: 1\n").unwrap();
        expect_reload(&mut rx, "later edits are still seen").await;
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn validate_rejects_wrong_version() {
        let config = Config {
            version: 2,
            ..Config::default()
        };
        assert!(validate(&config).is_err());
    }

    #[test]
    fn validate_rejects_empty_rule_id() {
        let mut config = Config::default();
        config.rules.push(Rule {
            id: String::new(),
            match_criteria: MatchCriteria {
                executable: vec!["test".into()],
                cmdline_regex: None,
                wm_class: vec![],
                app_id: vec![],
                desktop_file: vec![],
                window_title_regex: None,
            },
            policy: PolicyConfig {
                use_profile: None,
                action: None,
                suspend_delay: None,
                nice: None,
                cpu_weight: None,
                cpu_quota: None,
                memory_high: None,
                memory_reclaim: None,
                maintenance_resume: None,
                guards: None,
            },
        });
        assert!(validate(&config).is_err());
    }

    #[test]
    fn validate_rejects_unknown_profile() {
        let mut config = Config::default();
        config.rules.push(Rule {
            id: "test".into(),
            match_criteria: MatchCriteria {
                executable: vec!["test".into()],
                cmdline_regex: None,
                wm_class: vec![],
                app_id: vec![],
                desktop_file: vec![],
                window_title_regex: None,
            },
            policy: PolicyConfig {
                use_profile: Some("nonexistent".into()),
                action: None,
                suspend_delay: None,
                nice: None,
                cpu_weight: None,
                cpu_quota: None,
                memory_high: None,
                memory_reclaim: None,
                maintenance_resume: None,
                guards: None,
            },
        });
        assert!(validate(&config).is_err());
    }

    #[test]
    fn validate_accepts_valid_config() {
        let config = Config::default();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn load_config_or_default_returns_defaults() {
        let config = load_config_or_default(Path::new("/nonexistent/path/config.yaml"));
        assert_eq!(config.version, 1);
        assert!(config.defaults.enabled);
    }

    #[test]
    fn nice_boundary_values() {
        // -20 is the valid minimum
        assert!(validate_throttle_params("ctx", Some(-20), None, None).is_ok());
        // -21 is below minimum
        assert!(validate_throttle_params("ctx", Some(-21), None, None).is_err());
        // 19 is the valid maximum
        assert!(validate_throttle_params("ctx", Some(19), None, None).is_ok());
        // 20 is above maximum
        assert!(validate_throttle_params("ctx", Some(20), None, None).is_err());
    }

    #[test]
    fn cpu_weight_boundary_values() {
        // 0 is below minimum
        assert!(validate_throttle_params("ctx", None, Some(0), None).is_err());
        // 1 is the valid minimum
        assert!(validate_throttle_params("ctx", None, Some(1), None).is_ok());
        // 10000 is the valid maximum
        assert!(validate_throttle_params("ctx", None, Some(10000), None).is_ok());
        // 10001 is above maximum
        assert!(validate_throttle_params("ctx", None, Some(10001), None).is_err());
    }

    #[test]
    fn cpu_quota_boundary_values() {
        // "0%" is below minimum (1%)
        assert!(validate_throttle_params("ctx", None, None, Some("0%")).is_err());
        // "1%" is the valid minimum
        assert!(validate_throttle_params("ctx", None, None, Some("1%")).is_ok());
        // "100%" is the valid maximum
        assert!(validate_throttle_params("ctx", None, None, Some("100%")).is_ok());
        // "101%" is above maximum
        assert!(validate_throttle_params("ctx", None, None, Some("101%")).is_err());
    }

    #[test]
    fn resolve_config_path_prefers_user_then_system() {
        let root = std::env::temp_dir().join(format!(
            "app-powerd-cfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let user = root.join("user.yaml");
        let system = root.join("system.yaml");
        assert_eq!(resolve_config_path(&user, &system), user);

        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&system, "version: 1\n").unwrap();
        assert_eq!(resolve_config_path(&user, &system), system);

        std::fs::write(&user, "version: 1\n").unwrap();
        assert_eq!(resolve_config_path(&user, &system), user);
        let _ = std::fs::remove_dir_all(root);
    }
}
