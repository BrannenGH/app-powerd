//! Memory pressure sampling.
//!
//! The killer compares `MemAvailable` and PSI `some` avg10 with the configured
//! thresholds. Parsing is split from the file reads so the trip decision can be
//! tested without a live `/proc`.

use std::path::Path;

/// Bytes of `MemAvailable` and the PSI `some` avg10 percentage, when readable.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PressureSample {
    pub available: Option<u64>,
    pub psi_some_avg10: Option<f64>,
}

/// Read pressure from the user cgroup (`memory.pressure` walking up from
/// `base`) and from `/proc/meminfo` plus `/proc/pressure/memory`.
pub fn sample(base: &Path) -> PressureSample {
    let available = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| parse_mem_available(&text));
    let psi_some_avg10 = psi_from_cgroup(base).or_else(|| {
        std::fs::read_to_string("/proc/pressure/memory")
            .ok()
            .and_then(|text| parse_psi_some_avg10(&text))
    });
    PressureSample {
        available,
        psi_some_avg10,
    }
}

fn psi_from_cgroup(base: &Path) -> Option<f64> {
    let mut dir = Some(base);
    while let Some(current) = dir {
        if let Some(value) = std::fs::read_to_string(current.join("memory.pressure"))
            .ok()
            .and_then(|text| parse_psi_some_avg10(&text))
        {
            return Some(value);
        }
        dir = current.parent().filter(|parent| {
            parent.starts_with("/sys/fs/cgroup") && *parent != Path::new("/sys/fs/cgroup")
        });
    }
    None
}

/// `MemAvailable` from `/proc/meminfo`, in bytes.
pub fn parse_mem_available(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("MemAvailable:") {
            let kib: u64 = parts.next()?.parse().ok()?;
            return Some(kib.saturating_mul(1024));
        }
    }
    None
}

/// PSI `some` avg10 (percent) from a `memory.pressure` or `/proc/pressure/memory` body.
pub fn parse_psi_some_avg10(text: &str) -> Option<f64> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("some") {
            continue;
        }
        for field in parts {
            if let Some(value) = field.strip_prefix("avg10=") {
                return value.parse().ok();
            }
        }
    }
    None
}

/// Whether either configured tripwire is crossed.
///
/// A missing sample does not trip: we only act on a number we actually read.
pub fn pressure_tripped(
    sample: PressureSample,
    available_min: Option<u64>,
    psi_limit: Option<f64>,
) -> bool {
    if let (Some(have), Some(min)) = (sample.available, available_min) {
        if have < min {
            return true;
        }
    }
    if let (Some(have), Some(limit)) = (sample.psi_some_avg10, psi_limit) {
        if have >= limit {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mem_available() {
        let text = "MemTotal:       2048 kB\nMemAvailable:   256 kB\n";
        assert_eq!(parse_mem_available(text), Some(256 * 1024));
        assert_eq!(parse_mem_available("MemFree: 1 kB\n"), None);
    }

    #[test]
    fn parses_psi_some_avg10() {
        let text = "some avg10=12.50 avg60=1.00 avg300=0.10 total=9\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        assert_eq!(parse_psi_some_avg10(text), Some(12.5));
        assert_eq!(parse_psi_some_avg10("full avg10=80.00\n"), None);
    }

    #[test]
    fn tripwire_is_either_threshold() {
        let quiet = PressureSample {
            available: Some(1 << 30),
            psi_some_avg10: Some(1.0),
        };
        assert!(!pressure_tripped(quiet, Some(256 << 20), Some(40.0)));

        let low_ram = PressureSample {
            available: Some(100 << 20),
            psi_some_avg10: Some(1.0),
        };
        assert!(pressure_tripped(low_ram, Some(256 << 20), Some(40.0)));

        let stalled = PressureSample {
            available: Some(1 << 30),
            psi_some_avg10: Some(40.0),
        };
        assert!(pressure_tripped(stalled, Some(256 << 20), Some(40.0)));

        let unreadable = PressureSample {
            available: None,
            psi_some_avg10: None,
        };
        assert!(!pressure_tripped(unreadable, Some(256 << 20), Some(40.0)));
    }
}
