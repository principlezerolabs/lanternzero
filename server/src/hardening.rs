//! Memory hygiene for a process that holds viewing keys (spec §6.2).
//!
//! "Never on disk" includes swap and crash dumps. At start the server:
//! - turns off core dumps (`RLIMIT_CORE` 0, and on Linux
//!   `PR_SET_DUMPABLE` 0, which also blocks `ptrace` by other users);
//! - locks all its memory (`mlockall`) when the memlock limit is unlimited,
//!   so nothing it holds can be swapped out;
//! - otherwise checks that swap can't take its pages: no swap device, a
//!   container whose cgroup forbids swap, or swap that is always encrypted
//!   (macOS).
//!
//! A server that offers scanning refuses to start when none of those
//! holds, unless the operator sets `hardening.allow_swap` to say the swap
//! is encrypted. The calls go through `rustix`, so the workspace still has
//! no `unsafe` of its own.

use serde::Deserialize;

/// `[hardening]` in the config.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardeningConfig {
    /// Start a scanning server even though swap may hold its memory: only
    /// when swap is encrypted (for example dm-crypt), which the server can't
    /// check itself.
    #[serde(default)]
    pub allow_swap: bool,
}

/// Whether the process's memory is locked against swapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lock {
    Locked,
    /// `RLIMIT_MEMLOCK` isn't unlimited. Locking under a finite limit would
    /// make later allocations fail, so the server doesn't try.
    LimitTooLow,
    /// The limit allowed it, but `mlockall` failed.
    Failed,
    /// No `mlockall` on this system.
    Unsupported,
}

/// Whether swap can take the process's pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Swap {
    /// No swap device (compressed RAM, `zram`, doesn't count).
    Off,
    /// Swap exists, but this process's cgroup may not use it
    /// (`memory.swap.max` is 0), as in a container run with
    /// `memswap_limit` equal to `mem_limit`.
    CgroupOff,
    /// The system always encrypts swap (macOS).
    Encrypted,
    On,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub core_dumps_off: bool,
    pub memory: Lock,
    pub swap: Swap,
}

impl Report {
    /// Spec §6.2 holds: no core dumps, and memory locked or swap that
    /// can't leak it.
    pub fn keys_safe(&self) -> bool {
        self.core_dumps_off && (self.memory == Lock::Locked || self.swap_safe())
    }

    fn swap_safe(&self) -> bool {
        matches!(self.swap, Swap::Off | Swap::CgroupOff | Swap::Encrypted)
    }
}

/// What to do at start, given the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    /// Start, but log a warning: no keys are held (no scanning), or the
    /// operator said swap is encrypted.
    Warn,
    /// Refuse to start.
    Refuse,
}

/// The start-up decision. `scanning`: the server may hold viewing keys.
pub fn verdict(report: &Report, scanning: bool, config: &HardeningConfig) -> Verdict {
    if report.keys_safe() {
        Verdict::Ok
    } else if !scanning || (report.core_dumps_off && config.allow_swap) {
        Verdict::Warn
    } else {
        Verdict::Refuse
    }
}

/// Applies the protections to this process and reports what holds. Call
/// it first thing, before any key is loaded.
pub fn apply() -> Report {
    let core_dumps_off = disable_core_dumps();
    let memory = lock_memory();
    Report {
        core_dumps_off,
        memory,
        swap: swap(),
    }
}

/// What [`apply`] would achieve in a process started the same way, without
/// changing this one (for `doctor`).
pub fn inspect() -> Report {
    Report {
        // Lowering one's own limit is always allowed.
        core_dumps_off: cfg!(unix),
        // The same rule as `lock_memory`: Linux, and an unlimited memlock
        // limit.
        memory: if !cfg!(target_os = "linux") {
            Lock::Unsupported
        } else if memlock_unlimited() {
            Lock::Locked
        } else {
            Lock::LimitTooLow
        },
        swap: swap(),
    }
}

#[cfg(unix)]
fn disable_core_dumps() -> bool {
    use rustix::process::{Resource, Rlimit, setrlimit};
    let off = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .is_ok();
    #[cfg(target_os = "linux")]
    let off = off
        && rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .is_ok();
    off
}

#[cfg(not(unix))]
fn disable_core_dumps() -> bool {
    false
}

#[cfg(unix)]
fn memlock_unlimited() -> bool {
    use rustix::process::{Resource, getrlimit};
    getrlimit(Resource::Memlock).current.is_none()
}

#[cfg(not(unix))]
fn memlock_unlimited() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn lock_memory() -> Lock {
    use rustix::mm::{MlockAllFlags, mlockall};
    if !memlock_unlimited() {
        return Lock::LimitTooLow;
    }
    match mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE) {
        Ok(()) => Lock::Locked,
        Err(_) => Lock::Failed,
    }
}

#[cfg(not(target_os = "linux"))]
fn lock_memory() -> Lock {
    Lock::Unsupported
}

#[cfg(target_os = "linux")]
fn swap() -> Swap {
    let Ok(swaps) = std::fs::read_to_string("/proc/swaps") else {
        return Swap::Unknown;
    };
    if !swap_devices_active(&swaps) {
        return Swap::Off;
    }
    let max = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|c| cgroup_v2_path(&c))
        .and_then(|p| std::fs::read_to_string(format!("/sys/fs/cgroup{p}/memory.swap.max")).ok());
    match max.as_deref().map(str::trim) {
        Some("0") => Swap::CgroupOff,
        _ => Swap::On,
    }
}

#[cfg(target_os = "macos")]
fn swap() -> Swap {
    // macOS has encrypted its swap files since 10.8, and it can't be
    // turned off.
    Swap::Encrypted
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn swap() -> Swap {
    Swap::Unknown
}

/// Whether `/proc/swaps` lists a swap device other than `zram`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn swap_devices_active(proc_swaps: &str) -> bool {
    proc_swaps
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .any(|dev| !dev.starts_with("/dev/zram"))
}

/// This process's cgroup v2 path, from `/proc/self/cgroup`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn cgroup_v2_path(proc_cgroup: &str) -> Option<String> {
    let path = proc_cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    let path = path.trim().trim_end_matches('/');
    // Reject anything that could step outside /sys/fs/cgroup.
    if path.split('/').any(|seg| seg == "..") {
        return None;
    }
    Some(path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_proc_swaps_and_cgroups() {
        let header = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
        assert!(!swap_devices_active(header));
        assert!(!swap_devices_active(&format!(
            "{header}/dev/zram0  partition 4194300 0 100\n"
        )));
        assert!(swap_devices_active(&format!(
            "{header}/swap.img   file      2097148 0 -2\n"
        )));
        assert_eq!(cgroup_v2_path("0::/\n").as_deref(), Some(""));
        assert_eq!(
            cgroup_v2_path("12:pids:/x\n0::/system.slice/lz.service\n").as_deref(),
            Some("/system.slice/lz.service")
        );
        assert_eq!(cgroup_v2_path("0::/../etc\n"), None);
        assert_eq!(cgroup_v2_path("1:name=systemd:/\n"), None);
    }

    fn report(core: bool, memory: Lock, swap: Swap) -> Report {
        Report {
            core_dumps_off: core,
            memory,
            swap,
        }
    }

    #[test]
    fn a_scanning_server_needs_locked_memory_or_safe_swap() {
        let strict = HardeningConfig::default();
        let allow = HardeningConfig { allow_swap: true };
        let v = |r: Report, scanning, c: &HardeningConfig| verdict(&r, scanning, c);
        assert_eq!(
            v(report(true, Lock::Locked, Swap::On), true, &strict),
            Verdict::Ok
        );
        for swap in [Swap::Off, Swap::CgroupOff, Swap::Encrypted] {
            assert_eq!(
                v(report(true, Lock::LimitTooLow, swap), true, &strict),
                Verdict::Ok
            );
        }
        for swap in [Swap::On, Swap::Unknown] {
            assert_eq!(
                v(report(true, Lock::LimitTooLow, swap), true, &strict),
                Verdict::Refuse
            );
            assert_eq!(
                v(report(true, Lock::LimitTooLow, swap), true, &allow),
                Verdict::Warn
            );
            // No scanning, no keys: a warning only.
            assert_eq!(
                v(report(true, Lock::LimitTooLow, swap), false, &strict),
                Verdict::Warn
            );
        }
        // Core dumps on: never safe for keys, and `allow_swap` doesn't help.
        assert_eq!(
            v(report(false, Lock::Locked, Swap::Off), true, &allow),
            Verdict::Refuse
        );
    }

    #[cfg(unix)]
    #[test]
    fn inspect_does_not_change_this_process() {
        use rustix::process::{Resource, getrlimit};
        let before = getrlimit(Resource::Core);
        let _ = inspect();
        assert_eq!(getrlimit(Resource::Core), before);
    }
}
