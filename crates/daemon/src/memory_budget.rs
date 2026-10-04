// SPDX-License-Identifier: Apache-2.0

//! A provider-independent limit for daemon protocol messages.
const MIB: usize = 1024 * 1024;

#[cfg(target_os = "linux")]
fn available_memory_bytes() -> Option<u64> {
    let host = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("MemAvailable:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
                    .map(|kb| kb.saturating_mul(1024))
            })
        });
    let cgroup = [
        ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current"),
        (
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
            "/sys/fs/cgroup/memory/memory.usage_in_bytes",
        ),
    ]
    .into_iter()
    .find_map(|(limit, usage)| {
        let limit = std::fs::read_to_string(limit).ok()?;
        let limit = limit.trim().parse::<u64>().ok()?;
        if limit >= (1_u64 << 60) {
            return None;
        }
        let usage = std::fs::read_to_string(usage)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()?;
        Some(limit.saturating_sub(usage))
    });
    match (host, cgroup) {
        (Some(host), Some(cgroup)) => Some(host.min(cgroup)),
        (host, cgroup) => host.or(cgroup),
    }
}

pub fn memory_aware_byte_limit(env_name: &str) -> usize {
    if let Some(value) = std::env::var(env_name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
    {
        return value;
    }
    #[cfg(target_os = "linux")]
    if let Some(available) = available_memory_bytes() {
        return usize::try_from(available / 512)
            .unwrap_or(usize::MAX)
            .clamp(MIB, 64 * MIB);
    }
    8 * MIB
}
