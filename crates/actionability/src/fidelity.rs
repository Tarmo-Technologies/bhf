// SPDX-License-Identifier: Apache-2.0

//! Structured fuzzing-fidelity record (roadmap track CC-1).
//!
//! BHF fuzzes many high-demand targets — VxWorks / INTEGRITY / QNX / Windows
//! code — on an x86-64 Linux host by stub-isolating their platform: the portable
//! algorithmic body is compiled and fuzzed natively while the target ISA, RTOS
//! runtime, and hardware peripherals are *faked*. A clean result from such a run
//! is host-stub evidence, NOT target assurance, and conflating the two is a
//! safety hazard for DO-178 / safety-critical users.
//!
//! Historically that distinction was a single coarse "reduced-fidelity" string
//! stapled to the target. This module replaces it with a typed, serde-able record
//! that states, per dimension — `arch`, `endianness`, `rtos_runtime`,
//! `hardware_peripherals`, `concurrency`, `sanitizers` — whether it was genuinely
//! exercised, not exercised (a real gap), or not applicable. The old
//! human-readable caveat is *derived* from this record ([`Fidelity::caveat`]) so
//! it can never disagree with the structured facts, and a fully-native host
//! target carries no caveat at all.

use serde::{Deserialize, Serialize};

/// Per-dimension fidelity verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FidelityStatus {
    /// The dimension was genuinely exercised against the real thing (e.g. the
    /// code ran on the host ISA and that IS the target, or a sanitizer was armed
    /// and active).
    Exercised,
    /// The dimension exists for this target but was NOT exercised — it was faked,
    /// stubbed, or simply never explored. This is a real fidelity gap the reader
    /// must weigh: findings do not speak to it.
    NotExercised,
    /// The dimension does not apply to this target (e.g. a plain host process has
    /// no RTOS runtime), so its absence is not a gap.
    NotApplicable,
}

impl FidelityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exercised => "exercised",
            Self::NotExercised => "not_exercised",
            Self::NotApplicable => "not_applicable",
        }
    }

    /// Aggregation severity: a genuine gap (`NotExercised`) outranks a real
    /// exercise, which outranks "does not apply". Used to roll many targets'
    /// fidelity into one worst-case campaign record — a single stubbed target
    /// must be enough to flag the dimension for the whole run.
    fn severity(self) -> u8 {
        match self {
            Self::NotExercised => 2,
            Self::Exercised => 1,
            Self::NotApplicable => 0,
        }
    }
}

/// One fidelity dimension: its status plus a short human reason describing why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FidelityDimension {
    pub status: FidelityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl FidelityDimension {
    pub fn exercised(reason: impl Into<String>) -> Self {
        Self {
            status: FidelityStatus::Exercised,
            reason: Some(reason.into()),
        }
    }

    pub fn not_exercised(reason: impl Into<String>) -> Self {
        Self {
            status: FidelityStatus::NotExercised,
            reason: Some(reason.into()),
        }
    }

    pub fn not_applicable(reason: impl Into<String>) -> Self {
        Self {
            status: FidelityStatus::NotApplicable,
            reason: Some(reason.into()),
        }
    }

    /// True when this dimension is a real, weigh-it gap (`NotExercised`).
    /// `NotApplicable` is deliberately NOT a gap.
    pub fn is_gap(&self) -> bool {
        self.status == FidelityStatus::NotExercised
    }
}

/// Byte order the fuzzed logic actually ran in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    Little,
    Big,
}

impl Endianness {
    /// The endianness of the host BHF is running on.
    pub fn host() -> Self {
        if cfg!(target_endian = "big") {
            Self::Big
        } else {
            Self::Little
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Little => "little-endian",
            Self::Big => "big-endian",
        }
    }
}

/// The facts a caller already knows about how a target was built and fuzzed, from
/// which a [`Fidelity`] record is derived. Construct with [`FidelityFacts::host`]
/// and set the fields that differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FidelityFacts {
    /// The foreign OS/RTOS platform this target was stub-isolated for
    /// (`"vxworks"`, `"integrity"`, `"qnx"`, `"windows"`), or `None` for a plain
    /// native host target. When set, the target ISA / RTOS runtime / hardware
    /// were faked, not executed.
    pub platform_stub: Option<String>,
    /// The host architecture the fuzzer actually ran on (e.g. `"x86_64"`).
    pub host_arch: String,
    /// The host byte order the fuzzed logic ran in.
    pub host_endianness: Endianness,
    /// Which sanitizers were actually armed for the build/run (e.g.
    /// `["asan", "ubsan"]`). Empty means none were active.
    pub sanitizers: Vec<String>,
    /// Whether a ThreadSanitizer pass actually ran (the only signal that
    /// concurrent access was exercised at all today).
    pub tsan_ran: bool,
}

impl FidelityFacts {
    /// Facts for a plain native host target: no platform stub, host arch and byte
    /// order filled from the build, no sanitizers, no TSan. Callers set the
    /// fields that differ.
    pub fn host() -> Self {
        Self {
            platform_stub: None,
            host_arch: std::env::consts::ARCH.to_owned(),
            host_endianness: Endianness::host(),
            sanitizers: Vec::new(),
            tsan_ran: false,
        }
    }
}

/// A structured record of which execution dimensions a fuzz result actually
/// exercised. Attached to every finding and rolled up onto the campaign summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fidelity {
    /// Target instruction-set architecture. `Exercised` only when the code ran on
    /// the real target ISA (for a host-native target the host IS the target).
    pub arch: FidelityDimension,
    /// Byte order. `Exercised` when the target's byte order was actually run.
    pub endianness: FidelityDimension,
    /// RTOS runtime semantics (scheduling, IPC, timing). `NotApplicable` on a
    /// plain host process; `NotExercised` when a vendor RTOS was stubbed inert.
    pub rtos_runtime: FidelityDimension,
    /// Hardware / peripheral behavior (MMIO, DMA, devices). `NotApplicable` on a
    /// host process; `NotExercised` when device access was faked.
    pub hardware_peripherals: FidelityDimension,
    /// Concurrent-access exploration. `Exercised` only when a ThreadSanitizer
    /// pass ran; otherwise interleavings were not explored.
    pub concurrency: FidelityDimension,
    /// Sanitizer instrumentation. `Exercised` when at least one sanitizer was
    /// armed and active for the run.
    pub sanitizers: FidelityDimension,
}

impl Fidelity {
    /// Derive the record from the known facts.
    pub fn from_facts(facts: &FidelityFacts) -> Self {
        let concurrency = if facts.tsan_ran {
            FidelityDimension::exercised(
                "ThreadSanitizer pass replayed the corpus for concurrent-access faults",
            )
        } else {
            FidelityDimension::not_exercised(
                "no ThreadSanitizer pass ran; concurrent interleavings not explored",
            )
        };
        let sanitizers = if facts.sanitizers.is_empty() {
            FidelityDimension::not_exercised("no sanitizer instrumentation was active")
        } else {
            FidelityDimension::exercised(format!("ran under {}", facts.sanitizers.join("+")))
        };

        match facts.platform_stub.as_deref() {
            // Host stub-isolation lane: the platform was faked to compile the
            // portable body natively. The target ISA / RTOS / hardware never ran.
            Some(platform) => Fidelity {
                arch: FidelityDimension::not_exercised(format!(
                    "portable logic fuzzed on host {arch}; {platform} target ISA not executed",
                    arch = facts.host_arch,
                )),
                endianness: FidelityDimension::not_exercised(format!(
                    "ran in host {endian}; {platform} target byte order not verified",
                    endian = facts.host_endianness.as_str(),
                )),
                rtos_runtime: FidelityDimension::not_exercised(format!(
                    "{platform} runtime stubbed with inert handles; RTOS scheduling/IPC not modeled"
                )),
                hardware_peripherals: FidelityDimension::not_exercised(format!(
                    "{platform} device/peripheral access faked; no real hardware, MMIO, or DMA"
                )),
                concurrency,
                sanitizers,
            },
            // Native host target: the host IS the target, so arch and byte order
            // were genuinely exercised; RTOS/hardware simply do not apply.
            None => Fidelity {
                arch: FidelityDimension::exercised(format!(
                    "fuzzed natively on the host {arch} target",
                    arch = facts.host_arch,
                )),
                endianness: FidelityDimension::exercised(format!(
                    "native host target ran in {endian}",
                    endian = facts.host_endianness.as_str(),
                )),
                rtos_runtime: FidelityDimension::not_applicable(
                    "host process target has no RTOS runtime",
                ),
                hardware_peripherals: FidelityDimension::not_applicable(
                    "host process target has no hardware peripherals",
                ),
                concurrency,
                sanitizers,
            },
        }
    }

    /// An all-`NotApplicable` record for a finding produced without dynamic
    /// execution (e.g. a static-analysis hit). Nothing ran, so no dimension is a
    /// gap and it carries no caveat.
    pub fn not_executed(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let dim = || FidelityDimension::not_applicable(reason.clone());
        Fidelity {
            arch: dim(),
            endianness: dim(),
            rtos_runtime: dim(),
            hardware_peripherals: dim(),
            concurrency: dim(),
            sanitizers: dim(),
        }
    }

    /// The dimensions that indicate whether the *target platform itself* was
    /// faithfully exercised. A gap in any of these — and only these — means
    /// findings are host-stub evidence, not target assurance. Concurrency and
    /// sanitizers describe fuzzing depth, not target platform fidelity, so they
    /// never on their own turn a native run into a "reduced-fidelity" caveat.
    fn platform_dimensions(&self) -> [&FidelityDimension; 4] {
        [
            &self.arch,
            &self.endianness,
            &self.rtos_runtime,
            &self.hardware_peripherals,
        ]
    }

    /// True when the target platform was not faithfully exercised (any platform
    /// dimension is a gap). False for a fully-native host target.
    pub fn is_reduced_fidelity(&self) -> bool {
        self.platform_dimensions().iter().any(|dim| dim.is_gap())
    }

    /// The human-readable caveat, derived from the structured record. `Some` only
    /// for a reduced-fidelity (host-stub) result; a native target returns `None`
    /// so it never carries a spurious caveat. When present it enumerates every
    /// un-exercised dimension, including concurrency.
    pub fn caveat(&self) -> Option<String> {
        if !self.is_reduced_fidelity() {
            return None;
        }
        let mut gaps: Vec<&str> = Vec::new();
        for (label, dim) in [
            ("target ISA/arch", &self.arch),
            ("endianness", &self.endianness),
            ("RTOS runtime", &self.rtos_runtime),
            ("hardware peripherals", &self.hardware_peripherals),
            ("concurrency", &self.concurrency),
        ] {
            if dim.is_gap() {
                gaps.push(label);
            }
        }
        Some(format!(
            "reduced-fidelity: portable logic fuzzed on host; NOT exercised: {}. \
             Findings are host-stub evidence, not target assurance.",
            gaps.join(", "),
        ))
    }

    /// Merge two records into the worst case per dimension (a genuine gap wins),
    /// keeping the reason from the winning side. The building block for a campaign
    /// rollup.
    pub fn worst_with(&self, other: &Fidelity) -> Fidelity {
        fn worst(a: &FidelityDimension, b: &FidelityDimension) -> FidelityDimension {
            if b.status.severity() > a.status.severity() {
                b.clone()
            } else {
                a.clone()
            }
        }
        Fidelity {
            arch: worst(&self.arch, &other.arch),
            endianness: worst(&self.endianness, &other.endianness),
            rtos_runtime: worst(&self.rtos_runtime, &other.rtos_runtime),
            hardware_peripherals: worst(&self.hardware_peripherals, &other.hardware_peripherals),
            concurrency: worst(&self.concurrency, &other.concurrency),
            sanitizers: worst(&self.sanitizers, &other.sanitizers),
        }
    }

    /// Roll a set of per-target records into a single worst-case campaign record.
    /// `None` when the set is empty (no fuzzed target).
    pub fn rollup<'a>(items: impl IntoIterator<Item = &'a Fidelity>) -> Option<Fidelity> {
        let mut iter = items.into_iter();
        let first = iter.next()?.clone();
        Some(iter.fold(first, |acc, f| acc.worst_with(f)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vxworks_facts() -> FidelityFacts {
        FidelityFacts {
            platform_stub: Some("vxworks".to_owned()),
            host_arch: "x86_64".to_owned(),
            host_endianness: Endianness::Little,
            sanitizers: vec!["asan".to_owned(), "ubsan".to_owned()],
            tsan_ran: false,
        }
    }

    #[test]
    fn platform_stub_marks_target_dimensions_not_exercised_with_reasons() {
        let f = Fidelity::from_facts(&vxworks_facts());

        assert_eq!(f.arch.status, FidelityStatus::NotExercised);
        assert_eq!(f.rtos_runtime.status, FidelityStatus::NotExercised);
        assert_eq!(f.hardware_peripherals.status, FidelityStatus::NotExercised);

        // Each gap carries a reason that names the platform / the missing surface.
        assert!(f.arch.reason.as_deref().unwrap().contains("vxworks"));
        assert!(f
            .rtos_runtime
            .reason
            .as_deref()
            .unwrap()
            .to_lowercase()
            .contains("rtos"));
        assert!(f
            .hardware_peripherals
            .reason
            .as_deref()
            .unwrap()
            .to_lowercase()
            .contains("hardware"));

        // The host stub build DID run under sanitizers.
        assert_eq!(f.sanitizers.status, FidelityStatus::Exercised);

        // And the derived caveat enumerates the target gaps and refuses assurance.
        let caveat = f.caveat().expect("a stubbed target must carry a caveat");
        assert!(caveat.contains("arch"), "{caveat}");
        assert!(caveat.contains("RTOS runtime"), "{caveat}");
        assert!(caveat.contains("hardware peripherals"), "{caveat}");
        assert!(caveat.contains("not target assurance"), "{caveat}");
    }

    #[test]
    fn native_host_target_has_no_spurious_caveat() {
        let mut facts = FidelityFacts::host();
        facts.sanitizers = vec!["asan".to_owned(), "ubsan".to_owned()];
        let f = Fidelity::from_facts(&facts);

        // The host IS the target: arch and byte order were genuinely exercised.
        assert_eq!(f.arch.status, FidelityStatus::Exercised);
        assert_eq!(f.endianness.status, FidelityStatus::Exercised);
        // RTOS / hardware simply do not apply — they are NOT gaps.
        assert_eq!(f.rtos_runtime.status, FidelityStatus::NotApplicable);
        assert_eq!(f.hardware_peripherals.status, FidelityStatus::NotApplicable);

        assert!(!f.is_reduced_fidelity());
        assert!(
            f.caveat().is_none(),
            "a fully-native host target must not carry a reduced-fidelity caveat"
        );
    }

    #[test]
    fn concurrency_is_exercised_only_when_tsan_ran() {
        let mut with_tsan = FidelityFacts::host();
        with_tsan.tsan_ran = true;
        assert_eq!(
            Fidelity::from_facts(&with_tsan).concurrency.status,
            FidelityStatus::Exercised
        );

        let mut without_tsan = FidelityFacts::host();
        without_tsan.tsan_ran = false;
        let f = Fidelity::from_facts(&without_tsan);
        assert_eq!(f.concurrency.status, FidelityStatus::NotExercised);

        // A missing TSan pass must NOT, on its own, turn a native run into a
        // reduced-fidelity caveat (that is a fuzzing-depth gap, not a platform gap).
        assert!(f.caveat().is_none());
    }

    #[test]
    fn fidelity_json_round_trips_and_keeps_shape() {
        let f = Fidelity::from_facts(&vxworks_facts());
        let value = serde_json::to_value(&f).unwrap();

        for dim in [
            "arch",
            "endianness",
            "rtos_runtime",
            "hardware_peripherals",
            "concurrency",
            "sanitizers",
        ] {
            assert!(value.get(dim).is_some(), "missing dimension {dim}");
            assert!(
                value[dim]["status"].is_string(),
                "status must serialize as a string for {dim}"
            );
        }
        // snake_case status tags on the wire.
        assert_eq!(value["arch"]["status"], "not_exercised");
        assert_eq!(value["rtos_runtime"]["status"], "not_exercised");

        // Exact round-trip back to an identical record.
        let back: Fidelity = serde_json::from_value(value).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn rollup_takes_the_worst_case_per_dimension() {
        let native = Fidelity::from_facts(&FidelityFacts::host());
        let stub = Fidelity::from_facts(&vxworks_facts());

        // Native alone is clean.
        assert!(!native.is_reduced_fidelity());

        // Rolled together, the stub's gaps must dominate.
        let rolled = Fidelity::rollup([&native, &stub]).expect("non-empty rollup");
        assert_eq!(rolled.arch.status, FidelityStatus::NotExercised);
        assert_eq!(rolled.rtos_runtime.status, FidelityStatus::NotExercised);
        assert_eq!(
            rolled.hardware_peripherals.status,
            FidelityStatus::NotExercised
        );
        assert!(rolled.is_reduced_fidelity());

        // An empty rollup is None (no fuzzed target).
        assert!(Fidelity::rollup(std::iter::empty()).is_none());
    }

    #[test]
    fn not_executed_record_has_no_gaps() {
        let f = Fidelity::not_executed("static analysis finding; nothing was executed");
        assert_eq!(f.arch.status, FidelityStatus::NotApplicable);
        assert!(!f.is_reduced_fidelity());
        assert!(f.caveat().is_none());
    }
}
