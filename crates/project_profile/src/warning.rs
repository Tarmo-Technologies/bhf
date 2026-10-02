// SPDX-License-Identifier: Apache-2.0

//! Non-fatal compatibility / fidelity warnings surfaced during lowering and
//! resolution. These are recorded in provenance so an importer can see, for
//! example, that a declared grammar could not be honored by the chosen engine.

use serde::{Deserialize, Serialize};

/// A stable warning category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WarningKind {
    /// A grammar was declared but the selected engine cannot consume BHF's
    /// JSON grammar mutator (e.g. external `afl-fuzz`, or the binary lane).
    GrammarUnsupportedByEngine,
    /// An asset resolved outside the manifest directory (external path opt-in).
    ExternalPath,
}

/// A single warning: a stable `kind` plus a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warning {
    pub kind: WarningKind,
    pub message: String,
}

impl Warning {
    pub fn new(kind: WarningKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}
