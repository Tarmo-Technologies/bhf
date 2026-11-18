// SPDX-License-Identifier: Apache-2.0

//! Board profiles (#293): one board's transport contract in a file, as
//! `bhf fuzz` takes it. A profile holds the `--target-transport` and
//! `--transport-coverage-map` specs of the board's debug-probe lane (`gdb`,
//! `coverage_map`) and the `--target-transport` spec of the reference agent on
//! its UART (`serial`), so a bring-up records the addresses, the completion
//! symbol, the fault word and the reset once. `docs/hil-bringup.md` is the
//! runbook; `docs/hil-boards/` has profiles to start from.
//!
//! ```toml
//! name = "nucleo-f411re"
//! gdb = "gdb:127.0.0.1:3333,done=0x08000201,fault=0x20000100,reset=monitor:reset halt"
//! coverage_map = "input=0x2000020c,input_cap=64,ring=0x20000004,write=0x20000204,wrapped=0x20000208,cap=512"
//! serial = "agent:serial:/dev/ttyACM0,baud=115200"
//! ```

use std::path::Path;

use serde::Deserialize;

use crate::transport_fuzz::TransportPlan;

/// Which of a board profile's lanes `bhf fuzz --board-profile` runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum BoardLane {
    /// The debug probe's gdbstub: the profile's `gdb` and `coverage_map`.
    #[default]
    Gdb,
    /// The reference agent on the board's UART: the profile's `serial`.
    Serial,
}

/// A board profile, as its TOML file spells it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BoardProfile {
    /// The board's name, for the run's log.
    pub name: String,
    /// The `--target-transport` spec of the debug-probe lane (`gdb:...`).
    #[serde(default)]
    pub gdb: Option<String>,
    /// Its `--transport-coverage-map` spec.
    #[serde(default)]
    pub coverage_map: Option<String>,
    /// The `--target-transport` spec of the agent lane (`agent:serial:...`).
    #[serde(default)]
    pub serial: Option<String>,
}

impl BoardProfile {
    /// Read the profile at `path`; each spec it names must parse as the
    /// lane's transport spec, so a mistyped profile fails before anything
    /// connects.
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("board profile {}: {error}", path.display()))?;
        let profile: Self = toml::from_str(&text)
            .map_err(|error| format!("board profile {}: {error}", path.display()))?;
        if profile.gdb.is_none() && profile.serial.is_none() {
            return Err(format!(
                "board profile {}: names neither a gdb nor a serial lane",
                path.display()
            ));
        }
        for lane in [BoardLane::Gdb, BoardLane::Serial] {
            if let Ok((spec, map)) = profile.lane(lane) {
                TransportPlan::parse(&spec, map.as_deref())
                    .map_err(|error| format!("board profile {}: {error}", path.display()))?;
            }
        }
        Ok(profile)
    }

    /// The `--target-transport` and `--transport-coverage-map` of `lane`.
    pub(crate) fn lane(&self, lane: BoardLane) -> Result<(String, Option<String>), String> {
        match lane {
            BoardLane::Gdb => {
                let spec = self
                    .gdb
                    .clone()
                    .ok_or_else(|| format!("board profile {:?} has no gdb lane", self.name))?;
                Ok((spec, self.coverage_map.clone()))
            }
            BoardLane::Serial => {
                let spec = self
                    .serial
                    .clone()
                    .ok_or_else(|| format!("board profile {:?} has no serial lane", self.name))?;
                Ok((spec, None))
            }
        }
    }
}

/// Fill `--target-transport` and `--transport-coverage-map` from
/// `--board-profile` (#293). Either flag given beside a profile is refused:
/// the profile is the board's contract, and a second spec would say two
/// things.
pub(crate) fn apply(args: &mut crate::fuzz::FuzzArgs) -> Result<(), String> {
    let Some(path) = args.board_profile.clone() else {
        return Ok(());
    };
    for (flag, given) in [
        ("--target-transport", args.target_transport.is_some()),
        (
            "--transport-coverage-map",
            args.transport_coverage_map.is_some(),
        ),
    ] {
        if given {
            return Err(format!(
                "{flag} cannot be given with --board-profile, which names the board's specs"
            ));
        }
    }
    let profile = BoardProfile::load(&path)?;
    let (spec, map) = profile.lane(args.board_lane)?;
    crate::bhfeprintln!(
        "bhf fuzz: board {:?} over {spec}{}",
        profile.name,
        map.as_deref()
            .map(|map| format!(" (coverage map {map})"))
            .unwrap_or_default()
    );
    args.target_transport = Some(spec);
    args.transport_coverage_map = map;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, text: &str) -> std::path::PathBuf {
        let path = dir.join("board.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    const RING: &str = "input=0x2000020c,input_cap=64,ring=0x20000004,write=0x20000204,\
                        wrapped=0x20000208,cap=512";

    #[test]
    fn a_profile_gives_each_lane_its_specs() {
        let dir = crate::test_support::TestDir::new("board-profile");
        let path = write(
            dir.path(),
            &format!(
                "name = \"nucleo\"\n\
                 gdb = \"gdb:127.0.0.1:3333,done=0x08000201,reset=monitor:reset halt\"\n\
                 coverage_map = \"{RING}\"\n\
                 serial = \"agent:serial:/dev/ttyACM0,baud=115200\"\n"
            ),
        );
        let profile = BoardProfile::load(&path).unwrap();
        assert_eq!(
            profile.lane(BoardLane::Gdb).unwrap(),
            (
                "gdb:127.0.0.1:3333,done=0x08000201,reset=monitor:reset halt".to_owned(),
                Some(RING.to_owned())
            )
        );
        assert_eq!(
            profile.lane(BoardLane::Serial).unwrap(),
            ("agent:serial:/dev/ttyACM0,baud=115200".to_owned(), None)
        );
    }

    /// The template the runbook starts from is a profile bhf takes.
    #[test]
    fn the_shipped_board_profile_template_loads() {
        let template = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/hil-boards/nucleo-f411re.toml");
        let profile = BoardProfile::load(&template).unwrap();
        assert_eq!(profile.name, "nucleo-f411re");
        for lane in [BoardLane::Gdb, BoardLane::Serial] {
            profile.lane(lane).unwrap();
        }
    }

    #[test]
    fn a_profile_that_would_not_run_is_refused_when_read() {
        let dir = crate::test_support::TestDir::new("board-profile-bad");
        for (text, want) in [
            ("name = \"x\"\n", "names neither a gdb nor a serial lane"),
            (
                "name = \"x\"\nserial = \"agent:serial:/dev/x\"\nbaud = 1\n",
                "unknown field",
            ),
            (
                "name = \"x\"\ngdb = \"gdb:127.0.0.1:3333\"\n",
                "--transport-coverage-map",
            ),
            (
                &format!("name = \"x\"\ngdb = \"gdb:h:1,reset=hard\"\ncoverage_map = \"{RING}\"\n"),
                "expected restart or monitor:COMMAND",
            ),
        ] {
            let error = BoardProfile::load(&write(dir.path(), text)).unwrap_err();
            assert!(error.contains(want), "{text}: {error}");
        }
        let profile = BoardProfile::load(&write(
            dir.path(),
            "name = \"uart-only\"\nserial = \"agent:serial:/dev/ttyUSB0\"\n",
        ))
        .unwrap();
        let error = profile.lane(BoardLane::Gdb).unwrap_err();
        assert!(error.contains("has no gdb lane"), "{error}");
    }
}
