// SPDX-License-Identifier: Apache-2.0

//! Full PageHeap for one WinAFL run (`--winafl-page-heap`).
//!
//! PageHeap is configured per image name, machine-wide, by an Image File
//! Execution Options key (what `gflags /p /enable <image> /full` writes). So
//! that no other run, campaign or later run ever sees it, each run fuzzes its
//! own copy of the WinAFL build under a name no other run uses
//! (`main_winafl-<pid>-<n>-<stamp>.exe`, beside the build) and sets the key for
//! that name only.
//!
//! The key carries an owner value (the bhf process id and start time, whether
//! bhf created the key, and the values it replaced), and the copy a marker
//! file beside it (`<copy>.bhf-run`, naming the same owner): what bhf deletes
//! later is only what one of them proves a bhf run made. bhf restores what it
//! changed when the run ends, and from a console control handler on Ctrl-C,
//! Ctrl-Break or a closed console, which also stops the targets and then
//! deletes the copies. A run killed outright (`taskkill /F`) runs neither, so
//! every WinAFL run first reclaims the keys and copies of owners that are no
//! longer running. Only the values bhf wrote are touched, and the key is
//! deleted only when bhf created it and nothing else is in it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::FUZZ_BINARY_STEM;

/// The Image File Execution Options key, under which each image name has its
/// own subkey.
pub(crate) const IFEO: &str =
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
pub(crate) const GLOBAL_FLAG: &str = "GlobalFlag";
pub(crate) const PAGE_HEAP_FLAGS: &str = "PageHeapFlags";
/// The value that marks a key as set by a bhf run, and by which one.
pub(crate) const OWNER_VALUE: &str = "BhfPageHeapOwner";
/// `FLG_HEAP_PAGE_ALLOCS` in `GlobalFlag`.
pub(crate) const FLG_HEAP_PAGE_ALLOCS: u32 = 0x0200_0000;
/// `PageHeapFlags` for full PageHeap (enabled, full).
pub(crate) const FULL_PAGE_HEAP: u32 = 0x3;

/// A registry value as bhf reads and writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegValue {
    Dword(u32),
    Str(String),
    /// A value of another type, kept so a key is never mistaken for empty.
    #[cfg_attr(not(windows), allow(dead_code))]
    Other(u32),
}

/// The registry operations the PageHeap guard needs, on full key paths
/// (`HKLM\...`). The Windows registry implements it; tests use a map.
pub(crate) trait Registry: Send + Sync {
    /// Every value of `key`, or `None` when the key does not exist.
    fn values(&self, key: &str) -> Result<Option<BTreeMap<String, RegValue>>, String>;
    /// The names of the subkeys of `key` (none when it does not exist).
    fn subkeys(&self, key: &str) -> Result<Vec<String>, String>;
    /// Create `key`, or open it when it exists.
    fn create_key(&self, key: &str) -> Result<(), String>;
    fn set_value(&self, key: &str, name: &str, value: &RegValue) -> Result<(), String>;
    /// Delete one value; a missing value or key is not an error.
    fn delete_value(&self, key: &str, name: &str) -> Result<(), String>;
    /// Delete `key` when it holds no value and no subkey; true when deleted.
    fn delete_key_if_empty(&self, key: &str) -> Result<bool, String>;
    /// Whether this process may create a subkey of `key` (an elevated shell,
    /// for the Image File Execution Options key).
    fn writable(&self, key: &str) -> bool;
}

/// The bhf process that set a key: its id and start time, so a reused process
/// id is not taken for the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Owner {
    pub(crate) pid: u32,
    pub(crate) started: u64,
}

/// What bhf records in [`OWNER_VALUE`]: who set the key, and what to put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnerRecord {
    pub(crate) owner: Owner,
    /// bhf created the key, so it may delete it once its own values are gone.
    pub(crate) created_key: bool,
    /// The `GlobalFlag` and `PageHeapFlags` the key held before (`None`: the
    /// value was absent and is deleted again).
    pub(crate) previous_global_flag: Option<u32>,
    pub(crate) previous_page_heap_flags: Option<u32>,
}

fn encode_previous(value: Option<u32>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("0x{value:x}"))
}

fn parse_previous(text: &str) -> Option<Option<u32>> {
    if text == "-" {
        return Some(None);
    }
    u32::from_str_radix(text.strip_prefix("0x")?, 16)
        .ok()
        .map(Some)
}

impl OwnerRecord {
    pub(crate) fn encode(&self) -> String {
        format!(
            "bhf pid={} started={} created={} {GLOBAL_FLAG}={} {PAGE_HEAP_FLAGS}={}",
            self.owner.pid,
            self.owner.started,
            u8::from(self.created_key),
            encode_previous(self.previous_global_flag),
            encode_previous(self.previous_page_heap_flags)
        )
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut words = text.split_whitespace();
        (words.next()? == "bhf").then_some(())?;
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for word in words {
            let (name, value) = word.split_once('=')?;
            fields.insert(name, value);
        }
        Some(Self {
            owner: Owner {
                pid: fields.get("pid")?.parse().ok()?,
                started: fields.get("started")?.parse().ok()?,
            },
            created_key: match *fields.get("created")? {
                "1" => true,
                "0" => false,
                _ => return None,
            },
            previous_global_flag: parse_previous(fields.get(GLOBAL_FLAG)?)?,
            previous_page_heap_flags: parse_previous(fields.get(PAGE_HEAP_FLAGS)?)?,
        })
    }
}

impl Owner {
    /// The text of a copy's marker file.
    pub(crate) fn encode(&self) -> String {
        format!("bhf pid={} started={}\n", self.pid, self.started)
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut words = text.split_whitespace();
        (words.next()? == "bhf").then_some(())?;
        let (mut pid, mut started) = (None, None);
        for word in words {
            match word.split_once('=')? {
                ("pid", value) => pid = Some(value.parse().ok()?),
                ("started", value) => started = Some(value.parse().ok()?),
                _ => return None,
            }
        }
        Some(Self {
            pid: pid?,
            started: started?,
        })
    }
}

/// What the marker beside a run's copy is named after: `<copy>.bhf-run`.
pub(crate) const MARKER_SUFFIX: &str = ".bhf-run";

/// The marker file of the run copy `image`.
pub(crate) fn marker_path(image: &Path) -> PathBuf {
    let mut name = image.file_name().unwrap_or_default().to_os_string();
    name.push(MARKER_SUFFIX);
    image.with_file_name(name)
}

/// The process id in a run-unique image name, `main_winafl-<pid>-<n>-<hex>`
/// with the platform's executable suffix (ignoring case, as the registry and
/// the file system do), or `None` for any other name.
pub(crate) fn run_image_pid(name: &str) -> Option<u32> {
    let suffix = std::env::consts::EXE_SUFFIX;
    let prefix = format!("{FUZZ_BINARY_STEM}-");
    if !starts_with_ignore_case(name, &prefix) || name.len() < prefix.len() + suffix.len() {
        return None;
    }
    let (rest, tail) = name[prefix.len()..].split_at(name.len() - prefix.len() - suffix.len());
    if !tail.eq_ignore_ascii_case(suffix) {
        return None;
    }
    let mut parts = rest.split('-');
    let (pid, sequence, stamp) = (parts.next()?, parts.next()?, parts.next()?);
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    let hex = !stamp.is_empty() && stamp.bytes().all(|byte| byte.is_ascii_hexdigit());
    (parts.next().is_none() && digits(pid) && digits(sequence) && hex)
        .then(|| pid.parse().ok())
        .flatten()
}

pub(crate) fn image_key(image: &str) -> String {
    format!("{IFEO}\\{image}")
}

/// A value by name, ignoring case as the registry does.
fn value<'a>(values: &'a BTreeMap<String, RegValue>, name: &str) -> Option<&'a RegValue> {
    values
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn dword(values: &BTreeMap<String, RegValue>, name: &str) -> Option<u32> {
    match value(values, name) {
        Some(RegValue::Dword(value)) => Some(*value),
        _ => None,
    }
}

/// The owner a key was tagged with, if bhf tagged it.
pub(crate) fn owner_of(values: &BTreeMap<String, RegValue>) -> Option<OwnerRecord> {
    match value(values, OWNER_VALUE) {
        Some(RegValue::Str(text)) => OwnerRecord::parse(text),
        _ => None,
    }
}

/// Whether `values` turn full PageHeap on for their image.
pub(crate) fn page_heap_in_effect(values: &BTreeMap<String, RegValue>) -> bool {
    dword(values, GLOBAL_FLAG).is_some_and(|flags| flags & FLG_HEAP_PAGE_ALLOCS != 0)
}

/// Whether the PageHeap of the image named `image` is on, from its key.
pub(crate) fn configured_for(registry: &dyn Registry, image: &str) -> bool {
    registry
        .values(&image_key(image))
        .ok()
        .flatten()
        .is_some_and(|values| page_heap_in_effect(&values))
}

/// Put back what `record` says bhf changed under `key`: each of its two
/// values restored to what it was, or deleted when it was absent, then the
/// owner value; and the key itself deleted when bhf created it and nothing
/// else is left in it. Restoring twice is harmless.
pub(crate) fn restore(
    registry: &dyn Registry,
    key: &str,
    record: &OwnerRecord,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for (name, previous) in [
        (GLOBAL_FLAG, record.previous_global_flag),
        (PAGE_HEAP_FLAGS, record.previous_page_heap_flags),
    ] {
        let result = match previous {
            Some(previous) => registry.set_value(key, name, &RegValue::Dword(previous)),
            None => registry.delete_value(key, name),
        };
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if let Err(error) = registry.delete_value(key, OWNER_VALUE) {
        errors.push(error);
    }
    if record.created_key {
        if let Err(error) = registry.delete_key_if_empty(key) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// What a process id is now ([`process_liveness`] on this host; tests pass
/// their own).
pub(crate) type Probe = dyn Fn(u32) -> Liveness;

/// Whether the bhf process `owner` names still runs: a reused process id has
/// another start time, and one bhf may not query counts as running.
fn owner_running(probe: &Probe, owner: &Owner) -> bool {
    match probe(owner.pid) {
        Liveness::Running(started) => started == owner.started,
        Liveness::Gone => false,
        Liveness::Unknown => true,
    }
}

/// Restore every `main_winafl*` key whose bhf owner is no longer running (a
/// run killed before it could clean up), and delete an empty key with a
/// run-unique name whose process is gone (a run killed between creating the
/// key and tagging it, or between untagging and deleting it). Other keys are
/// left alone: someone else configured them. So is a key that cannot be read.
/// Returns the reclaimed image names.
pub(crate) fn reclaim_dead_owners(registry: &dyn Registry, probe: &Probe) -> Vec<String> {
    let names = match registry.subkeys(IFEO) {
        Ok(names) => names,
        Err(error) => {
            bhfeprintln!(
                "bhf: warning: could not list the PageHeap keys earlier runs left: {error}"
            );
            return Vec::new();
        }
    };
    let mut reclaimed = Vec::new();
    for name in names {
        if !starts_with_ignore_case(&name, FUZZ_BINARY_STEM) {
            continue;
        }
        let key = image_key(&name);
        let Ok(Some(values)) = registry.values(&key) else {
            continue;
        };
        let Some(record) = owner_of(&values) else {
            let stopped = run_image_pid(&name).is_some_and(|pid| probe(pid) == Liveness::Gone);
            if values.is_empty() && stopped && registry.delete_key_if_empty(&key) == Ok(true) {
                bhfeprintln!("bhf: removed the empty PageHeap key a stopped run left for {name}");
                reclaimed.push(name);
            }
            continue;
        };
        if owner_running(probe, &record.owner) {
            continue;
        }
        match restore(registry, &key, &record) {
            Ok(()) => {
                bhfeprintln!(
                    "bhf: removed the PageHeap setting a stopped run (pid {}) left for {name}",
                    record.owner.pid
                );
                reclaimed.push(name);
            }
            Err(error) => bhfeprintln!(
                "bhf: warning: could not remove the PageHeap setting a stopped run left under \
                 {key}: {error}; remove it from an elevated shell with: {}",
                manual_removal_command(&key)
            ),
        }
    }
    reclaimed
}

fn starts_with_ignore_case(text: &str, prefix: &str) -> bool {
    text.len() >= prefix.len()
        && text.is_char_boundary(prefix.len())
        && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Delete the run copy `image`, waiting up to `wait` while its process still
/// exits (Windows does not delete a running image), then its marker. The
/// marker stays while the copy does, so a later run can still prove the copy
/// bhf's. True when the copy is gone.
pub(crate) fn remove_copy(image: &Path, wait: Duration) -> bool {
    let until = std::time::Instant::now() + wait;
    loop {
        match std::fs::remove_file(image) {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) if std::time::Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    }
    let _ = std::fs::remove_file(marker_path(image));
    true
}

/// Delete the run copies in `dir` whose marker names a bhf run that has
/// stopped, with their markers (and a marker whose copy is already gone). A
/// file without a marker, under any name, is not bhf's to delete. A copy is
/// kept while its owner, or the owner on its key, still runs, and when its
/// key or marker cannot be read.
pub(crate) fn reclaim_stale_copies(registry: &dyn Registry, dir: &Path, probe: &Probe) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut images: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let image = match name.len().checked_sub(MARKER_SUFFIX.len()) {
            Some(cut)
                if name.is_char_boundary(cut)
                    && name[cut..].eq_ignore_ascii_case(MARKER_SUFFIX) =>
            {
                name[..cut].to_owned()
            }
            _ => name,
        };
        if run_image_pid(&image).is_some() {
            images.insert(image);
        }
    }
    for name in images {
        let image = dir.join(&name);
        let Ok(marker) = std::fs::read_to_string(marker_path(&image)) else {
            continue;
        };
        let Some(owner) = Owner::parse(&marker) else {
            continue;
        };
        let key_owner_runs = match registry.values(&image_key(&name)) {
            Ok(values) => values
                .as_ref()
                .and_then(owner_of)
                .is_some_and(|record| owner_running(probe, &record.owner)),
            // Unreadable: it may be a live run's, so its copy stays.
            Err(_) => true,
        };
        if owner_running(probe, &owner) || key_owner_runs {
            continue;
        }
        remove_copy(&image, Duration::ZERO);
    }
}

/// The command that removes `key` by hand, the key one word of the
/// operator's shell (PowerShell's on Windows).
pub(crate) fn manual_removal_command(key: &str) -> String {
    format!("reg delete {} /f", crate::repro_lane::host_word(key))
}

/// Reclaim what stopped runs left: their keys, when this process may write
/// them, and their copies of the build in `dir`. Every WinAFL run does this
/// first, with or without PageHeap.
pub(crate) fn reclaim(registry: &dyn Registry, probe: &Probe, dir: &Path) {
    if registry.writable(IFEO) {
        reclaim_dead_owners(registry, probe);
    }
    reclaim_stale_copies(registry, dir, probe);
}

/// The run-unique image name for one run's copy of the WinAFL build, with
/// the platform's executable suffix as the build has (`.exe` on Windows).
pub(crate) fn run_image_name(owner: &Owner) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    crate::auto::layout::harness_exe_name(&format!(
        "{FUZZ_BINARY_STEM}-{}-{sequence}-{:x}",
        owner.pid,
        stamp & 0xffff_ffff
    ))
}

/// The runs of this process whose key or copy is still to be cleaned up, for
/// the console control handler.
struct Active {
    id: u64,
    registry: Arc<dyn Registry>,
    key: String,
    /// What to put back under `key`; `None` once it has been.
    record: Option<OwnerRecord>,
    /// The run's copy of the build.
    image: PathBuf,
}

static ACTIVE: Mutex<Vec<Active>> = Mutex::new(Vec::new());

fn active() -> std::sync::MutexGuard<'static, Vec<Active>> {
    ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Set once a console control event is ending this process.
static STOPPING: AtomicBool = AtomicBool::new(false);

/// How long the console control handler waits for a stopped target to exit
/// before it gives up on deleting the copy (a closed console allows a handler
/// 5 s in all).
const COPY_WAIT_ON_STOP: Duration = Duration::from_secs(2);

/// Whether a console control event (Ctrl-C, Ctrl-Break, a closed console) is
/// ending this process: a run then starts nothing more.
pub(crate) fn console_stopping() -> bool {
    STOPPING.load(Ordering::SeqCst)
}

/// What the console control handler does: restore every key a live run of
/// this process set, stop the process trees fuzzing (WinAFL, DynamoRIO and the
/// targets), then delete the run copies, which Windows does not delete while
/// they run, and say where each run's unreplayed inputs stay. Each key is restored once: a run's `Drop` restores under the same
/// lock and then finds nothing left to do.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn console_stop() -> usize {
    STOPPING.store(true, Ordering::SeqCst);
    let restored = stop_active(|_| true, super::stop_all_process_trees, COPY_WAIT_ON_STOP);
    super::print_stop_notes();
    restored
}

fn stop_active(select: impl Fn(&Active) -> bool, stop: impl FnOnce(), wait: Duration) -> usize {
    let (restored, images) = {
        let mut entries = active();
        let mut restored = 0;
        for entry in entries.iter_mut().filter(|entry| select(entry)) {
            if let Some(record) = entry.record.take() {
                let _ = restore(entry.registry.as_ref(), &entry.key, &record);
                restored += 1;
            }
        }
        let images: Vec<PathBuf> = entries
            .iter()
            .filter(|entry| select(entry))
            .map(|entry| entry.image.clone())
            .collect();
        (restored, images)
    };
    stop();
    let until = std::time::Instant::now() + wait;
    for image in images {
        remove_copy(
            &image,
            until.saturating_duration_since(std::time::Instant::now()),
        );
    }
    restored
}

/// Full PageHeap on one run's copy of the WinAFL build, for as long as this
/// value lives.
pub(crate) struct PageHeapRun {
    /// The copy WinAFL fuzzes, beside the build.
    pub(crate) image: PathBuf,
    /// Its Image File Execution Options key.
    pub(crate) key: String,
    /// PageHeap as read back from the key after it was set.
    pub(crate) in_effect: bool,
    id: u64,
    registry: Arc<dyn Registry>,
}

impl PageHeapRun {
    /// Reclaim what stopped runs left, then copy `build` to a run-unique name
    /// beside it, with a marker naming `owner`, and turn full PageHeap on for
    /// that name. A key or file already under that name is refused, not
    /// adopted. On any failure what was changed is put back.
    pub(crate) fn start(
        registry: Arc<dyn Registry>,
        owner: Owner,
        probe: &Probe,
        build: &Path,
    ) -> Result<Self, String> {
        let name = run_image_name(&owner);
        Self::start_as(registry, owner, probe, build, name)
    }

    /// [`Self::start`] under the image name `name`.
    fn start_as(
        registry: Arc<dyn Registry>,
        owner: Owner,
        probe: &Probe,
        build: &Path,
        name: String,
    ) -> Result<Self, String> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        install_console_handler();
        let dir = build.parent().unwrap_or(Path::new("."));
        reclaim(registry.as_ref(), probe, dir);

        let key = image_key(&name);
        let image = dir.join(&name);
        if registry.values(&key)?.is_some() {
            return Err(format!(
                "--winafl-page-heap: {key} already exists; bhf sets PageHeap only under a key it \
                 creates for the run"
            ));
        }
        if image.exists() || marker_path(&image).exists() {
            return Err(format!(
                "--winafl-page-heap: {} (or its marker) already exists; bhf copies the build \
                 only to a name no file has",
                image.display()
            ));
        }
        let record = OwnerRecord {
            owner,
            created_key: true,
            previous_global_flag: None,
            previous_page_heap_flags: None,
        };
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        // Registered before the first write, so a Ctrl-C from here on restores.
        active().push(Active {
            id,
            registry: Arc::clone(&registry),
            key: key.clone(),
            record: Some(record.clone()),
            image: image.clone(),
        });
        let mut run = Self {
            image,
            key: key.clone(),
            in_effect: false,
            id,
            registry,
        };
        let elevated_hint = |error: String| {
            format!(
                "--winafl-page-heap sets PageHeap for {name} under {key}, which needs an elevated \
                 (administrator) shell: {error}"
            )
        };
        run.registry.create_key(&key).map_err(elevated_hint)?;
        run.registry
            .set_value(&key, OWNER_VALUE, &RegValue::Str(record.encode()))
            .map_err(elevated_hint)?;
        run.registry
            .set_value(&key, GLOBAL_FLAG, &RegValue::Dword(FLG_HEAP_PAGE_ALLOCS))
            .map_err(elevated_hint)?;
        run.registry
            .set_value(&key, PAGE_HEAP_FLAGS, &RegValue::Dword(FULL_PAGE_HEAP))
            .map_err(elevated_hint)?;
        // The marker first: whatever of the copy exists is then provably bhf's.
        let marker = marker_path(&run.image);
        std::fs::write(&marker, owner.encode())
            .map_err(|error| format!("--winafl-page-heap: write {}: {error}", marker.display()))?;
        std::fs::copy(build, &run.image).map_err(|error| {
            format!(
                "--winafl-page-heap: copy {} to {}: {error}",
                build.display(),
                run.image.display()
            )
        })?;
        run.in_effect = run
            .registry
            .values(&key)?
            .is_some_and(|values| page_heap_in_effect(&values));
        Ok(run)
    }
}

impl Drop for PageHeapRun {
    fn drop(&mut self) {
        {
            // The restore runs under the lock, so a console control event in
            // the middle of it waits for it instead of finding nothing to do.
            let mut entries = active();
            if let Some(entry) = entries.iter_mut().find(|entry| entry.id == self.id) {
                if let Some(record) = entry.record.take() {
                    if let Err(error) = restore(self.registry.as_ref(), &entry.key, &record) {
                        bhfeprintln!(
                            "bhf: warning: could not remove the PageHeap setting under {}: \
                             {error}; remove it from an elevated shell with: {}",
                            entry.key,
                            manual_removal_command(&entry.key)
                        );
                    }
                }
            }
        }
        // The target may still be exiting after its job was ended.
        if !remove_copy(&self.image, Duration::from_secs(2)) {
            bhfeprintln!(
                "bhf: warning: could not delete {}, the run's copy of the WinAFL build; a later \
                 WinAFL run deletes it",
                self.image.display()
            );
        }
        active().retain(|entry| entry.id != self.id);
    }
}

/// Whether a process is running, and since when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Liveness {
    /// Running, started at this time.
    Running(u64),
    Gone,
    /// It exists but bhf may not query it: treated as running, so its key is
    /// left alone.
    Unknown,
}

/// The owner a process with `liveness` is recorded as: an error when its
/// start time is unknown, since another run would take a recorded `0` for a
/// stopped owner.
fn owner_from(pid: u32, liveness: Liveness) -> Result<Owner, String> {
    match liveness {
        Liveness::Running(started) => Ok(Owner { pid, started }),
        Liveness::Gone | Liveness::Unknown => Err(format!(
            "--winafl-page-heap: could not read the start time of this process (pid {pid}), \
             which the PageHeap key records so other runs can tell whether it still runs"
        )),
    }
}

/// The current process, as recorded in an owner value.
pub(crate) fn current_owner() -> Result<Owner, String> {
    let pid = std::process::id();
    owner_from(pid, process_liveness(pid))
}

/// Whether the process `owner` names is still running (a reused process id
/// has another start time).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn owner_alive(owner: &Owner) -> bool {
    owner_running(&process_liveness, owner)
}

#[cfg(windows)]
pub(crate) fn process_liveness(pid: u32) -> Liveness {
    win::process_liveness(pid)
}

/// The start time of a process from `/proc/<pid>/stat` (in clock ticks), so
/// the owner logic behaves the same in tests off Windows.
#[cfg(not(windows))]
pub(crate) fn process_liveness(pid: u32) -> Liveness {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return Liveness::Gone;
    };
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19)?.parse().ok())
        .map_or(Liveness::Unknown, Liveness::Running)
}

/// The registry of this host: the Windows registry, or none at all elsewhere
/// (nothing is configured, and nothing can be written).
pub(crate) fn system_registry() -> Arc<dyn Registry> {
    #[cfg(windows)]
    {
        Arc::new(win::WindowsRegistry)
    }
    #[cfg(not(windows))]
    {
        Arc::new(NoRegistry)
    }
}

#[cfg(not(windows))]
struct NoRegistry;

#[cfg(not(windows))]
impl Registry for NoRegistry {
    fn values(&self, _key: &str) -> Result<Option<BTreeMap<String, RegValue>>, String> {
        Ok(None)
    }
    fn subkeys(&self, _key: &str) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    fn create_key(&self, key: &str) -> Result<(), String> {
        Err(format!("{key}: there is no Windows registry on this host"))
    }
    fn set_value(&self, key: &str, _name: &str, _value: &RegValue) -> Result<(), String> {
        self.create_key(key)
    }
    fn delete_value(&self, _key: &str, _name: &str) -> Result<(), String> {
        Ok(())
    }
    fn delete_key_if_empty(&self, _key: &str) -> Result<bool, String> {
        Ok(false)
    }
    fn writable(&self, _key: &str) -> bool {
        false
    }
}

/// Install the console control handler (once per process; nothing elsewhere
/// than Windows).
pub(crate) fn install_console_handler() {
    #[cfg(windows)]
    {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(win::install_console_handler);
    }
}

#[cfg(windows)]
mod win {
    //! The Windows registry (advapi32) and the process and console calls the
    //! guard needs, without a dependency.
    use super::{Liveness, RegValue, Registry};
    use std::collections::BTreeMap;

    type Hkey = *mut core::ffi::c_void;
    type Handle = *mut core::ffi::c_void;

    const ERROR_SUCCESS: i32 = 0;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_NO_MORE_ITEMS: i32 = 259;
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;
    const KEY_CREATE_SUB_KEY: u32 = 0x0004;
    const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
    const KEY_WOW64_64KEY: u32 = 0x0100;
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_DWORD: u32 = 4;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(key: Hkey, sub: *const u16, options: u32, sam: u32, out: *mut Hkey)
            -> i32;
        fn RegCreateKeyExW(
            key: Hkey,
            sub: *const u16,
            reserved: u32,
            class: *mut u16,
            options: u32,
            sam: u32,
            security: *const core::ffi::c_void,
            out: *mut Hkey,
            disposition: *mut u32,
        ) -> i32;
        fn RegQueryInfoKeyW(
            key: Hkey,
            class: *mut u16,
            class_len: *mut u32,
            reserved: *mut u32,
            subkeys: *mut u32,
            max_subkey_len: *mut u32,
            max_class_len: *mut u32,
            values: *mut u32,
            max_value_name_len: *mut u32,
            max_value_len: *mut u32,
            security: *mut u32,
            written: *mut FileTime,
        ) -> i32;
        fn RegEnumKeyExW(
            key: Hkey,
            index: u32,
            name: *mut u16,
            name_len: *mut u32,
            reserved: *mut u32,
            class: *mut u16,
            class_len: *mut u32,
            written: *mut FileTime,
        ) -> i32;
        fn RegEnumValueW(
            key: Hkey,
            index: u32,
            name: *mut u16,
            name_len: *mut u32,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            data_len: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            key: Hkey,
            name: *const u16,
            reserved: u32,
            kind: u32,
            data: *const u8,
            data_len: u32,
        ) -> i32;
        fn RegDeleteValueW(key: Hkey, name: *const u16) -> i32;
        fn RegDeleteKeyExW(key: Hkey, sub: *const u16, sam: u32, reserved: u32) -> i32;
        fn RegCloseKey(key: Hkey) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn GetProcessTimes(
            process: Handle,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn GetExitCodeProcess(process: Handle, code: *mut u32) -> i32;
        fn GetLastError() -> u32;
        fn CloseHandle(handle: Handle) -> i32;
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn os_error(status: i32) -> String {
        std::io::Error::from_raw_os_error(status).to_string()
    }

    /// `HKLM\rest` or `HKCU\rest` as the predefined root and the rest.
    fn split(key: &str) -> Result<(Hkey, &str), String> {
        let (root, rest) = key
            .split_once('\\')
            .ok_or_else(|| format!("{key}: not a full registry key"))?;
        let root = match root.to_ascii_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => 0x8000_0002u32 as i32 as isize,
            "HKCU" | "HKEY_CURRENT_USER" => 0x8000_0001u32 as i32 as isize,
            _ => return Err(format!("{key}: unsupported registry root {root}")),
        };
        Ok((root as Hkey, rest))
    }

    /// An open key, closed on drop.
    struct Key(Hkey);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: closing a key this value opened.
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    /// Open `key`; `Ok(None)` when it does not exist.
    fn open(key: &str, access: u32) -> Result<Option<Key>, String> {
        let (root, rest) = split(key)?;
        let sub = wide(rest);
        let mut out: Hkey = core::ptr::null_mut();
        // SAFETY: `sub` is NUL-terminated and outlives the call; `out` is a
        // valid out pointer.
        let status =
            unsafe { RegOpenKeyExW(root, sub.as_ptr(), 0, access | KEY_WOW64_64KEY, &mut out) };
        match status {
            ERROR_SUCCESS => Ok(Some(Key(out))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(format!("open {key}: {}", os_error(other))),
        }
    }

    fn counts(key: &Key) -> Result<(u32, u32, u32, u32), String> {
        let (mut subkeys, mut values, mut max_name, mut max_data) = (0u32, 0u32, 0u32, 0u32);
        let mut max_subkey = 0u32;
        // SAFETY: every out pointer is valid or null as the API allows.
        let status = unsafe {
            RegQueryInfoKeyW(
                key.0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut subkeys,
                &mut max_subkey,
                core::ptr::null_mut(),
                &mut values,
                &mut max_name,
                &mut max_data,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("query key: {}", os_error(status)));
        }
        Ok((subkeys, values, max_name.max(max_subkey), max_data))
    }

    fn utf16_string(units: &[u16]) -> String {
        let end = units
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(units.len());
        String::from_utf16_lossy(&units[..end])
    }

    pub(super) struct WindowsRegistry;

    impl Registry for WindowsRegistry {
        fn values(&self, key: &str) -> Result<Option<BTreeMap<String, RegValue>>, String> {
            let Some(open) = open(key, KEY_QUERY_VALUE)? else {
                return Ok(None);
            };
            let (_, count, max_name, max_data) =
                counts(&open).map_err(|e| format!("{key}: {e}"))?;
            let mut out = BTreeMap::new();
            for index in 0..count {
                let mut name = vec![0u16; max_name as usize + 1];
                let mut name_len = name.len() as u32;
                let mut data = vec![0u8; max_data as usize + 2];
                let mut data_len = data.len() as u32;
                let mut kind = 0u32;
                // SAFETY: the buffers are as long as the lengths passed.
                let status = unsafe {
                    RegEnumValueW(
                        open.0,
                        index,
                        name.as_mut_ptr(),
                        &mut name_len,
                        core::ptr::null_mut(),
                        &mut kind,
                        data.as_mut_ptr(),
                        &mut data_len,
                    )
                };
                if status == ERROR_NO_MORE_ITEMS {
                    break;
                }
                if status != ERROR_SUCCESS {
                    return Err(format!("read the values of {key}: {}", os_error(status)));
                }
                let name = String::from_utf16_lossy(&name[..name_len as usize]);
                let data = &data[..data_len as usize];
                let value = match kind {
                    REG_DWORD if data.len() >= 4 => {
                        RegValue::Dword(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
                    }
                    REG_SZ | REG_EXPAND_SZ => {
                        let units: Vec<u16> = data
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|pair| u16::from_le_bytes(*pair))
                            .collect();
                        RegValue::Str(utf16_string(&units))
                    }
                    other => RegValue::Other(other),
                };
                out.insert(name, value);
            }
            Ok(Some(out))
        }

        fn subkeys(&self, key: &str) -> Result<Vec<String>, String> {
            let Some(open) = open(key, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE)? else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for index in 0.. {
                let mut name = vec![0u16; 512];
                let mut name_len = name.len() as u32;
                // SAFETY: `name` is as long as `name_len` says.
                let status = unsafe {
                    RegEnumKeyExW(
                        open.0,
                        index,
                        name.as_mut_ptr(),
                        &mut name_len,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                };
                match status {
                    ERROR_SUCCESS => out.push(String::from_utf16_lossy(&name[..name_len as usize])),
                    ERROR_NO_MORE_ITEMS => break,
                    other => return Err(format!("list the subkeys of {key}: {}", os_error(other))),
                }
            }
            Ok(out)
        }

        fn create_key(&self, key: &str) -> Result<(), String> {
            let (root, rest) = split(key)?;
            let sub = wide(rest);
            let mut out: Hkey = core::ptr::null_mut();
            let mut disposition = 0u32;
            // SAFETY: `sub` is NUL-terminated; the out pointers are valid.
            let status = unsafe {
                RegCreateKeyExW(
                    root,
                    sub.as_ptr(),
                    0,
                    core::ptr::null_mut(),
                    0,
                    KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY,
                    core::ptr::null(),
                    &mut out,
                    &mut disposition,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(format!("create {key}: {}", os_error(status)));
            }
            drop(Key(out));
            Ok(())
        }

        fn set_value(&self, key: &str, name: &str, value: &RegValue) -> Result<(), String> {
            let open = open(key, KEY_SET_VALUE)?.ok_or_else(|| format!("{key} does not exist"))?;
            let (kind, data): (u32, Vec<u8>) = match value {
                RegValue::Dword(value) => (REG_DWORD, value.to_le_bytes().to_vec()),
                RegValue::Str(text) => (
                    REG_SZ,
                    wide(text)
                        .iter()
                        .flat_map(|unit| unit.to_le_bytes())
                        .collect(),
                ),
                RegValue::Other(kind) => {
                    return Err(format!(
                        "{key}\\{name}: cannot write a value of type {kind}"
                    ))
                }
            };
            let name_w = wide(name);
            // SAFETY: `name_w` is NUL-terminated and `data` is `data.len()` bytes.
            let status = unsafe {
                RegSetValueExW(
                    open.0,
                    name_w.as_ptr(),
                    0,
                    kind,
                    data.as_ptr(),
                    data.len() as u32,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(format!("set {key}\\{name}: {}", os_error(status)));
            }
            Ok(())
        }

        fn delete_value(&self, key: &str, name: &str) -> Result<(), String> {
            let Some(open) = open(key, KEY_SET_VALUE)? else {
                return Ok(());
            };
            let name_w = wide(name);
            // SAFETY: `name_w` is NUL-terminated.
            let status = unsafe { RegDeleteValueW(open.0, name_w.as_ptr()) };
            match status {
                ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
                other => Err(format!("delete {key}\\{name}: {}", os_error(other))),
            }
        }

        fn delete_key_if_empty(&self, key: &str) -> Result<bool, String> {
            let Some(open) = open(key, KEY_QUERY_VALUE)? else {
                return Ok(false);
            };
            let (subkeys, values, _, _) = counts(&open).map_err(|e| format!("{key}: {e}"))?;
            drop(open);
            if subkeys != 0 || values != 0 {
                return Ok(false);
            }
            let (root, rest) = split(key)?;
            let sub = wide(rest);
            // SAFETY: `sub` is NUL-terminated.
            let status = unsafe { RegDeleteKeyExW(root, sub.as_ptr(), KEY_WOW64_64KEY, 0) };
            match status {
                ERROR_SUCCESS => Ok(true),
                ERROR_FILE_NOT_FOUND => Ok(false),
                other => Err(format!("delete {key}: {}", os_error(other))),
            }
        }

        fn writable(&self, key: &str) -> bool {
            open(key, KEY_CREATE_SUB_KEY | KEY_SET_VALUE).is_ok_and(|opened| opened.is_some())
        }
    }

    pub(super) fn process_liveness(pid: u32) -> Liveness {
        // SAFETY: plain process queries on a handle closed before returning.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                // ERROR_INVALID_PARAMETER: no such process. Any other failure
                // is a process bhf may not open.
                return if GetLastError() == ERROR_INVALID_PARAMETER {
                    Liveness::Gone
                } else {
                    Liveness::Unknown
                };
            }
            let mut code = 0u32;
            let exited = GetExitCodeProcess(handle, &mut code) != 0 && code != STILL_ACTIVE;
            let mut times = [FileTime::default(); 4];
            let [creation, exit, kernel, user] = &mut times;
            let read = GetProcessTimes(handle, creation, exit, kernel, user) != 0;
            CloseHandle(handle);
            if exited {
                Liveness::Gone
            } else if read {
                Liveness::Running((u64::from(creation.high) << 32) | u64::from(creation.low))
            } else {
                Liveness::Unknown
            }
        }
    }

    unsafe extern "system" fn on_console_ctrl(_event: u32) -> i32 {
        super::console_stop();
        // Not handled: the default handler then ends the process as before.
        0
    }

    pub(super) fn install_console_handler() {
        // SAFETY: registers a handler that stays valid for the process life.
        unsafe {
            SetConsoleCtrlHandler(Some(on_console_ctrl), 1);
        }
    }
}

/// An in-memory registry for tests.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryRegistry {
    pub(crate) keys: Mutex<BTreeMap<String, BTreeMap<String, RegValue>>>,
    pub(crate) read_only: bool,
    /// Reading a key's values fails (access denied).
    pub(crate) unreadable: bool,
}

#[cfg(test)]
impl MemoryRegistry {
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, BTreeMap<String, RegValue>>> {
        self.keys.lock().unwrap()
    }

    fn find(keys: &BTreeMap<String, BTreeMap<String, RegValue>>, key: &str) -> Option<String> {
        keys.keys()
            .find(|known| known.eq_ignore_ascii_case(key))
            .cloned()
    }

    pub(crate) fn snapshot(&self, key: &str) -> Option<BTreeMap<String, RegValue>> {
        let keys = self.map();
        Self::find(&keys, key).map(|known| keys[&known].clone())
    }

    pub(crate) fn insert(&self, key: &str, values: &[(&str, RegValue)]) {
        let mut keys = self.map();
        let entry = keys.entry(key.to_owned()).or_default();
        for (name, value) in values {
            entry.insert((*name).to_owned(), value.clone());
        }
    }
}

#[cfg(test)]
impl Registry for MemoryRegistry {
    fn values(&self, key: &str) -> Result<Option<BTreeMap<String, RegValue>>, String> {
        if self.unreadable {
            return Err(format!(
                "read the values of {key}: Access is denied. (os error 5)"
            ));
        }
        Ok(self.snapshot(key))
    }

    fn subkeys(&self, key: &str) -> Result<Vec<String>, String> {
        let prefix = format!("{}\\", key.to_ascii_lowercase());
        let mut out: Vec<String> = self
            .map()
            .keys()
            .filter_map(|known| {
                let lower = known.to_ascii_lowercase();
                let rest = lower.strip_prefix(&prefix)?;
                (!rest.contains('\\')).then(|| known[prefix.len()..].to_owned())
            })
            .collect();
        out.sort();
        Ok(out)
    }

    fn create_key(&self, key: &str) -> Result<(), String> {
        if self.read_only {
            return Err(format!("create {key}: Access is denied. (os error 5)"));
        }
        let mut keys = self.map();
        if Self::find(&keys, key).is_none() {
            keys.insert(key.to_owned(), BTreeMap::new());
        }
        Ok(())
    }

    fn set_value(&self, key: &str, name: &str, value: &RegValue) -> Result<(), String> {
        if self.read_only {
            return Err(format!("set {key}\\{name}: Access is denied. (os error 5)"));
        }
        let mut keys = self.map();
        let known = Self::find(&keys, key).ok_or_else(|| format!("{key} does not exist"))?;
        let values = keys.get_mut(&known).unwrap();
        values.retain(|existing, _| !existing.eq_ignore_ascii_case(name));
        values.insert(name.to_owned(), value.clone());
        Ok(())
    }

    fn delete_value(&self, key: &str, name: &str) -> Result<(), String> {
        let mut keys = self.map();
        if let Some(known) = Self::find(&keys, key) {
            keys.get_mut(&known)
                .unwrap()
                .retain(|existing, _| !existing.eq_ignore_ascii_case(name));
        }
        Ok(())
    }

    fn delete_key_if_empty(&self, key: &str) -> Result<bool, String> {
        let has_subkeys = !self.subkeys(key)?.is_empty();
        let mut keys = self.map();
        let Some(known) = Self::find(&keys, key) else {
            return Ok(false);
        };
        if has_subkeys || !keys[&known].is_empty() {
            return Ok(false);
        }
        keys.remove(&known);
        Ok(true)
    }

    fn writable(&self, _key: &str) -> bool {
        !self.read_only
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: Owner = Owner {
        pid: 4242,
        started: 1_000,
    };
    const DEAD: Owner = Owner {
        pid: 77,
        started: 5,
    };

    /// Only ME runs.
    fn only_me(pid: u32) -> Liveness {
        if pid == ME.pid {
            Liveness::Running(ME.started)
        } else {
            Liveness::Gone
        }
    }

    fn exe(stem: &str) -> String {
        crate::auto::layout::harness_exe_name(stem)
    }

    fn build_in(dir: &Path) -> PathBuf {
        let build = dir.join(FUZZ_BINARY_STEM);
        std::fs::write(&build, b"MZ WinAFL build").unwrap();
        build
    }

    fn new_registry() -> Arc<MemoryRegistry> {
        Arc::new(MemoryRegistry::default())
    }

    /// The command printed for removing a key by hand is one runnable line of
    /// the operator's shell: the key, which has spaces, is one quoted word.
    #[test]
    fn the_manual_removal_command_quotes_the_key_as_one_word() {
        let key = image_key("main_winafl-1-0-0.exe");
        assert_eq!(
            manual_removal_command(&key),
            "reg delete 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File \
             Execution Options\\main_winafl-1-0-0.exe' /f"
        );
    }

    #[test]
    fn owner_records_round_trip_and_reject_foreign_text() {
        let record = OwnerRecord {
            owner: ME,
            created_key: false,
            previous_global_flag: Some(0x100),
            previous_page_heap_flags: None,
        };
        let text = record.encode();
        assert_eq!(
            text,
            "bhf pid=4242 started=1000 created=0 GlobalFlag=0x100 PageHeapFlags=-"
        );
        assert_eq!(OwnerRecord::parse(&text), Some(record));
        assert_eq!(OwnerRecord::parse("gflags 1"), None);
        assert_eq!(OwnerRecord::parse("bhf pid=1 started=2"), None);
    }

    #[test]
    fn a_run_sets_page_heap_only_for_its_own_copy_and_removes_key_and_copy_after() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path());
        let registry = new_registry();
        // A user's PageHeap for the build's own name is not bhf's to touch.
        let user_key = image_key(FUZZ_BINARY_STEM);
        registry.insert(&user_key, &[(GLOBAL_FLAG, RegValue::Dword(0x0200_0000))]);
        let run = PageHeapRun::start(registry.clone(), ME, &only_me, &build).unwrap();
        let name = run
            .image
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with("main_winafl-4242-"), "{name}");
        assert!(name.ends_with(std::env::consts::EXE_SUFFIX), "{name}");
        assert_eq!(run.image.parent(), Some(dir.path()));
        assert_eq!(std::fs::read(&run.image).unwrap(), b"MZ WinAFL build");
        assert_eq!(run.key, image_key(&name));
        assert!(run.in_effect);
        let values = registry.snapshot(&run.key).unwrap();
        assert_eq!(values[GLOBAL_FLAG], RegValue::Dword(FLG_HEAP_PAGE_ALLOCS));
        assert_eq!(values[PAGE_HEAP_FLAGS], RegValue::Dword(FULL_PAGE_HEAP));
        assert_eq!(
            owner_of(&values),
            Some(OwnerRecord {
                owner: ME,
                created_key: true,
                previous_global_flag: None,
                previous_page_heap_flags: None,
            })
        );
        let (key, image) = (run.key.clone(), run.image.clone());
        drop(run);
        assert_eq!(
            registry.snapshot(&key),
            None,
            "bhf created the key, so it goes"
        );
        assert!(!image.exists(), "the run's copy is deleted");
        assert!(build.exists());
        assert_eq!(
            registry.snapshot(&user_key).unwrap()[GLOBAL_FLAG],
            RegValue::Dword(0x0200_0000)
        );
    }

    #[test]
    fn two_overlapping_runs_get_separate_keys_and_one_ending_leaves_the_other() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path());
        let registry = new_registry();
        let first = PageHeapRun::start(registry.clone(), ME, &only_me, &build).unwrap();
        let second = PageHeapRun::start(registry.clone(), ME, &only_me, &build).unwrap();
        assert_ne!(first.key, second.key);
        assert_ne!(first.image, second.image);
        let second_key = second.key.clone();
        drop(first);
        let values = registry
            .snapshot(&second_key)
            .expect("the second run's key stays");
        assert!(page_heap_in_effect(&values));
        assert!(second.image.exists());
        drop(second);
        assert_eq!(registry.snapshot(&second_key), None);
    }

    #[test]
    fn restore_touches_only_the_values_bhf_wrote_and_keeps_a_key_it_did_not_create() {
        let registry = MemoryRegistry::default();
        let key = image_key("main_winafl-1-0-0.exe");
        registry.insert(
            &key,
            &[
                ("Debugger", RegValue::Str("vsjitdebugger.exe".to_owned())),
                ("MitigationOptions", RegValue::Other(3)),
                (GLOBAL_FLAG, RegValue::Dword(0x100)),
                (OWNER_VALUE, RegValue::Str("bhf".to_owned())),
                (PAGE_HEAP_FLAGS, RegValue::Dword(3)),
            ],
        );
        let record = OwnerRecord {
            owner: ME,
            created_key: false,
            previous_global_flag: Some(0x100),
            previous_page_heap_flags: None,
        };
        restore(&registry, &key, &record).unwrap();
        let values = registry.snapshot(&key).unwrap();
        assert_eq!(
            values.into_iter().collect::<Vec<_>>(),
            [
                (
                    "Debugger".to_owned(),
                    RegValue::Str("vsjitdebugger.exe".to_owned())
                ),
                (GLOBAL_FLAG.to_owned(), RegValue::Dword(0x100)),
                ("MitigationOptions".to_owned(), RegValue::Other(3)),
            ]
        );
        // Even a key bhf created stays while a value it did not write is in it.
        let created = OwnerRecord {
            created_key: true,
            ..record
        };
        registry.insert(&key, &[(OWNER_VALUE, RegValue::Str("bhf".to_owned()))]);
        restore(&registry, &key, &created).unwrap();
        assert!(registry.snapshot(&key).unwrap().contains_key("Debugger"));
    }

    #[test]
    fn a_key_a_killed_run_left_is_reclaimed_at_the_next_start_and_its_copy_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path());
        let registry = new_registry();
        // A run killed outright: neither Drop nor the console handler ran.
        let killed =
            PageHeapRun::start(registry.clone(), DEAD, &|_| Liveness::Unknown, &build).unwrap();
        let (stale_key, stale_copy) = (killed.key.clone(), killed.image.clone());
        restore_all_active_for_test(killed.id);
        std::mem::forget(killed);
        assert!(registry.snapshot(&stale_key).is_some());
        assert!(stale_copy.exists());
        // A key a user set for a bhf-like name, without bhf's owner value.
        let foreign = image_key("main_winafl-handmade.exe");
        registry.insert(&foreign, &[(GLOBAL_FLAG, RegValue::Dword(0x0200_0000))]);
        // A live run of this process is not reclaimed either.
        let live = PageHeapRun::start(registry.clone(), ME, &only_me, &build).unwrap();
        assert_eq!(
            registry.snapshot(&stale_key),
            None,
            "dead owner's key reclaimed"
        );
        assert!(!stale_copy.exists(), "dead owner's copy deleted");
        assert!(registry.snapshot(&foreign).is_some());
        let third = PageHeapRun::start(registry.clone(), ME, &only_me, &build).unwrap();
        assert!(
            registry.snapshot(&live.key).is_some(),
            "a live owner's key stays"
        );
        assert!(live.image.exists(), "a live owner's copy stays");
        drop(third);
        drop(live);
    }

    /// Forget a run's console-handler entry, as a killed process would.
    fn restore_all_active_for_test(id: u64) {
        active().retain(|entry| entry.id != id);
    }

    #[test]
    fn the_console_handler_restores_every_active_key_once() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path());
        let registry = new_registry();
        let run = PageHeapRun::start(registry.clone(), ME, &only_me, &build).unwrap();
        let key = run.key.clone();
        // What the handler runs, limited to this test's registry so tests
        // running beside it keep theirs.
        let this = Arc::as_ptr(&registry) as *const ();
        let image = run.image.clone();
        let mut stopped = false;
        let restored = stop_active(
            |entry| Arc::as_ptr(&entry.registry) as *const () == this,
            || {
                // The targets are stopped after the keys are restored and
                // before the copies are deleted.
                assert_eq!(registry.snapshot(&key), None, "Ctrl-C removes the key");
                assert!(image.exists(), "the copy is deleted after the stop");
                stopped = true;
            },
            Duration::from_secs(1),
        );
        assert!(stopped);
        assert_eq!(restored, 1);
        assert!(!image.exists(), "Ctrl-C deletes the copy");
        assert!(!marker_path(&image).exists(), "and its marker");
        // Drop afterwards has nothing left to restore and does not recreate it.
        drop(run);
        assert_eq!(registry.snapshot(&key), None);
        assert!(
            !active().iter().any(|entry| entry.key == key),
            "the run left the handler's list"
        );
    }

    #[test]
    fn run_image_names_are_matched_exactly() {
        assert_eq!(
            run_image_pid(&exe("main_winafl-4321-0-6935c1a2")),
            Some(4321)
        );
        assert_eq!(
            run_image_pid(&exe("MAIN_WINAFL-12-3-ABCDEF").to_ascii_uppercase()),
            Some(12)
        );
        for name in [
            exe("main_winafl-handmade"),
            exe("main_winafl-1-2"),
            exe("main_winafl-1-2-3-4"),
            exe("main_winafl-x1-2-3"),
            exe("main_winafl-1-2-xyz"),
            exe("main_winafl--2-3"),
            exe("main_winafl"),
            "main_winafl-1-2-3.txt".to_owned(),
            exe("other-1-2-3"),
        ] {
            assert_eq!(run_image_pid(&name), None, "{name}");
        }
        assert_eq!(Owner::parse(&ME.encode()), Some(ME));
        assert_eq!(Owner::parse("bhf pid=1"), None);
        assert_eq!(Owner::parse("gflags pid=1 started=2"), None);
        assert_eq!(
            marker_path(Path::new("d").join("main_winafl-1-0-0.exe").as_path()),
            Path::new("d").join("main_winafl-1-0-0.exe.bhf-run")
        );
    }

    /// Only copies a marker proves a stopped bhf run made are deleted: a file
    /// without one is kept whatever its name, and so is a live run's copy,
    /// a copy whose key a live run owns, and one whose marker is not bhf's.
    #[test]
    fn copies_are_deleted_only_when_a_marker_names_a_stopped_run() {
        let dir = tempfile::tempdir().unwrap();
        let file = |name: &str, contents: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, contents).unwrap();
            path
        };
        let copy = |stem: &str, marker: Option<&str>| {
            let path = file(&exe(stem), "copy");
            if let Some(marker) = marker {
                std::fs::write(marker_path(&path), marker).unwrap();
            }
            path
        };
        let dead = DEAD.encode();
        let me = ME.encode();
        let handmade = copy("main_winafl-handmade", None);
        let unmarked = copy("main_winafl-65000-2-abc", None);
        let notes = file("main_winafl-notes.txt", "notes");
        let stale = copy("main_winafl-77-0-1", Some(&dead));
        let live = copy("main_winafl-4242-0-2", Some(&me));
        let foreign_marker = copy("main_winafl-77-2-4", Some("written by hand"));
        let key_owned = copy("main_winafl-77-3-5", Some(&dead));
        let orphan_marker = marker_path(&dir.path().join(exe("main_winafl-77-1-3")));
        std::fs::write(&orphan_marker, &dead).unwrap();
        let registry = MemoryRegistry::default();
        let live_record = OwnerRecord {
            owner: ME,
            created_key: true,
            previous_global_flag: None,
            previous_page_heap_flags: None,
        };
        registry.insert(
            &image_key(&exe("main_winafl-77-3-5")),
            &[(OWNER_VALUE, RegValue::Str(live_record.encode()))],
        );
        reclaim_stale_copies(&registry, dir.path(), &only_me);
        for kept in [
            &handmade,
            &unmarked,
            &notes,
            &live,
            &foreign_marker,
            &key_owned,
        ] {
            assert!(kept.exists(), "{} was deleted", kept.display());
        }
        assert!(marker_path(&live).exists());
        assert!(!stale.exists(), "a stopped run's marked copy is deleted");
        assert!(!marker_path(&stale).exists());
        assert!(
            !orphan_marker.exists(),
            "a marker whose copy is gone is deleted"
        );
    }

    /// A key that cannot be read may be a live run's: its copy is kept, and
    /// so is the key.
    #[test]
    fn a_registry_read_error_keeps_the_copy_and_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join(exe("main_winafl-77-0-1"));
        std::fs::write(&stale, "copy").unwrap();
        std::fs::write(marker_path(&stale), DEAD.encode()).unwrap();
        let registry = MemoryRegistry {
            unreadable: true,
            ..Default::default()
        };
        let key = image_key(&exe("main_winafl-77-0-1"));
        registry.insert(
            &key,
            &[(
                OWNER_VALUE,
                RegValue::Str(format!(
                    "bhf pid=77 started=5 created=1 {GLOBAL_FLAG}=- {PAGE_HEAP_FLAGS}=-"
                )),
            )],
        );
        reclaim(&registry, &only_me, dir.path());
        assert!(stale.exists(), "the copy is kept");
        assert!(marker_path(&stale).exists());
        assert!(registry.snapshot(&key).is_some(), "the key is kept");
    }

    /// A run killed between creating its key and tagging it (or between
    /// untagging and deleting it) leaves an empty key with its run-unique name:
    /// it is deleted once that process is gone. Other empty keys stay.
    #[test]
    fn an_empty_key_a_killed_run_left_is_deleted_once_its_process_is_gone() {
        let registry = MemoryRegistry::default();
        let gone = image_key(&exe("main_winafl-77-0-ab"));
        let running = image_key(&exe("main_winafl-4242-0-ab"));
        let handmade = image_key(&exe("main_winafl-handmade"));
        let with_value = image_key(&exe("main_winafl-77-1-ab"));
        for key in [&gone, &running, &handmade] {
            registry.create_key(key).unwrap();
        }
        registry.insert(&with_value, &[("Debugger", RegValue::Str("x".to_owned()))]);
        let reclaimed = reclaim_dead_owners(&registry, &only_me);
        assert_eq!(reclaimed, [exe("main_winafl-77-0-ab")]);
        assert_eq!(registry.snapshot(&gone), None);
        for kept in [&running, &handmade, &with_value] {
            assert!(registry.snapshot(kept).is_some(), "{kept}");
        }
    }

    /// A key or file already under a run's name is refused, never adopted.
    #[test]
    fn a_key_or_file_already_under_the_run_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path());
        let registry = new_registry();
        let name = exe("main_winafl-4242-9-1");
        let key = image_key(&name);
        registry.insert(&key, &[(GLOBAL_FLAG, RegValue::Dword(0x100))]);
        let error = PageHeapRun::start_as(registry.clone(), ME, &only_me, &build, name.clone())
            .err()
            .expect("an existing key is refused");
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(
            registry
                .snapshot(&key)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            [(GLOBAL_FLAG.to_owned(), RegValue::Dword(0x100))],
            "the key is left as it was"
        );
        let other = exe("main_winafl-4242-9-2");
        std::fs::write(dir.path().join(&other), b"someone's").unwrap();
        let error = PageHeapRun::start_as(registry.clone(), ME, &only_me, &build, other.clone())
            .err()
            .expect("an existing file is refused");
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(
            std::fs::read(dir.path().join(&other)).unwrap(),
            b"someone's"
        );
        assert_eq!(registry.snapshot(&image_key(&other)), None);
    }

    /// A registry whose first value deletion waits until it is let go, to
    /// stop a restore in the middle.
    struct GatedRegistry {
        inner: MemoryRegistry,
        entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl Registry for GatedRegistry {
        fn values(&self, key: &str) -> Result<Option<BTreeMap<String, RegValue>>, String> {
            self.inner.values(key)
        }
        fn subkeys(&self, key: &str) -> Result<Vec<String>, String> {
            self.inner.subkeys(key)
        }
        fn create_key(&self, key: &str) -> Result<(), String> {
            self.inner.create_key(key)
        }
        fn set_value(&self, key: &str, name: &str, value: &RegValue) -> Result<(), String> {
            self.inner.set_value(key, name, value)
        }
        fn delete_value(&self, key: &str, name: &str) -> Result<(), String> {
            if let Some(entered) = self.entered.lock().unwrap().take() {
                entered.send(()).unwrap();
                let release = self.release.lock().unwrap().take().unwrap();
                release.recv().unwrap();
            }
            self.inner.delete_value(key, name)
        }
        fn delete_key_if_empty(&self, key: &str) -> Result<bool, String> {
            self.inner.delete_key_if_empty(key)
        }
        fn writable(&self, key: &str) -> bool {
            self.inner.writable(key)
        }
    }

    /// A console control event while a run's `Drop` is restoring its key
    /// waits for that restore, rather than finding nothing to do while the
    /// process is about to end with the restore half done.
    #[test]
    fn a_console_stop_during_a_restore_waits_for_it() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path());
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let registry = Arc::new(GatedRegistry {
            inner: MemoryRegistry::default(),
            entered: Mutex::new(None),
            release: Mutex::new(Some(release_rx)),
        });
        let run = PageHeapRun::start(registry.clone(), ME, &only_me, &build).unwrap();
        let key = run.key.clone();
        *registry.entered.lock().unwrap() = Some(entered_tx);
        let dropper = std::thread::spawn(move || drop(run));
        entered_rx.recv().unwrap();
        // Drop is in the middle of the restore.
        let released = Arc::new(AtomicBool::new(false));
        let this = Arc::as_ptr(&registry) as *const () as usize;
        let handler = {
            let released = released.clone();
            std::thread::spawn(move || {
                stop_active(
                    |entry| Arc::as_ptr(&entry.registry) as *const () as usize == this,
                    || {},
                    Duration::ZERO,
                );
                released.load(Ordering::SeqCst)
            })
        };
        std::thread::sleep(Duration::from_millis(200));
        released.store(true, Ordering::SeqCst);
        release_tx.send(()).unwrap();
        dropper.join().unwrap();
        assert!(
            handler.join().unwrap(),
            "the handler returned before the restore it interrupted finished"
        );
        assert_eq!(registry.inner.snapshot(&key), None);
    }

    #[test]
    fn an_owner_whose_start_time_is_unknown_is_an_error() {
        assert_eq!(
            owner_from(7, Liveness::Running(9)),
            Ok(Owner { pid: 7, started: 9 })
        );
        for liveness in [Liveness::Unknown, Liveness::Gone] {
            let error = owner_from(7, liveness).unwrap_err();
            assert!(error.contains("start time"), "{error}");
        }
        assert!(current_owner().is_ok());
    }

    #[test]
    fn a_failed_write_puts_back_what_was_set_and_names_elevation() {
        let dir = tempfile::tempdir().unwrap();
        let build = build_in(dir.path());
        let registry = Arc::new(MemoryRegistry {
            read_only: true,
            ..Default::default()
        });
        let error = PageHeapRun::start(registry.clone(), ME, &only_me, &build)
            .err()
            .expect("a read-only registry refuses PageHeap");
        assert!(error.contains("elevated (administrator) shell"), "{error}");
        assert!(error.contains(IFEO), "{error}");
        assert!(registry.keys.lock().unwrap().is_empty());
        let copies: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        assert_eq!(copies, [std::ffi::OsString::from(FUZZ_BINARY_STEM)]);
    }

    #[test]
    fn page_heap_in_effect_reads_global_flag() {
        let registry = MemoryRegistry::default();
        assert!(!configured_for(&registry, "main_winafl"));
        registry.insert(
            &image_key("MAIN_WINAFL"),
            &[(GLOBAL_FLAG, RegValue::Dword(0x0200_0100))],
        );
        assert!(configured_for(&registry, "main_winafl"));
        registry.insert(
            &image_key("main_winafl.exe"),
            &[(GLOBAL_FLAG, RegValue::Dword(0x100))],
        );
        assert!(!configured_for(&registry, "main_winafl.exe"));
    }

    /// The Windows registry calls themselves, under a scratch key of the
    /// current user (no elevation needed).
    #[cfg(windows)]
    #[test]
    fn the_windows_registry_reads_writes_lists_and_deletes() {
        let registry = win::WindowsRegistry;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let parent = format!(
            "HKCU\\Software\\bhf-registry-test-{}-{nonce}",
            std::process::id()
        );
        let key = format!("{parent}\\main_winafl-1-0-0.exe");
        assert_eq!(registry.values(&key).unwrap(), None);
        assert!(registry.subkeys(&parent).unwrap().is_empty());
        registry.create_key(&key).unwrap();
        registry
            .set_value(&key, GLOBAL_FLAG, &RegValue::Dword(FLG_HEAP_PAGE_ALLOCS))
            .unwrap();
        let record = OwnerRecord {
            owner: current_owner().unwrap(),
            created_key: true,
            previous_global_flag: None,
            previous_page_heap_flags: None,
        };
        registry
            .set_value(&key, OWNER_VALUE, &RegValue::Str(record.encode()))
            .unwrap();
        let values = registry.values(&key).unwrap().unwrap();
        assert_eq!(values[GLOBAL_FLAG], RegValue::Dword(FLG_HEAP_PAGE_ALLOCS));
        assert_eq!(owner_of(&values), Some(record.clone()));
        assert!(page_heap_in_effect(&values));
        assert_eq!(
            registry.subkeys(&parent).unwrap(),
            ["main_winafl-1-0-0.exe".to_owned()]
        );
        assert!(
            !registry.delete_key_if_empty(&key).unwrap(),
            "it has values"
        );
        restore(&registry, &key, &record).unwrap();
        assert_eq!(
            registry.values(&key).unwrap(),
            None,
            "restored: the key is gone"
        );
        registry.delete_value(&key, GLOBAL_FLAG).unwrap();
        assert!(registry.delete_key_if_empty(&parent).unwrap());
        assert!(registry.writable("HKCU\\Software"));
    }

    #[cfg(windows)]
    #[test]
    fn a_finished_process_is_not_a_live_owner() {
        let me = current_owner().unwrap();
        assert_ne!(me.started, 0);
        assert!(owner_alive(&me));
        assert!(!owner_alive(&Owner {
            started: me.started + 1,
            ..me
        }));
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "exit 0"])
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap();
        drop(child);
        assert!(!owner_alive(&Owner { pid, started: 1 }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_current_process_is_its_own_live_owner_and_a_reused_pid_is_not() {
        let me = current_owner().unwrap();
        assert!(owner_alive(&me));
        assert!(!owner_alive(&Owner {
            started: me.started + 1,
            ..me
        }));
    }
}
