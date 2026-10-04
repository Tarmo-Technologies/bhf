# SPDX-License-Identifier: Apache-2.0
"""Pluggable target set for the engine-quality trade study.

``trade_study.py`` used to hard-code its target set to the four toy
``engine_parity`` gates. This module makes the target set *config-driven* so the
same reviewed harness/oracle/censoring/aggregate machinery can be pointed at
maintained real-code benchmarks instead.

A "target" here is whatever compiles, together with a harness adapter that
defines ``int target_one_input(const unsigned char *, size_t)``, into a fuzz
binary. That is exactly the shape of the toy fixtures (a fixture ``.c`` plus a
generated wrapper) and of a real library (an adapter ``.c`` that includes the
library header and calls its public API, compiled with the library's own
translation units and include paths).

Two providers are exposed:

* :func:`builtin_fixture_targets` — the four controlled gates, preserving the
  study's historical default so running ``trade_study.py`` with no manifest
  behaves exactly as before.
* :func:`load_manifest` — a JSON or TOML manifest of real-code targets, each
  pinned to an upstream revision, with explicit include paths, compile flags,
  seed corpus, budgets, sanitizer policy, and a documented bhf-harness mode.

The schema is deliberately stdlib-only (dataclasses + strict validation that
raises descriptive errors) so the offline powered study runs on a bare
``python3`` with no third-party dependency. See
``experiment1-real-code.example.json`` for a documented example and
``METHODOLOGY.md`` for the field reference.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Status of whether the simple single-invocation compile model can run a target
# as-is. Anything that is not RUNNABLE is still emitted as a visible row so a
# maintainer sees exactly which real-code targets are pending, not a silent drop.
RUNNABLE = "runnable"
REQUIRES_BUILD_RECIPE = "requires_build_recipe"
MANUAL = "manual"
_STATUSES = frozenset({RUNNABLE, REQUIRES_BUILD_RECIPE, MANUAL})

# How the bhf lane is harnessed. "generated" lets bhf auto-generate its harness
# (what the toy study measures — this conflates engine quality with harness
# generation and is only honest on a self-contained single file). "provided"
# holds the harness fixed across every engine, which is the correct mode for an
# engine-quality comparison on real code; wiring the exact bhf invocation for a
# provided harness is a documented maintainer step (see METHODOLOGY.md).
BHF_GENERATED = "generated"
BHF_PROVIDED = "provided"
_BHF_MODES = frozenset({BHF_GENERATED, BHF_PROVIDED})

# Sanitizer/oracle policy strings are pinned per target so the policy is part of
# the recorded variant rather than an implicit constant.
_SANITIZER_POLICIES = frozenset({"asan_ubsan", "asan"})

KIND_BUILTIN = "builtin_fixture"
KIND_SELF_CONTAINED = "self_contained"
_KINDS = frozenset({KIND_BUILTIN, KIND_SELF_CONTAINED})


class ManifestError(ValueError):
    """Raised with a descriptive message when a manifest is malformed."""


@dataclass(frozen=True)
class Upstream:
    """Provenance pin for a real-code target."""

    url: str
    commit: str

    def as_dict(self) -> dict:
        return {"url": self.url, "commit": self.commit}


@dataclass(frozen=True)
class TargetSpec:
    """One pinned engine-quality target.

    ``sources`` are compiled together with the engine's harness adapter; one of
    them must define ``target_one_input`` unless ``target_callback`` names a
    symbol to wrap. ``primary_source`` is the translation unit handed to
    ``bhf generate-harness`` in the ``generated`` bhf mode.
    """

    name: str
    kind: str
    description: str = ""
    # Builtin fixtures: the fixture source is produced by run.fixture_source and
    # no on-disk sources are listed. Self-contained: concrete source paths.
    fixture_case: str | None = None
    sources: tuple[Path, ...] = ()
    include_dirs: tuple[Path, ...] = ()
    extra_cflags: tuple[str, ...] = ()
    target_callback: str | None = None
    upstream: Upstream | None = None
    seed_dir: Path | None = None
    budget_s: int | None = None
    max_len: int | None = None
    sanitizer_policy: str = "asan_ubsan"
    bhf_harness_mode: str = BHF_GENERATED
    expected_oracle: str = "any ASan/UBSan diagnostic"
    status: str = RUNNABLE
    notes: str = ""
    # Resolved at load time for self-contained targets; empty for fixtures.
    source_sha256: dict[str, str] = field(default_factory=dict)

    @property
    def primary_source(self) -> Path | None:
        return self.sources[0] if self.sources else None

    def provenance(self) -> dict:
        """JSON-serializable pin of everything that defines this variant."""
        return {
            "name": self.name,
            "kind": self.kind,
            "fixture_case": self.fixture_case,
            "sources": [str(p) for p in self.sources],
            "include_dirs": [str(p) for p in self.include_dirs],
            "extra_cflags": list(self.extra_cflags),
            "target_callback": self.target_callback,
            "upstream": self.upstream.as_dict() if self.upstream else None,
            "seed_dir": str(self.seed_dir) if self.seed_dir else None,
            "budget_s": self.budget_s,
            "max_len": self.max_len,
            "sanitizer_policy": self.sanitizer_policy,
            "bhf_harness_mode": self.bhf_harness_mode,
            "expected_oracle": self.expected_oracle,
            "status": self.status,
            "source_sha256": self.source_sha256,
            "notes": self.notes,
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def builtin_fixture_targets(cases: dict[str, str]) -> list[TargetSpec]:
    """The historical default: one TargetSpec per controlled fixture gate.

    ``cases`` is ``run.CASES`` (case name -> callback symbol). These keep
    ``status == RUNNABLE`` and carry no upstream pin because they are checked in
    at this repository's own revision.
    """
    specs: list[TargetSpec] = []
    for case, callback in cases.items():
        specs.append(
            TargetSpec(
                name=case,
                kind=KIND_BUILTIN,
                description=f"controlled coverage-gated fixture ({callback})",
                fixture_case=case,
                target_callback=callback,
                status=RUNNABLE,
                expected_oracle="stack-buffer-overflow (ASan)",
            )
        )
    return specs


def _as_path_list(value, base: Path, field_name: str, target: str) -> tuple[Path, ...]:
    if not isinstance(value, list):
        raise ManifestError(
            f"target {target!r}: {field_name} must be a list, got {type(value).__name__}"
        )
    out: list[Path] = []
    for item in value:
        if not isinstance(item, str):
            raise ManifestError(
                f"target {target!r}: {field_name} entries must be strings, got {item!r}"
            )
        candidate = Path(item)
        out.append(candidate if candidate.is_absolute() else (base / candidate))
    return tuple(out)


def _validate_choice(
    value: str, allowed: frozenset[str], field_name: str, target: str
) -> str:
    if value not in allowed:
        raise ManifestError(
            f"target {target!r}: {field_name} must be one of "
            f"{sorted(allowed)}, got {value!r}"
        )
    return value


def _parse_target(entry: dict, base: Path, *, resolve_sources: bool) -> TargetSpec:
    if not isinstance(entry, dict):
        raise ManifestError(f"each target must be a table/object, got {entry!r}")
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        raise ManifestError(f"target missing a non-empty string 'name': {entry!r}")
    kind = _validate_choice(
        entry.get("kind", KIND_SELF_CONTAINED), _KINDS, "kind", name
    )

    sources = _as_path_list(entry.get("sources", []), base, "sources", name)
    include_dirs = _as_path_list(
        entry.get("include_dirs", []), base, "include_dirs", name
    )
    status = _validate_choice(entry.get("status", RUNNABLE), _STATUSES, "status", name)

    if kind == KIND_SELF_CONTAINED and status == RUNNABLE and not sources:
        raise ManifestError(
            f"target {name!r}: a runnable self_contained target needs at least one "
            f"source; mark it status={REQUIRES_BUILD_RECIPE!r} if sources are not "
            f"yet materialized"
        )

    extra_cflags = entry.get("extra_cflags", [])
    if not isinstance(extra_cflags, list) or not all(
        isinstance(x, str) for x in extra_cflags
    ):
        raise ManifestError(f"target {name!r}: extra_cflags must be a list of strings")

    upstream_raw = entry.get("upstream")
    upstream: Upstream | None = None
    if upstream_raw is not None:
        if (
            not isinstance(upstream_raw, dict)
            or "url" not in upstream_raw
            or "commit" not in upstream_raw
        ):
            raise ManifestError(
                f"target {name!r}: upstream must be a table with 'url' and 'commit'"
            )
        upstream = Upstream(
            url=str(upstream_raw["url"]), commit=str(upstream_raw["commit"])
        )
    elif kind == KIND_SELF_CONTAINED:
        raise ManifestError(
            f"target {name!r}: a real-code target must pin an upstream {{url, commit}}"
        )

    seed_dir_raw = entry.get("seed_dir")
    seed_dir = None
    if seed_dir_raw is not None:
        p = Path(seed_dir_raw)
        seed_dir = p if p.is_absolute() else base / p

    for int_field in ("budget_s", "max_len"):
        if int_field in entry and not isinstance(entry[int_field], int):
            raise ManifestError(f"target {name!r}: {int_field} must be an integer")

    source_sha: dict[str, str] = {}
    if resolve_sources and status == RUNNABLE:
        for src in sources:
            if not src.is_file():
                raise ManifestError(
                    f"target {name!r}: source {src} does not exist; run the manifest "
                    f"'fetch' step first or mark the target status="
                    f"{REQUIRES_BUILD_RECIPE!r}"
                )
            source_sha[src.name] = _sha256(src)

    return TargetSpec(
        name=name,
        kind=kind,
        description=str(entry.get("description", "")),
        sources=sources,
        include_dirs=include_dirs,
        extra_cflags=tuple(extra_cflags),
        target_callback=entry.get("target_callback"),
        upstream=upstream,
        seed_dir=seed_dir,
        budget_s=entry.get("budget_s"),
        max_len=entry.get("max_len"),
        sanitizer_policy=_validate_choice(
            entry.get("sanitizer_policy", "asan_ubsan"),
            _SANITIZER_POLICIES,
            "sanitizer_policy",
            name,
        ),
        bhf_harness_mode=_validate_choice(
            entry.get("bhf_harness_mode", BHF_GENERATED),
            _BHF_MODES,
            "bhf_harness_mode",
            name,
        ),
        expected_oracle=str(entry.get("expected_oracle", "any ASan/UBSan diagnostic")),
        status=status,
        notes=str(entry.get("notes", "")),
        source_sha256=source_sha,
    )


def _load_document(path: Path) -> dict:
    text = path.read_text()
    if path.suffix == ".toml":
        import tomllib

        return tomllib.loads(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise ManifestError(f"{path}: invalid JSON: {error}") from error


def load_manifest(path: Path, *, resolve_sources: bool = True) -> list[TargetSpec]:
    """Parse a real-code target manifest (``.json`` or ``.toml``).

    Paths inside the manifest are resolved relative to the manifest's own
    directory unless absolute. With ``resolve_sources`` (the default) each
    runnable target's source files must exist and are hashed into the pin; pass
    ``resolve_sources=False`` to validate the schema/plan without the sources on
    disk (used by ``trade_study.py --dry-run``).
    """
    if not path.is_file():
        raise ManifestError(f"manifest not found: {path}")
    document = _load_document(path)
    if not isinstance(document, dict) or "targets" not in document:
        raise ManifestError(f"{path}: manifest must have a top-level 'targets' list")
    targets = document["targets"]
    if not isinstance(targets, list) or not targets:
        raise ManifestError(f"{path}: 'targets' must be a non-empty list")
    base = path.resolve().parent
    specs = [
        _parse_target(entry, base, resolve_sources=resolve_sources) for entry in targets
    ]
    names = [s.name for s in specs]
    if len(set(names)) != len(names):
        dupes = sorted({n for n in names if names.count(n) > 1})
        raise ManifestError(f"{path}: duplicate target names: {dupes}")
    return specs


def fetch_sources(
    spec: TargetSpec, sources_root: Path, *, log_dir: Path | None = None
) -> Path:
    """Clone the target's upstream at its pinned commit into ``sources_root``.

    This is the documented offline fetch step: it makes a real-code manifest
    reproducible without vendoring upstream code into this repository. Returns
    the checkout directory. Raises on any clone/checkout/revision mismatch
    (never silently continues on a wrong revision).
    """
    if spec.upstream is None:
        raise ManifestError(
            f"target {spec.name!r}: cannot fetch without an upstream pin"
        )
    checkout = sources_root / spec.name
    checkout.parent.mkdir(parents=True, exist_ok=True)
    log = (log_dir / f"{spec.name}-fetch.log") if log_dir else None

    def _run(argv: list[str], cwd: Path | None = None) -> None:
        if log is not None:
            with log.open("ab") as handle:
                rc = subprocess.run(
                    argv, cwd=cwd, stdout=handle, stderr=subprocess.STDOUT
                ).returncode
        else:
            rc = subprocess.run(argv, cwd=cwd).returncode
        if rc != 0:
            raise ManifestError(
                f"target {spec.name!r}: command failed ({rc}): {' '.join(argv)}"
            )

    if not (checkout / ".git").is_dir():
        _run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                spec.upstream.url,
                str(checkout),
            ]
        )
    _run(["git", "fetch", "--depth", "1", "origin", spec.upstream.commit], cwd=checkout)
    _run(["git", "checkout", "--detach", spec.upstream.commit], cwd=checkout)
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=checkout, text=True
    ).strip()
    if actual != spec.upstream.commit:
        raise ManifestError(
            f"target {spec.name!r}: revision mismatch after checkout: "
            f"{actual} != pinned {spec.upstream.commit}"
        )
    return checkout
