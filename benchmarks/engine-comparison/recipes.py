# SPDX-License-Identifier: Apache-2.0
"""Build recipes for the real-code trade-study targets (#255, #370, #371).

The study compiles each engine's binary with one compiler invocation, so a
real-code target needs its sources reduced to a list of translation units,
include dirs and flags. A recipe does that for one target's checkout (cloned
at its manifest pin by ``trade_study.py --fetch``): it checks the pinned
SHA-256 of every input file it takes from the checkout, generates whatever
the project's own build would (SQLite's amalgamation), checks the generated
files too, and returns what to compile, with the target's adapter
(``adapters/<name>.c``, which defines ``target_one_input``) first.

A checksum mismatch is an error, never a silent rebuild: a moved pin or a
changed generator means the variant is not the one the manifest names.
"""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

ADAPTERS = Path(__file__).resolve().parent / "adapters"


class RecipeError(ValueError):
    """Raised when a checkout cannot be turned into the pinned build."""


@dataclass(frozen=True)
class Prepared:
    """What a recipe compiles: the adapter first, then the project's sources."""

    sources: tuple[Path, ...]
    include_dirs: tuple[Path, ...]
    extra_cflags: tuple[str, ...] = ()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(root: Path, pins: dict[str, str], what: str) -> None:
    """Check each ``root``-relative file against its pinned SHA-256."""
    for relative, expected in pins.items():
        path = root / relative
        if not path.is_file():
            raise RecipeError(f"{what}: {relative} is missing under {root}")
        actual = _sha256(path)
        if actual != expected:
            raise RecipeError(
                f"{what}: {relative} has SHA-256 {actual}, the recipe pins {expected}"
            )


def _run(argv: list[str], cwd: Path, log: Path) -> None:
    with log.open("ab") as handle:
        rc = subprocess.run(argv, cwd=cwd, stdout=handle, stderr=subprocess.STDOUT).returncode
    if rc != 0:
        raise RecipeError(f"{' '.join(argv)} failed ({rc}); see {log}")


CJSON_PINS = {
    "cJSON.c": "607e756460fa0de37d20a7a9181f2de29c97bfb7ce5a0e6c2f548243836cd852",
    "cJSON.h": "25b0145150d500498e4d209cec69c18c42cf818bffcc54690be3b895a2a16dee",
}


def cjson(checkout: Path, build: Path) -> Prepared:
    """cJSON is one translation unit."""
    verify(checkout, CJSON_PINS, "cjson")
    return Prepared(
        sources=(ADAPTERS / "cjson.c", checkout / "cJSON.c"),
        include_dirs=(checkout,),
    )


# The amalgamation SQLite 3.54.0's `make sqlite3.c` generates at the pin; the
# generator (tool/mksqlite3c.tcl under the bundled jimsh) is deterministic.
SQLITE_AMALGAMATION_PINS = {
    "sqlite3.c": "4f0ea8e4e7e19366a20f75e69ff33d2b23e079618d3672a878270a4fd260acce",
    "sqlite3.h": "73f886b27c6a57ddebe3d6d094e75685b2772386a83f74e15758b44b630c7ca0",
}
SQLITE_PINS = {
    "VERSION": "7f61124735d044fa39bd13799617c4f8682650997cd6dedc84bba569b5413edc",
}


def sqlite(checkout: Path, build: Path) -> Prepared:
    """SQLite's amalgamation, generated out of tree by its own build."""
    verify(checkout, SQLITE_PINS, "sqlite")
    amalgamation = build / "sqlite-amalgamation"
    if not (amalgamation / "sqlite3.c").is_file():
        amalgamation.mkdir(parents=True, exist_ok=True)
        log = amalgamation / "recipe.log"
        _run([str(checkout / "configure"), "--disable-tcl"], amalgamation, log)
        _run(["make", "sqlite3.c"], amalgamation, log)
    verify(amalgamation, SQLITE_AMALGAMATION_PINS, "sqlite amalgamation")
    return Prepared(
        sources=(ADAPTERS / "sqlite.c", amalgamation / "sqlite3.c"),
        include_dirs=(amalgamation,),
        extra_cflags=(
            "-DSQLITE_THREADSAFE=0",
            "-DSQLITE_OMIT_LOAD_EXTENSION",
            "-DSQLITE_DEFAULT_MEMSTATUS=0",
        ),
    )


RECIPES = {"cjson": cjson, "sqlite": sqlite}


def prepare(name: str, checkout: Path, build: Path) -> Prepared:
    """Run the recipe ``name`` over a checkout, building under ``build``."""
    recipe = RECIPES.get(name)
    if recipe is None:
        raise RecipeError(f"no build recipe named {name!r}; known: {sorted(RECIPES)}")
    if not checkout.is_dir():
        raise RecipeError(
            f"{name}: no checkout at {checkout}; run trade_study.py --fetch first"
        )
    build.mkdir(parents=True, exist_ok=True)
    return recipe(checkout, build)
