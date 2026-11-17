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


ZLIB_SOURCES = (
    "adler32.c",
    "compress.c",
    "crc32.c",
    "deflate.c",
    "infback.c",
    "inffast.c",
    "inflate.c",
    "inftrees.c",
    "trees.c",
    "uncompr.c",
    "zutil.c",
)
ZLIB_PINS = {
    "adler32.c": "9cd1443a24ff2a3053961695bd432035c58347386a420d3388232376ebabe211",
    "compress.c": "41f1c7ad886012571cd481a2b1b6a83812e5125e90d995e298fde34d6c015614",
    "crc32.c": "da37f3483e77c20f64c28cf55d62d7bed9d62af33eb401be906835d84539b9c9",
    "deflate.c": "8244ed0d9b791d6da527eeca10cc920418ae6d440e0cdb4f9e1974188539496e",
    "infback.c": "9f05ca3bfe4e27e9b08418fd02eeb48d63daefd7d2d90c80f7dca5e3b5c305d6",
    "inffast.c": "f96787a11bb7131ffd2221fb40db27f6a5a1dfb12f59c0bc388807010749c34a",
    "inflate.c": "90221ea7d762e7044057f6ad5013e969086c6ba3d3051716b7aa786d7a6362ec",
    "inftrees.c": "64fc6aeea744510253a22f8b0611fcefa970458224a41a1649f5e0db340af8fe",
    "trees.c": "a16217d5ea6d8342ff08afe5207b1dab620f05610e121dda55b4f9aae9de4f68",
    "uncompr.c": "953f5381650838d507b01499790bd64524433ea6ea29ea9325bf542af10cfe7d",
    "zutil.c": "04303a4d607958905f0c036aeca43d14218d01752e6c444fdbeb94983912ec38",
    "zlib.h": "6f5162028729e94b221eb6586debe9548a007fd951cfea7a77f67e0323555545",
    "zconf.h": "cb7c2c84211473b4699223edd363d3207b43b9578e739b5bf638f42204ea6e0f",
}


def zlib(checkout: Path, build: Path) -> Prepared:
    """zlib's core translation units (no gz* file I/O); the checked-in
    zconf.h is the one configure would leave for this host."""
    verify(checkout, ZLIB_PINS, "zlib")
    return Prepared(
        sources=(ADAPTERS / "zlib.c", *(checkout / name for name in ZLIB_SOURCES)),
        include_dirs=(checkout,),
    )


LIBYAML_SOURCES = (
    "src/api.c",
    "src/dumper.c",
    "src/emitter.c",
    "src/loader.c",
    "src/parser.c",
    "src/reader.c",
    "src/scanner.c",
    "src/writer.c",
)
LIBYAML_PINS = {
    "src/api.c": "71f9263a2c77237762c8fa5e7c3d2bdd35723ecf1e2898222c7a603a5bf3f2db",
    "src/dumper.c": "56fe41a1db73e1b9342b9381856e1fade8ea339a0b723bef90e7e1e8638bc441",
    "src/emitter.c": "fbec4f702153929ad1421636ab0f5ecded140f0f37014d5ab3c65dfecd7e0743",
    "src/loader.c": "68424f0b29e16434e7f2c0838b26dd4b68e04b567ad40f4f4c1bc61cd8e93479",
    "src/parser.c": "3df3106f1b045da438a3bfba316efcee246573565122ea68095a4e8ef7d2ea23",
    "src/reader.c": "c428a44b177391557bdf49177c1dc0216edf2a2bbe0e24ca2ef2725ef7f01e9d",
    "src/scanner.c": "a853092204abb33d7f79b3da7a19f8df14c156c5cca738f1bb54c19d1f52f2e2",
    "src/writer.c": "44a75c870a0b7039e37b457850b31748a69ce3bf1bf39950e7b855acef472de2",
    "src/yaml_private.h": "8dffe95c784665eba4ee88169456ebd41137a6d80ad13d536df6ad10d7a4d459",
    "include/yaml.h": "5dfca217235c26810a0ab2f52c328fd3b95fd2ee244fab12f1b0f72d63da2780",
}


LIBYAML_CONFIG_H = """/* The config.h libyaml 0.2.5's configure writes, as far as its sources read it. */
#define YAML_VERSION_MAJOR 0
#define YAML_VERSION_MINOR 2
#define YAML_VERSION_PATCH 5
#define YAML_VERSION_STRING "0.2.5"
"""


def libyaml(checkout: Path, build: Path) -> Prepared:
    """libyaml's src/*.c, with the config.h its configure would write for the
    version configure.ac defines (0.2.5), so no autogen step runs. A header,
    not -D flags: a quoted string define does not survive a make recipe."""
    verify(checkout, LIBYAML_PINS, "libyaml")
    config = build / "config"
    config.mkdir(parents=True, exist_ok=True)
    (config / "config.h").write_text(LIBYAML_CONFIG_H)
    return Prepared(
        sources=(ADAPTERS / "libyaml.c", *(checkout / name for name in LIBYAML_SOURCES)),
        include_dirs=(checkout / "include", checkout / "src", config),
        extra_cflags=("-DHAVE_CONFIG_H=1", "-DYAML_DECLARE_STATIC"),
    )


RECIPES = {"cjson": cjson, "sqlite": sqlite, "zlib": zlib, "libyaml": libyaml}


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
