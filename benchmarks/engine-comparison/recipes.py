# SPDX-License-Identifier: Apache-2.0
"""Build recipes for the real-code trade-study targets (#255, #370, #371).

The study compiles each engine's binary with one compiler invocation, so a
real-code target needs its sources reduced to a list of translation units,
include dirs and flags. A recipe does that for one target's checkout (cloned
at its manifest pin by ``trade_study.py --fetch``): it checks the pinned
SHA-256 of every input file it takes from the checkout, generates whatever
the project's own build would (SQLite's amalgamation), checks the generated
files too, and returns what to compile, with the target's adapter
(``adapters/<name>_adapter.c``, which defines ``target_one_input``) first.

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
    # Libraries to link, after the sources.
    link_flags: tuple[str, ...] = ()


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
        sources=(ADAPTERS / "cjson_adapter.c", checkout / "cJSON.c"),
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
        sources=(ADAPTERS / "sqlite_adapter.c", amalgamation / "sqlite3.c"),
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
        sources=(ADAPTERS / "zlib_adapter.c", *(checkout / name for name in ZLIB_SOURCES)),
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
        sources=(ADAPTERS / "libyaml_adapter.c", *(checkout / name for name in LIBYAML_SOURCES)),
        include_dirs=(checkout / "include", checkout / "src", config),
        extra_cflags=("-DHAVE_CONFIG_H=1", "-DYAML_DECLARE_STATIC"),
    )


LIBPNG_SOURCES = (
    "png.c",
    "pngerror.c",
    "pngget.c",
    "pngmem.c",
    "pngpread.c",
    "pngread.c",
    "pngrio.c",
    "pngrtran.c",
    "pngrutil.c",
    "pngset.c",
    "pngsimd.c",
    "pngtrans.c",
    "pngwio.c",
    "pngwrite.c",
    "pngwtran.c",
    "pngwutil.c",
)
LIBPNG_PINS = {
    "pnglibconf.h.prebuilt": "ff522fa35ee246d3327ff368d9c016b3a361b7299c8e3186930126ff9730f5c2",
    "png.h": "6d3355e4562c85ced56c3a27e9b79d95a18e7b02a70a22387767aafbccf9d05f",
    "pngconf.h": "bf04cb1fbf458487c4cef73d6c514627ea3a95db5be20771a616ec7f8b68830e",
    "png.c": "77ef0244d56389a223e336b43b84ebd2568c33f294fe8738add4ffc5f28edf41",
    "pngerror.c": "393be4b28db741a4b5408f3f02cbe982d8e8133acba6007dc2513c0189ada6f3",
    "pngget.c": "2896f3fb8b0e33d8dbe77ed093ce42cc672389a6dc4509856ad07410005343cb",
    "pngmem.c": "a09e23fe10e753bc46b5d2c23e67a76e6d84a200a43ecead1b095639c039dfb5",
    "pngpread.c": "2e47c48165371022350b174eab66c25e51215b15322add0c19b4f64a4cb7cc15",
    "pngread.c": "3b97503efea0e89f5b6e733ea6dce060cabcb57ac9e13b5b64b809d67663ca66",
    "pngrio.c": "cb6b59cd79816fada58c518f8d77128bcff8127caa6812e7a47701d7ce5d555b",
    "pngrtran.c": "c480280203275b5fb2f2fd5df56409eaa886a6011cf6208320ec75bd8ee66a2d",
    "pngrutil.c": "4a2d42b1f446d97af41d13e7cee044ff3e1316fdf3b6884927bf66956ab56fa6",
    "pngset.c": "87f9a4f1d56ae04351274bfc0e4553012f5e691557740113869e7e62d28394cb",
    "pngsimd.c": "64e4a2d497ca4320b5a9e1359f32b7bbe89b67c0537b6cb0fad784ecf8d6e3ad",
    "pngtrans.c": "0f003db81c4cc25d7780c5b41189c80b1fe7ad5241d5c6ce6675a4d15b78f322",
    "pngwio.c": "2a5f157132a1de174da55f90367cbc1f202d8c6c4dd9443efad9ef4ce29facb2",
    "pngwrite.c": "31a9193892fc9e6ad12a5bae580d4f4652ec2e936a8bb3d87ff5cdc1ad938b71",
    "pngwtran.c": "ec7e76b97db1c27a84d919c3f3aa3461e4ef821706438c139c3b22d5d8868dff",
    "pngwutil.c": "0b9d36f3f39199d842f973f90e47e4c3bd47a3563cde68a3bf659c350df5b6b1",
}


def libpng(checkout: Path, build: Path) -> Prepared:
    """libpng's library translation units with the pnglibconf.h it ships
    prebuilt, linked with the zlib recipe's sources from the zlib checkout
    beside it (the manifest fetches both)."""
    verify(checkout, LIBPNG_PINS, "libpng")
    zlib_checkout = checkout.parent / "zlib"
    if not zlib_checkout.is_dir():
        raise RecipeError(f"libpng: no zlib checkout at {zlib_checkout}; fetch zlib too")
    zlib_build = zlib(zlib_checkout, build)
    config = build / "pnglibconf"
    config.mkdir(parents=True, exist_ok=True)
    (config / "pnglibconf.h").write_bytes((checkout / "pnglibconf.h.prebuilt").read_bytes())
    return Prepared(
        sources=(
            ADAPTERS / "libpng_adapter.c",
            *(checkout / name for name in LIBPNG_SOURCES),
            *zlib_build.sources[1:],
        ),
        include_dirs=(checkout, config, *zlib_build.include_dirs),
    )


RE2_SOURCES = (
    "re2/bitmap256.cc",
    "re2/bitstate.cc",
    "re2/compile.cc",
    "re2/dfa.cc",
    "re2/filtered_re2.cc",
    "re2/mimics_pcre.cc",
    "re2/nfa.cc",
    "re2/onepass.cc",
    "re2/parse.cc",
    "re2/perl_groups.cc",
    "re2/prefilter.cc",
    "re2/prefilter_tree.cc",
    "re2/prog.cc",
    "re2/re2.cc",
    "re2/regexp.cc",
    "re2/set.cc",
    "re2/simplify.cc",
    "re2/tostring.cc",
    "re2/unicode_casefold.cc",
    "re2/unicode_groups.cc",
    "util/rune.cc",
    "util/strutil.cc",
)
RE2_PINS = {
    "re2/bitmap256.cc": "7fd5801493e739e26ca48fcaa0e63a4a511fffbdeaabb75545f6728befda2a1b",
    "re2/bitstate.cc": "67458e4fa4704e08aec2d1835a817391d2c1621b29488ca10abfb5f6663a9920",
    "re2/compile.cc": "72f532e4f7d8a38c920f8f080bf8b6a5a439833792e97821bef94a62f7bd8c8e",
    "re2/dfa.cc": "7c2cc2f28b0f83e75889254e03112b17c3bf5df264748c777264cb19412577f3",
    "re2/filtered_re2.cc": "df1de01b94f9d6d9d0579be8b6d2d134f8b93841a2d8de0219ffc4b5475c9c78",
    "re2/mimics_pcre.cc": "d0f4bdfc19f558bcbef3ee903606d17fb2266dbe11029c8cb6808df9c4e9a113",
    "re2/nfa.cc": "9bbb1ae5d3727b70dd0ad518e9bc787b0a7197c6ec86d8b64fdb2b1b1543d0c2",
    "re2/onepass.cc": "d82aac9a6a77972be727bfa24680fb14ba1fd0b016bd5da48edeca4aa46140fb",
    "re2/parse.cc": "1077a318b7170b3ef1ac4bbf4fa82e7456b1ce41ffb31f9396034e2a072d6f8e",
    "re2/perl_groups.cc": "9202c5d6bcc10e4b134a331ddfddd4dc6a41d51505126aff25c74a1ed032e243",
    "re2/prefilter.cc": "79de999a3351d9fc475cf87c13058ab214735fc683b32e58d02135f717887d6d",
    "re2/prefilter_tree.cc": "c280f5b7704c1b28ae19c64c19ffe95f4a8936a8d44a82b8a9564fd390f2bebc",
    "re2/prog.cc": "765e240d0ebc14cb77f914b4ca182d5ab9cc3d88d074293785c64ef5217653cd",
    "re2/re2.cc": "60d08b1f1f8614ef161f7030940cd5b33d7321f31e898671a20dbd9752efb634",
    "re2/regexp.cc": "6a568f1d5f8ef37ef7c6b2f10f03b4d5420b0a82ce342780c206855e3de8b22f",
    "re2/set.cc": "a5fb9b8894f1241d8a18524a593a40e97f69d8f5dfd378b3fd6396d163e85fde",
    "re2/simplify.cc": "9c4f202d968256daec3989d02916dff1291982648148728ee3b6472e4e3f5f26",
    "re2/tostring.cc": "5855de99b2105ee44f30a08bfbc42a942327a08d3745fd75fb3a50020f8b5574",
    "re2/unicode_casefold.cc": "64ca9ac88ceaa9833f07570dc44fd2892b75cfe1d1b3a2ce3cb348e8761a273a",
    "re2/unicode_groups.cc": "53997d641f218bc71ea5c7b4338c3777d81c31cc86b80e0bac27120249fc0fd0",
    "util/rune.cc": "81b413e5bc96c1260cab55c8847076d407b84a6533f6916a6638bd59a4b1cbc1",
    "util/strutil.cc": "52055ea13a5341a80b725a515aa1ce76edb02af94f508ce18b42c1992f20c57f",
    "re2/re2.h": "9e38921730f02883de794593b493428eaf6bf394ed2c48452604805126d8985b",
}
# The Abseil libraries RE2 2023-06-01 links, resolved by pkg-config.
RE2_ABSL_PACKAGES = (
    "absl_base",
    "absl_fixed_array",
    "absl_flat_hash_map",
    "absl_flat_hash_set",
    "absl_hash",
    "absl_inlined_vector",
    "absl_optional",
    "absl_span",
    "absl_str_format",
    "absl_strings",
    "absl_synchronization",
)


def re2(checkout: Path, build: Path) -> Prepared:
    """RE2 2023-06-01: its re2/*.cc and the util sources the library uses,
    against the system Abseil (20220623 or later, through pkg-config). Later
    releases need a newer Abseil than distributions ship."""
    verify(checkout, RE2_PINS, "re2")
    try:
        libs = subprocess.run(
            ["pkg-config", "--libs", *RE2_ABSL_PACKAGES],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
    except (OSError, subprocess.CalledProcessError) as error:
        raise RecipeError(
            "re2: pkg-config cannot find Abseil (install libabsl-dev and pkg-config)"
        ) from error
    return Prepared(
        sources=(ADAPTERS / "re2_adapter.cc", *(checkout / name for name in RE2_SOURCES)),
        include_dirs=(checkout,),
        # The C driver links no UBSan C++ runtime, which -fsanitize=vptr needs.
        extra_cflags=("-fno-sanitize=vptr",),
        link_flags=(*libs, "-lstdc++", "-lpthread"),
    )


RECIPES = {
    "cjson": cjson,
    "sqlite": sqlite,
    "zlib": zlib,
    "libyaml": libyaml,
    "libpng": libpng,
    "re2": re2,
}


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
