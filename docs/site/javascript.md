<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fuzzing JavaScript / Node.js with bhf

bhf fuzzes JavaScript with **no harness to write**. Point it at a Node source tree: it discovers exported functions, generates the harness and fuzzes each function with coverage guidance from **V8's own block coverage**, in a warm Node process.

```sh
bhf auto path/to/js-src --languages javascript
```

## How it works

The fuzzable unit is an **exported** function that takes at least one argument. bhf:

1. **Discovers** each exported function in both module systems, CommonJS (`module.exports = { parse }`, `exports.parse = …`, `module.exports = fn`) and ESM (`export function parse`, `export const parse = …`, `export default`), plus the **public instance methods of exported classes** (`class Parser { parse(x) }`; the driver constructs a class that takes no constructor arguments and calls the method). It infers the first argument from its name: `buf`, `data` or `bytes` get a `Buffer`; `str`, `text`, `source` or `html` get a UTF-8 `string`; a path-like name (`filePath`, `filename`) gets a temporary file holding the input. A TypeScript annotation takes precedence (see below).
2. **Checks** the module with `node -c` (a syntax check; there is no native binary to build) and writes a launcher.
3. **Fuzzes** it with bhf's built-in fork-server engine, which drives **one warm Node process** over the framed protocol, so the interpreter and `require` start once. For each input the driver records **V8 precise block coverage** through the inspector Profiler and folds it, keyed on `(script, block span, taken/not-taken)`, into bhf's cumulative `BHF_COV_SHM` edge bitmap. The engine gets branch feedback from the code that ran.

### Browser globals

A module written for a browser can reference `window`, `document` or `navigator`, which Node does not define. It then fails to load (`ReferenceError: window is not defined`) or throws on its first input. When that happens, the driver installs inert stand-ins for the browser globals Node lacks and loads or runs the module again:

- `window` and `self` as the global object;
- `document`, with elements that do nothing;
- `navigator`, `location` on `http://localhost/`, `history` and `screen`;
- in-memory `localStorage` and `sessionStorage`.

A class the module needs (`HTMLFormElement`, `customElements`, `MutationObserver`) gets a stand-in as the module reaches it, at load or when its receiver is constructed. A module that only tests `typeof window` gets none.

The driver records the globals it stood in for in the harness's `browser-globals.txt` and installs them before the target loads, because an ES module that threw while loading keeps that error in the process. Each of the target's findings lists them in `fidelity.environment_shim` and in its `fidelity_caveat`. Such a finding can depend on the stand-ins, so reproduce it in a real browser.

Some globals are neither Node's nor among the stand-ins: `FileReader`, or a name the host defines, such as an embedding runtime's `app`. A target that reads one on every call would report the same `ReferenceError` for every input. So after the build, before fuzzing, bhf runs the target in one Node process on the empty input, `A` and `AAAAAAAA`. If all three stop at the same `ReferenceError: X is not defined`, thrown at the same place, bhf runs these inputs too, again in one process:

- the run's seed inputs: `--seed-file` and `--seed-dir`, or the files mined from the tree's test data;
- each token of the target's fuzz dictionary (the string and number literals of its source file), alone and followed by 64 `A`s;
- 4096 `A`s, 64 zero bytes and 64 `0xff` bytes.

If every one of them stops at that place too, the target is reported as `built, NOT entered (target environment)`. The reason names `X` and the frame that threw. The target is not fuzzed and no finding is written. If any input gets past, the target is fuzzed as usual, and the `ReferenceError` is a BHF-210 finding. bhf cannot tell an undefined global behind a check that none of these inputs passes (a format the literals do not spell) from one every input reaches. To have such a target fuzzed, pass an input that gets past the check with `--seed-file`.

### Oracle

An **uncaught exception** that is not input rejection is a finding; the driver halts with exit code 86. bhf classifies the error into a rule and a CWE:

| Error | Rule | CWE |
|---|---|---|
| `RangeError: Maximum call stack size exceeded` | BHF-207 | CWE-674 (uncontrolled recursion) |
| `RangeError: Invalid array/string length`, out of memory | BHF-209 | CWE-789 (resource exhaustion) |
| `ReferenceError`, an explicit `throw new Error(...)`, and the other ECMAScript built-in error types not listed below | BHF-210 | reachable crash |

The finding's sink and fix location are the first frame in the target's own code. bhf skips V8 builtin frames (`at get length [as length] (<anonymous>)`, `native`, `node:internal/...`), which have no source file to fix.

**Input rejection.** These errors count as the target rejecting the input and do not become findings:

- `TypeError`, `SyntaxError`, `URIError` and a validating `RangeError`;
- errors whose `.name` is not an ECMAScript built-in, such as Node's `AssertionError` or a library's `ValidationError`.

In this untyped lane bhf synthesises only the *first* argument, so a `TypeError` ("Cannot read properties of undefined", "x is not a function") almost always comes from the harness calling the function without a later argument or with the wrong first shape. In the 30-project campaign below, every `TypeError` was of that kind. The Python lane treats `TypeError` and `AttributeError` the same way. Injection classes are caught by the detectors below.

**Taint-confirmed detectors.** Beyond uncaught exceptions, the driver runs bug detectors, the JavaScript counterpart of bhf's native oracles and of Jazzer.js's bug detectors:

- **Command injection** (**BHF-431, CWE-78**). The driver hooks `child_process.exec` and `execSync` and reports when a substring of the fuzz input that holds a shell metacharacter reaches the command, which means the input controls shell syntax. The command is **never run**: the hook returns a benign stub. An input whose metacharacters never reach a command is not flagged.
- **Prototype pollution** (**BHF-509, CWE-1321**). The driver snapshots `Object.prototype` and `Array.prototype` at start-up and, after any input carrying a `__proto__`, `constructor` or `prototype` token, reports a new own property on them. Complete `{"__proto__":{…}}` payloads are added to the dictionary so an unsafe `JSON.parse` and merge is reachable. The token gate keeps a plain `JSON.parse`, which never pollutes, from being flagged.

## Compared with other JavaScript fuzzers

- **[Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js)** (Code Intelligence) instruments source with a Babel hook plug-in and drives libFuzzer. You write a `fuzz(data)` entry per target, wire it into a Jest or standalone runner, and manage the toolchain. It ships bug detectors for command injection, path traversal and prototype pollution.
- **[jsfuzz](https://github.com/fuzzitdev/jsfuzz)** uses Istanbul coverage and also needs one hand-written `fuzz(buf)` function per target. Its repository has seen little maintenance.

ESLint, SonarJS and CodeQL flag candidate issues statically; they do not run the code with inputs.

| | Jazzer.js / jsfuzz | **bhf `auto --languages javascript`** |
|---|---|---|
| Fuzz entry to write | one per target | **none; discovered** |
| Coverage | Babel or Istanbul instrumentation | **V8 precise block coverage, no source rewrite** |
| Multi-target sweep | scripted by hand | **one command over the whole tree** |
| Warm process reuse | per runner | **framed fork-server (one warm V8)** |
| Findings to CWE, SARIF, CSV | n/a | built in |
| Bug detectors | command injection, path traversal, prototype pollution (Jazzer.js) | command injection, prototype pollution |

## TypeScript

`bhf auto --languages typescript` fuzzes `.ts` and `.tsx` files the same way. Discovery reads the TypeScript source directly, so it sees a signature such as `parse(input: string, opts?: Options): Result`, and it skips `interface` and `type` declarations and `private`, `protected` and `abstract` members.

The first parameter's annotation decides what it receives, whatever the parameter is called: `string` gets a string, and `Buffer`, `Uint8Array`, `ArrayBuffer`, `DataView` or a union holding one gets a `Buffer` (so `decode(data: string)` gets a string). A path-like name (`filePath`, `filename`) still gets a temporary file, and an unannotated parameter or another type falls back to the name rules above.

bhf then transpiles the target to CommonJS with [esbuild](https://esbuild.github.io/), bundling local imports and leaving `node_modules` external, and drives it with the same warm-Node framed driver: the same V8 block coverage, dictionary, exception oracle and detectors as the JavaScript lane. esbuild writes a source map next to the transpiled module, and the harness runs node with `--enable-source-maps`, so a finding's stack, `finding.json` and SARIF name the `.ts` file and line (`src/codec.ts:7`) rather than the transpiled `target.js`. A plain JavaScript harness runs node without that flag.

```sh
bhf auto path/to/ts-src --languages typescript   # needs node and esbuild
```

**Finding esbuild.** Install it with `npm i -g esbuild`, or use the project's own `node_modules/.bin/esbuild`. bhf looks on `PATH` first, then in `node_modules/.bin` of the target's directory and of each directory above it, up to and including the directory `bhf auto` scans, nearest first. It never looks above the scanned directory: a `node_modules` there belongs to no scanned project, and in a directory other users can write, such as `/tmp`, anyone could plant the esbuild bhf would run. When you scan a single file there is no project directory, so bhf searches only `PATH`. The toolchain check at the start of the run resolves esbuild the same way for each TypeScript target, so a project's own esbuild satisfies it. bhf never runs `npx` to find esbuild, because npm 7 and later look the package up in the registry.

When node or esbuild is missing, the lane skips the target with outcome `missing_toolchain`; the reason names the tool and the next steps say what to install. `bhf auto --resume` tries such a target again, so install the tool and resume. `.d.ts` declaration files hold no runtime code and are not fuzzed.

## Validation (campaign)

A 30-project campaign ran over widely depended-on npm libraries, including express, lodash, axios, moment, validator.js, node-semver, marked, joi, qs and node-fetch:

- **2,018 JavaScript files scanned, 531 fuzzable functions discovered, 0 bhf panics.** The corpus held CommonJS and ESM, minified and hand-written code (validator.js alone gave 111 targets, moment 162). The first-argument name filter keeps internal array and options helpers (`multilineRegexp(parts)`) out of the fuzz set.
- **End to end** on a parser, V8 branch coverage drove the engine to an uncontrolled-recursion crash (`RangeError: Maximum call stack size exceeded`, BHF-207, CWE-674) with the V8 stack, from **no hand-written harness**. With the `TypeError` rejection policy, the campaign's built and fuzzed validators gave **0 false positives**.

## Requirements and licensing

- **Node.js** on the host. The lane installs no npm packages; the target is `require`d as it is. Without `node`, the lane skips the target with a reason.
- The driver uses only Node built-ins (`inspector`, `fs`); it has no third-party fuzzing dependency and nothing is linked into bhf.

## Scope

- The fuzzed input is the **first argument** (a Buffer, string or file). A function whose behaviour depends on a second structured argument, such as an options object, is called with the first argument only, and the rejection policy above absorbs the `TypeError`s that causes.
- An `import`-only ESM package without `.mjs` or a `package.json` `"type"` can fail to load with `require`; point bhf at the built or published `lib/` directory instead.
- bhf fuzzes one function at a time. The target's own `require`d dependencies load, and coverage is scoped to the module under test.
