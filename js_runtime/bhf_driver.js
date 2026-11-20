// SPDX-License-Identifier: Apache-2.0
//
// bhf Node.js fork-server driver — the JavaScript analog of
// python_runtime/bhf_driver.py. Speaks the SAME BHF_FRAMED protocol so the
// builtin engine drives a warm, long-lived V8 one input at a time (amortizing
// interpreter + require startup), exactly like a C/Rust fork-server binary — no
// Jazzer.js, no jsfuzz, no libFuzzer.
//
// Coverage: V8 precise block coverage via the inspector Profiler. With
// callCount:false the coverage is cumulative (each `takePreciseCoverage` returns
// every block executed since start), which matches bhf's cumulative AFL-style
// edge bitmap: per input we fold the covered blocks of the target's own scripts
// into a 64 KB map (BHF_COV_BITS) and write it to the file-backed
// BHF_COV_SHM (the engine maps the same file MAP_SHARED and counts non-zero
// bytes). node internals and the driver are excluded so the signal is the code
// under test.
//
// Protocol (must match the C driver):
//   1. Save the engine's control pipe (fd 1) to a private fd, then redirect fd 1
//      to /dev/null so the target's stdout can't corrupt the sync stream (#427).
//   2. Write one ready byte to the control fd.
//   3. Loop: read {u32 little-endian length, bytes} from fd 0, run the harness,
//      write one sync byte to the control fd.
// An uncaught FINDING halts the process (exit 86) with no sync byte, so the engine
// sees the death and re-isolates the input. An expected rejection (input
// validation) is swallowed — the input is just rejected.
//
// Without BHF_FRAMED, argv[2] is a single input file to replay once (the
// engine's per-spawn crash-isolation path), else stdin is read. BHF_JS_PROBE
// runs a file of inputs once each, before any fuzzing (see probeInputs).

'use strict';
const fs = require('fs');
const inspector = require('inspector');

const FINDING_HALT_CODE = 86;
const COV_BITS = 1 << 16; // matches BHF_COV_BITS and the AFL map

// --- coverage state ---------------------------------------------------------
const covMap = new Uint8Array(COV_BITS);
let covFd = -1;
let session = null;
const targetHint = process.env.BHF_JS_MODULE || '';

function covInit() {
  const path = process.env.BHF_COV_SHM;
  if (path) {
    try {
      covFd = fs.openSync(path, 'r+');
    } catch (_) {
      try {
        covFd = fs.openSync(path, 'w+');
      } catch (_) {
        covFd = -1;
      }
    }
  }
  try {
    session = new inspector.Session();
    session.connect();
    session.post('Profiler.enable');
    // callCount:true + detailed:true => per-block execution counts (branch-level).
    // Each takePreciseCoverage returns the delta since the last take and resets the
    // counters, so folding count>0 blocks into the never-cleared covMap accumulates
    // cumulative edge coverage (with callCount:false V8 only reports function-level
    // coverage, which gives no branch feedback).
    session.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  } catch (_) {
    session = null;
  }
}

// Fold the target's covered blocks into the cumulative map (async: the inspector
// reply arrives on the event loop, which runs while we await).
function covFold() {
  if (!session) return Promise.resolve();
  return new Promise((resolve) => {
    session.post('Profiler.takePreciseCoverage', (err, res) => {
      if (!err && res && res.result) {
        for (const script of res.result) {
          const url = script.url || '';
          // Skip node internals, the driver, and anonymous eval scripts — keep
          // only the code under test so the map is meaningful.
          if (!url || url.startsWith('node:') || url.includes('bhf_driver')) continue;
          // Hash the URL (stable across takes; scriptId is not guaranteed to be)
          // into the block key so two scripts' identical offsets don't alias.
          let uh = 0;
          for (let k = 0; k < url.length; k++) uh = (Math.imul(uh, 31) + url.charCodeAt(k)) | 0;
          for (const fn of script.functions) {
            for (const r of fn.ranges) {
              // V8 detailed block coverage collapses *taken* contiguous blocks into
              // the parent range, so the branch-discriminating signal lives in the
              // *not-taken* (count==0) ranges. Fold EVERY range keyed on its span
              // plus a taken/not-taken bit: the set of (block, taken?) pairs is a
              // path signature that changes as different branches are exercised, so
              // the never-cleared covMap grows exactly when a new branch is reached.
              let h =
                Math.imul(uh, 0x9e3779b1) ^
                Math.imul(r.startOffset | 0, 0x85ebca6b) ^
                Math.imul(r.endOffset | 0, 0x27d4eb2f);
              if (r.count === 0) h ^= 0x5bd1e995;
              h = (h ^ (h >>> 15)) >>> 0;
              covMap[h % COV_BITS] = 1;
            }
          }
        }
      }
      if (covFd >= 0) {
        try {
          fs.writeSync(covFd, covMap, 0, COV_BITS, 0);
        } catch (_) {
          /* ignore */
        }
      }
      resolve();
    });
  });
}

// --- exception classification ----------------------------------------------
// Errors that are input *rejection* or our-fault, never a target bug — mirrors the
// Python driver's REJECTION_EXC. A dynamically-fed API rejects bad input with a
// SyntaxError (JSON.parse etc.), a URIError (bad %-escape), or a validating
// RangeError; suppressing them is the key to a low false-positive rate.
const EXPECTED = new Set(
  (process.env.BHF_EXPECTED_EXCEPTIONS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
);

function classify(err) {
  // Returns { finding: bool, rule: 'BHF-...' }.
  const name = err && err.name ? String(err.name) : '';
  const msg = err && err.message ? String(err.message) : String(err);
  if (EXPECTED.has(name)) return { finding: false };

  // A missing npm dependency the environment doesn't have — e.g. debug's
  // `common.js` LAZILY `require('ms')` only on a code path the fuzzer reaches, so
  // the pre-run module-load check (which only catches load-time requires) can't
  // see it. This is environmental (run `npm install`), not a target defect; mirrors
  // the interpreted-lane missing-dependency skip. Node stamps `code`
  // 'MODULE_NOT_FOUND'; match the message too for transpiled/bundled callers.
  if ((err && err.code === 'MODULE_NOT_FOUND') || /Cannot find module/i.test(msg)) {
    return { finding: false };
  }

  // Stack exhaustion (uncontrolled recursion) — a real defect (BHF-207).
  if (name === 'RangeError' && /call stack/i.test(msg)) {
    return { finding: true, rule: 'BHF-207' };
  }
  // Resource exhaustion: an input-driven huge allocation (BHF-209).
  if (
    (name === 'RangeError' && /Invalid (array|typed array|string) length/i.test(msg)) ||
    /out of memory/i.test(msg)
  ) {
    return { finding: true, rule: 'BHF-209' };
  }
  // Input validation / format / our-fault type — rejection, swallow. In an
  // untyped lane bhf synthesizes only the FIRST argument, so a `TypeError`
  // ("Cannot read properties of undefined", "x is not a function") is dominated by
  // us calling a function with a missing/typed later argument or the wrong first
  // shape — our fault, not a target defect. This mirrors the Python driver, which
  // suppresses the exact analogs (`TypeError`/`AttributeError`); a campaign over 30
  // npm libraries showed every `TypeError` was such an artifact. `SyntaxError`
  // (a JSON.parse-style reject), `URIError`, and a validating `RangeError` are the
  // API's intended input rejection.
  if (
    name === 'TypeError' ||
    name === 'SyntaxError' ||
    name === 'URIError' ||
    name === 'RangeError'
  ) {
    return { finding: false };
  }
  // A library's OWN error class — a `name` that is NOT an ECMAScript built-in error
  // type — is its deliberate way of rejecting bad input to its API (joi's
  // `AssertError` on an invalid schema/reference/template; a validator's
  // `ValidationError`). This is the JS analog of the Java/C# "exception defined in
  // the target's namespace" suppression. Fuzzing a validation library's builder API
  // otherwise flags every misuse rejection. Real security classes (command
  // injection, prototype pollution, path control, resource exhaustion) are caught by
  // the behavioral oracles, not by promoting every custom throw.
  const BUILTIN_ERRORS = new Set([
    'Error',
    'EvalError',
    'RangeError',
    'ReferenceError',
    'SyntaxError',
    'TypeError',
    'URIError',
    'AggregateError',
  ]);
  if (name && !BUILTIN_ERRORS.has(name)) {
    return { finding: false };
  }
  // A built-in ReferenceError (undefined variable), AssertionError, or an explicit
  // `throw new Error(...)` — a reachable crash the target owns (BHF-210).
  return { finding: true, rule: 'BHF-210' };
}

function reportFinding(err, rule) {
  const name = err && err.name ? String(err.name) : 'Error';
  const msg = (err && err.message ? String(err.message) : String(err)).replace(/[\r\n]+/g, ' ');
  // Marker mirrors the JVM/Python drivers; the engine's `parse_js_finding` reads
  // the pre-resolved BHF rule token and maps it to a CWE.
  process.stderr.write(`== bhf js finding: ${rule}: ${name}: ${msg}\n`);
  if (err && err.stack) process.stderr.write(String(err.stack) + '\n');
}

// --- browser globals (#288) -------------------------------------------------
// A module written for a browser references `window`, `document` or
// `navigator`, and under Node it fails to load ("window is not defined") or
// throws on its first input. When it does, the driver installs minimal stand-ins
// for the browser globals Node lacks, and one for the name it hit (an
// `HTMLFormElement`, a `MutationObserver`), loads or runs again, and records the
// names (BHF_JS_SHIM_RECORD), which the target's fidelity record reports: a
// finding may depend on them rather than on a real browser. A later start
// installs the recorded names before it loads: an ES module that threw as it
// loaded keeps its error in this process, so its next load is in the next one.
// A module that only tests `typeof window` never gets them.
const BROWSER_GLOBALS = [
  'window', 'self', 'document', 'navigator', 'location', 'localStorage',
  'sessionStorage', 'history', 'screen', 'customElements', 'HTMLElement', 'Element', 'Node',
];
const BROWSER_CLASS = /^(HTML\w*Element|SVG\w*Element|\w+Observer|DOMParser|XMLSerializer|DocumentFragment|Text|Comment|ShadowRoot|Range|Selection)$/;
// The names stood in for, in the order they were.
const standIns = [];
let baseShim = false;

// The browser global a ReferenceError says is missing, or null.
function missingBrowserGlobal(err) {
  if (!(err instanceof ReferenceError)) return null;
  const m = /^(\w+) is not defined$/.exec(String(err.message || ''));
  if (!m || m[1] in globalThis) return null;
  return BROWSER_GLOBALS.includes(m[1]) || BROWSER_CLASS.test(m[1]) ? m[1] : null;
}

function inertElement(tag) {
  const element = {
    tagName: String(tag || 'div').toUpperCase(),
    nodeName: String(tag || 'div').toUpperCase(),
    style: {},
    dataset: {},
    attributes: {},
    children: [],
    childNodes: [],
    textContent: '',
    innerHTML: '',
    innerText: '',
    value: '',
    classList: {
      add() {}, remove() {}, toggle() { return false; }, contains() { return false; },
    },
    setAttribute(name, value) { this.attributes[name] = String(value); },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null;
    },
    removeAttribute(name) { delete this.attributes[name]; },
    appendChild(child) { this.children.push(child); this.childNodes.push(child); return child; },
    removeChild(child) { return child; },
    insertBefore(child) { return child; },
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() { return true; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    getElementsByTagName() { return []; },
    getBoundingClientRect() { return { x: 0, y: 0, width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 }; },
    focus() {}, blur() {}, click() {},
  };
  return element;
}

function memoryStorage() {
  const items = new Map();
  return {
    get length() { return items.size; },
    key(index) { return Array.from(items.keys())[index] ?? null; },
    getItem(key) { return items.has(String(key)) ? items.get(String(key)) : null; },
    setItem(key, value) { items.set(String(key), String(value)); },
    removeItem(key) { items.delete(String(key)); },
    clear() { items.clear(); },
  };
}

// A class a module extends or tests against (`class X extends HTMLElement`,
// `x instanceof HTMLFormElement`); an observer's methods do nothing.
function standInClass(name) {
  const cls = function BrowserStandIn() {};
  Object.defineProperty(cls, 'name', { value: name });
  if (/Observer$/.test(name)) {
    cls.prototype.observe = function () {};
    cls.prototype.unobserve = function () {};
    cls.prototype.disconnect = function () {};
    cls.prototype.takeRecords = function () { return []; };
  }
  return cls;
}

function defineGlobal(name, value) {
  if (name in globalThis) return false;
  Object.defineProperty(globalThis, name, { value, writable: true, configurable: true, enumerable: false });
  return true;
}

// The browser globals Node does not define, once; their names are recorded.
function installBaseShim() {
  if (baseShim) return;
  baseShim = true;
  const g = globalThis;
  const define = (name, value) => {
    if (defineGlobal(name, value) && BROWSER_GLOBALS.includes(name)) standIns.push(name);
  };
  const html = inertElement('html');
  const body = inertElement('body');
  const head = inertElement('head');
  html.appendChild(head);
  html.appendChild(body);
  // `document.getElementsByTagName('head')[0]` and `querySelector('body')`
  // find the page's own elements.
  const byTag = (tag) => ({ html, head, body })[String(tag).toLowerCase()] || null;
  const url = new URL('http://localhost/');
  define('window', g);
  define('self', g);
  define('navigator', {
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) bhf-fuzz',
    language: 'en-US',
    languages: ['en-US'],
    platform: 'Linux x86_64',
    vendor: '',
    onLine: true,
    cookieEnabled: false,
    hardwareConcurrency: 1,
    maxTouchPoints: 0,
  });
  define('location', {
    href: url.href, protocol: url.protocol, host: url.host, hostname: url.hostname,
    port: url.port, pathname: url.pathname, search: '', hash: '', origin: url.origin,
    assign() {}, replace() {}, reload() {}, toString() { return url.href; },
  });
  define('document', {
    documentElement: html,
    body,
    head,
    cookie: '',
    title: '',
    readyState: 'complete',
    location: g.location,
    createElement: (tag) => inertElement(tag),
    createElementNS: (_ns, tag) => inertElement(tag),
    createTextNode: (text) => ({ nodeValue: String(text), textContent: String(text) }),
    createDocumentFragment: () => inertElement('fragment'),
    getElementById: () => null,
    getElementsByClassName: () => [],
    getElementsByTagName: (tag) => (byTag(tag) ? [byTag(tag)] : []),
    querySelector: (selector) => byTag(selector),
    querySelectorAll: (selector) => (byTag(selector) ? [byTag(selector)] : []),
    addEventListener() {},
    removeEventListener() {},
  });
  define('localStorage', memoryStorage());
  define('sessionStorage', memoryStorage());
  define('history', { length: 1, state: null, pushState() {}, replaceState() {}, back() {}, forward() {}, go() {} });
  define('screen', { width: 1280, height: 720, availWidth: 1280, availHeight: 720, colorDepth: 24 });
  const defined = new Map();
  define('customElements', {
    define(name, cls) { defined.set(String(name), cls); },
    get(name) { return defined.get(String(name)); },
    whenDefined() { return Promise.resolve(); },
    upgrade() {},
  });
  for (const name of ['HTMLElement', 'Element', 'Node']) {
    define(name, standInClass(name));
  }
  // Helpers on `window`, which go with it unrecorded.
  for (const name of ['addEventListener', 'removeEventListener', 'dispatchEvent', 'alert', 'scrollTo']) {
    if (typeof g[name] !== 'function') defineGlobal(name, () => undefined);
  }
  if (typeof g.requestAnimationFrame !== 'function') {
    defineGlobal('requestAnimationFrame', (cb) => setTimeout(() => cb(Date.now()), 0));
    defineGlobal('cancelAnimationFrame', (id) => clearTimeout(id));
  }
  if (typeof g.matchMedia !== 'function') {
    defineGlobal('matchMedia', (query) => ({
      matches: false, media: String(query), addListener() {}, removeListener() {},
      addEventListener() {}, removeEventListener() {},
    }));
  }
}

// Stand in for `name` (and the base globals), and record the names.
function standIn(name) {
  installBaseShim();
  if (defineGlobal(name, standInClass(name))) standIns.push(name);
  process.stderr.write(
    `bhf: note: the target references browser globals; it runs with bhf's minimal ` +
      `stand-ins for ${standIns.join(', ')}\n`,
  );
  const record = process.env.BHF_JS_SHIM_RECORD;
  if (record) {
    try {
      fs.writeFileSync(record, standIns.join(',') + '\n');
    } catch (_) {
      /* the record is best effort; the note above says it too */
    }
  }
}

// The names an earlier start stood in for, installed before the target loads.
function installRecordedStandIns() {
  const record = process.env.BHF_JS_SHIM_RECORD;
  let names = [];
  try {
    names = fs.readFileSync(record, 'utf8').trim().split(',').filter(Boolean);
  } catch (_) {
    return;
  }
  if (names.length === 0) return;
  installBaseShim();
  for (const name of names) {
    if (defineGlobal(name, standInClass(name))) standIns.push(name);
  }
}

let runOne = null;
let targetEntered = false;
// The bytes of the input currently being processed (latin1), for the sink taint
// check. Set per input before the target runs.
let currentInput = '';

function markTargetEntry() {
  if (targetEntered) return;
  const path = process.env.BHF_TARGET_ENTRY_SHM;
  if (!path) return;
  try {
    fs.writeFileSync(path, Buffer.from([1]));
    targetEntered = true;
  } catch (_) {
    // Entry evidence must never change target behavior.
  }
}

// --- taint-confirmed sink detectors (the JS analog of bhf's native BHF-431
// command-injection oracle) --------------------------------------------------
// Jazzer.js ships bug detectors; the bhf JS lane runs without the LD_PRELOAD
// shim (managed runtime), so the driver hooks the dangerous sinks in JS instead.
// A sink is a *finding* only when a shell-metacharacter-bearing substring of the
// current fuzz input reaches the command — i.e. the input controls shell syntax,
// not just data. The command is NEVER executed (that would let the fuzzer run
// arbitrary shell); a benign stub is returned so a non-injecting input continues.
const SHELL_META = /[;|`&><\n$()]/;

function inputControlsSink(sinkStr) {
  if (typeof sinkStr !== 'string' || currentInput.length < 2) return false;
  for (let i = 0; i < currentInput.length; i++) {
    if (!SHELL_META.test(currentInput[i])) continue;
    // Grow a window around the metacharacter and require it to appear verbatim in
    // the command — the fuzz bytes (incl. the metachar) flowed into the shell.
    const max = Math.min(24, currentInput.length - i);
    for (let len = 2; len <= max; len++) {
      const w = currentInput.substr(i, len);
      if (SHELL_META.test(w) && sinkStr.includes(w)) return true;
    }
  }
  return false;
}

function reportSink(rule, kind, sink, detail) {
  const d = String(detail).replace(/[\r\n]+/g, ' ').slice(0, 200);
  process.stderr.write(`== bhf js finding: ${rule}: ${kind}: ${sink}: ${d}\n`);
  try {
    fs.fsyncSync(2);
  } catch (_) {
    /* ignore */
  }
  process.exit(FINDING_HALT_CODE);
}

// Patch `child_process` exec/execSync so a fuzz-controlled shell command is
// detected (BHF-431, CWE-78) and never run. Best-effort — absent child_process, or
// a target that never execs, this is inert.
function installSinkGuards() {
  let cp;
  try {
    cp = require('child_process');
  } catch (_) {
    return;
  }
  const guard = (sink, cmd) => {
    if (inputControlsSink(cmd)) {
      reportSink('BHF-431', 'CommandInjection', sink, cmd);
    }
  };
  const emptyChild = () => {
    const { EventEmitter } = require('events');
    const child = new EventEmitter();
    const out = new EventEmitter();
    out.setEncoding = () => {};
    out.pipe = () => {};
    child.stdout = out;
    child.stderr = new EventEmitter();
    child.stdin = { write() {}, end() {} };
    child.kill = () => {};
    process.nextTick(() => child.emit('close', 0));
    return child;
  };
  if (typeof cp.execSync === 'function') {
    cp.execSync = (cmd) => {
      guard('execSync', cmd);
      return Buffer.from('');
    };
  }
  if (typeof cp.exec === 'function') {
    cp.exec = (cmd, ...rest) => {
      guard('exec', cmd);
      const cb = rest.find((a) => typeof a === 'function');
      if (cb) {
        process.nextTick(() => cb(null, '', ''));
      }
      return emptyChild();
    };
  }
}

// --- prototype-pollution detector (BHF-509, CWE-1321) ------------------------
// A merge/clone/set that writes an attacker-chosen key (`__proto__`,
// `constructor`, `prototype`) into an ordinary object pollutes Object.prototype
// (or Array.prototype) for the whole realm — the top JS injection class and a
// Jazzer.js bug detector. We snapshot the base prototypes' own-property names at
// startup, then after each input report a NEW own-property that appeared, gated on
// the input carrying a pollution vector token so it is taint-confirmed.
const PROTO_TARGETS = [
  ['Object.prototype', Object.prototype],
  ['Array.prototype', Array.prototype],
];
const protoBaselines = PROTO_TARGETS.map(([, p]) => new Set(Object.getOwnPropertyNames(p)));
const POLLUTION_VECTOR = /__proto__|constructor|prototype/;

function checkPrototypePollution() {
  if (!POLLUTION_VECTOR.test(currentInput)) return;
  for (let i = 0; i < PROTO_TARGETS.length; i++) {
    const [label, proto] = PROTO_TARGETS[i];
    for (const key of Object.getOwnPropertyNames(proto)) {
      if (!protoBaselines[i].has(key)) {
        reportSink('BHF-509', 'PrototypePollution', label, `polluted key '${key}'`);
      }
    }
  }
}

async function runInput(buf) {
  currentInput = buf.toString('latin1');
  try {
    // Await thenables as well as native promises. This keeps rejected async
    // parser calls inside the same finding classifier and, for path-backed
    // targets, keeps the materialized resource alive until the read completes.
    await runOne(buf);
  } catch (err) {
    // A browser module that touches `navigator` only when called: run the
    // input again with the stand-ins (#288) rather than report Node's lack.
    const name = missingBrowserGlobal(err);
    if (name !== null) {
      standIn(name);
      return runInput(buf);
    }
    const c = classify(err);
    if (c.finding) {
      reportFinding(err, c.rule);
      // Flush stderr then hard-halt so the engine re-isolates the input.
      try {
        fs.fsyncSync(2);
      } catch (_) {
        /* ignore */
      }
      process.exit(FINDING_HALT_CODE);
    }
    // else: expected rejection — swallow.
  }
  // Check for prototype pollution after every input (a merge that pollutes may
  // still return/throw normally); reportSink hard-halts on detection.
  checkPrototypePollution();
}

// --- undefined-global probe (#398) ----------------------------------------
// The build's last gate. BHF_JS_PROBE names a file of inputs, each framed as
// {u32 little-endian length, bytes}. They run in order in this one process,
// and the probe prints one verdict line on stderr:
//   == bhf js probe: got past: <i>           input i did not stop there
//   == bhf js probe: every input stopped: <n>: <global>: <frame>
// The second means all n inputs threw `ReferenceError: <global> is not
// defined` from the same frame, so no input reached code past that name. A
// sink or prototype-pollution halt, or a hang, ends the run with no verdict
// line, and the build then fuzzes the target as usual.

// The name and throwing frame of an undefined-global ReferenceError, or null.
function undefinedGlobal(err) {
  if (!err || err.name !== 'ReferenceError' || !classify(err).finding) return null;
  const m = /^([\w$]+) is not defined$/.exec(String(err.message || ''));
  if (!m) return null;
  const frame = String(err.stack || '')
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line.startsWith('at '));
  return { name: m[1], frame: frame ? frame.slice(3) : '(unknown frame)' };
}

// Run one input as runInput does, but report where it stopped instead of
// halting: the undefined global it threw for, or null.
async function undefinedGlobalStop(buf) {
  currentInput = buf.toString('latin1');
  try {
    await runOne(buf);
  } catch (err) {
    // A browser global the driver stands in for (#288): run it again with it.
    const name = missingBrowserGlobal(err);
    if (name !== null) {
      standIn(name);
      return undefinedGlobalStop(buf);
    }
    return undefinedGlobal(err);
  }
  return null;
}

async function probeInputs(path) {
  const data = fs.readFileSync(path);
  let first = null;
  let count = 0;
  for (let at = 0; at + 4 <= data.length; count++) {
    const n = data.readUInt32LE(at);
    const input = data.subarray(at + 4, at + 4 + n);
    at += 4 + n;
    const stop = await undefinedGlobalStop(input);
    const same =
      stop !== null &&
      (first === null || (stop.name === first.name && stop.frame === first.frame));
    if (!same) {
      process.stderr.write(`== bhf js probe: got past: ${count}\n`);
      return;
    }
    first = stop;
  }
  if (first !== null) {
    process.stderr.write(
      `== bhf js probe: every input stopped: ${count}: ${first.name}: ${first.frame}\n`
    );
  }
}

// --- harness resolution -----------------------------------------------------
// The launcher sets BHF_JS_MODULE (absolute path to the target) and
// BHF_JS_EXPORT (the dotted export path, e.g. "parse" or "Foo.bar") and
// BHF_JS_ARG ("buffer" | "string" | "path"). `runOne(buf)` decodes and calls it.
function loadRunOne() {
  const modPath = process.env.BHF_JS_MODULE;
  const exportPath = process.env.BHF_JS_EXPORT || '';
  const argKind = process.env.BHF_JS_ARG || 'buffer';
  // A browser module that touches `window` as it loads: load it again with
  // the stand-ins (#288). A CommonJS module that threw is not cached; an ES
  // module keeps its error, and loads in the next start.
  installRecordedStandIns();
  // Resolve the export, constructing a receiver for a `Class#method`.
  const resolve = () => {
    const mod = require(modPath);

    // A `ClassPath#method` export path means: resolve the class, `new` it (no-arg),
    // then call the instance method. `#method` (empty class part) = the module itself
    // is the class. Otherwise the export path is a plain dotted function path.
    const hash = exportPath.indexOf('#');
    let fn;
    let recv;
    if (hash >= 0) {
      const classPath = exportPath.slice(0, hash);
      const methodName = exportPath.slice(hash + 1);
      let cls = mod;
      for (const part of classPath.split('.').filter(Boolean)) {
        cls = cls[part];
      }
      if (typeof cls !== 'function') {
        throw new Error(`BHF_JS_EXPORT class '${classPath}' not found in ${modPath}`);
      }
      recv = new cls();
      fn = recv[methodName];
    } else {
      fn = mod;
      recv = undefined;
      for (const part of exportPath.split('.').filter(Boolean)) {
        recv = fn;
        fn = fn[part];
      }
    }
    if (typeof fn !== 'function') {
      throw new Error(`BHF_JS_EXPORT '${exportPath}' is not a function in ${modPath}`);
    }
    return { fn, recv };
  };
  let fn;
  let recv;
  for (let attempt = 0; ; attempt++) {
    try {
      ({ fn, recv } = resolve());
      break;
    } catch (err) {
      // As it loads, or as its receiver is constructed.
      const name = missingBrowserGlobal(err);
      if (name === null || attempt >= 16) throw err;
      standIn(name);
    }
  }
  const bound = fn.bind(recv);
  if (argKind === 'string') {
    return (buf) => {
      const arg = buf.toString('utf8');
      markTargetEntry();
      return bound(arg);
    };
  }
  if (argKind === 'path') {
    return async (buf) => {
      // An expert feeds file parsers by materializing the bytes, not by treating
      // arbitrary bytes as a filename. Create the resource before the entry
      // checkpoint so setup failure can never masquerade as target execution.
      const os = require('os');
      const path = require('path');
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bhf-js-'));
      const inputPath = path.join(dir, 'input');
      try {
        fs.writeFileSync(inputPath, buf);
        markTargetEntry();
        return await bound(inputPath);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    };
  }
  return (buf) => {
    markTargetEntry();
    return bound(buf);
  };
}

// --- framed protocol --------------------------------------------------------
function readExact(fd, n) {
  const out = Buffer.allocUnsafe(n);
  let got = 0;
  while (got < n) {
    let r;
    try {
      r = fs.readSync(fd, out, got, n - got, null);
    } catch (e) {
      if (e.code === 'EAGAIN') continue;
      return null;
    }
    if (r <= 0) return null;
    got += r;
  }
  return out;
}

function readU32(fd) {
  const b = readExact(fd, 4);
  if (!b) return -1;
  return b.readUInt32LE(0);
}

async function framedLoop() {
  const ctrl = setupControlFd();
  const one = Buffer.from([1]);
  fs.writeSync(ctrl, one, 0, 1, null); // ready byte
  while (true) {
    const n = readU32(0);
    if (n < 0) break;
    const data = n > 0 ? readExact(0, n) : Buffer.alloc(0);
    if (data === null) break;
    await runInput(data);
    await covFold();
    fs.writeSync(ctrl, one, 0, 1, null); // sync byte
  }
}

// The engine reads sync bytes from the child's stdout (fd 1). Node has no dup2()
// to point fd 1 at /dev/null, so instead: (1) duplicate fd 1 via /proc/self/fd/1
// (a new fd to the SAME pipe) as the private control channel, and (2) silence the
// JS-level stdout so the target's console output can't corrupt the sync stream on
// fd 1 (#427). A target writing to fd 1 through a raw syscall is not intercepted,
// but pure-JS targets go through process.stdout / console.
function setupControlFd() {
  let ctrl;
  try {
    ctrl = fs.openSync('/proc/self/fd/1', 'w');
  } catch (_) {
    ctrl = 1; // best effort
  }
  const noop = () => true;
  process.stdout.write = noop;
  console.log = noop;
  console.info = noop;
  console.debug = noop;
  return ctrl;
}

// In bhf's re-run of an input that hung, print the frames the target is
// running once the run reaches BHF_HANG_REPORT_MS, then halt: bhf keys the hang
// finding on them. A loop in JavaScript never yields to the event loop, so a
// worker thread keeps the time and pauses the main thread through the
// inspector (V8 answers at the loop's next back edge); the paused frames' URLs
// come from the scripts the debugger reported. The worker enables the debugger
// before the input runs, while the main thread can still answer.
const HANG_WATCHDOG = `
const fs = require('fs');
const inspector = require('inspector');
const { fileURLToPath } = require('url');
const { parentPort, workerData } = require('worker_threads');
const alive = setInterval(() => {}, 1000);
const scripts = new Map();
const session = new inspector.Session();
session.connectToMainThread();
session.on('Debugger.scriptParsed', ({ params }) => scripts.set(params.scriptId, params.url));
session.on('Debugger.paused', ({ params }) => {
  const lines = ['== bhf hang: js'];
  for (const frame of params.callFrames) {
    let file = frame.url || scripts.get(frame.location.scriptId) || '';
    if (file.startsWith('file://')) file = fileURLToPath(file);
    if (!file || file.startsWith('node:') || workerData.own.includes(file)) continue;
    if (workerData.prefix && !file.startsWith(workerData.prefix)) continue;
    const name = frame.functionName || '(anonymous)';
    lines.push('== bhf frame: ' + name + ' @ ' + file + ':' + (frame.location.lineNumber + 1));
    if (lines.length > 5) break;
  }
  fs.writeSync(2, lines.join('\\n') + '\\n');
  process.kill(process.pid, 'SIGKILL');
});
session.post('Debugger.enable', () => {
  parentPort.postMessage('ready');
  setTimeout(() => session.post('Debugger.pause'), Math.max(0, workerData.deadline - Date.now()));
});
`;

// Start the watchdog when BHF_HANG_REPORT_MS asks for one; resolves once it
// is ready (at once without one, or if it cannot start).
function armHangReport() {
  const after = Number(process.env.BHF_HANG_REPORT_MS);
  if (!Number.isFinite(after) || after <= 0) return Promise.resolve();
  let Worker;
  try {
    ({ Worker } = require('worker_threads'));
  } catch (_) {
    return Promise.resolve();
  }
  const deadline = Date.now() + after - process.uptime() * 1000;
  const workerData = { deadline, own: [__filename], prefix: process.env.BHF_TRACE_PREFIX || '' };
  return new Promise((resolve) => {
    const watchdog = new Worker(HANG_WATCHDOG, { eval: true, workerData });
    watchdog.unref();
    watchdog.once('message', resolve);
    watchdog.once('error', resolve);
    watchdog.once('exit', resolve);
  });
}

function main() {
  // The probe only asks where inputs stop; it needs no coverage.
  const probe = process.env.BHF_JS_PROBE;
  if (probe === undefined) covInit();
  installSinkGuards();
  runOne = loadRunOne();
  // BHF_JS_LOAD_ONLY: prove the target can be PREPARED, then stop. The build
  // gate uses this to tell "the export resolves and any receiver constructs"
  // apart from "the target crashed on an input", which running one input cannot
  // do — a finding halts with a nonzero code, so a target that crashes on the
  // empty input looks identical to one that could never load.
  if (process.env.BHF_JS_LOAD_ONLY !== undefined) {
    process.exit(0);
  }
  if (probe !== undefined) {
    probeInputs(probe).then(() => process.exit(0));
    return;
  }
  if (process.env.BHF_FRAMED !== undefined) {
    framedLoop().then(() => process.exit(0));
    return;
  }
  // Per-spawn single-input replay: argv[2] is an input file, else read stdin.
  let input;
  const argFile = process.argv[2];
  if (argFile && fs.existsSync(argFile)) {
    input = fs.readFileSync(argFile);
  } else {
    try {
      input = fs.readFileSync(0);
    } catch (_) {
      input = Buffer.alloc(0);
    }
  }
  armHangReport()
    .then(() => runInput(input))
    .then(() => covFold())
    .then(() => process.exit(0));
}

main();
