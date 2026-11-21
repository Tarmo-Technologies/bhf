<!-- SPDX-License-Identifier: Apache-2.0 -->
# JS-2 browser globals re-run, 2026-11-18

This record re-runs, by name, every JavaScript and TypeScript target that the 2026-07-28 campaign sweep (`results-0728`) skipped because a browser global was missing under Node: `ReferenceError: window is not defined`, and the same for `navigator`, `self` and `document`. That is the JS-2 class of [expected-gaps.md](../expected-gaps.md). Each project is re-run at the commit that sweep measured. The bhf under test is a release build of the wave-11 branch, with the driver's browser stand-ins (#288).

The rows are under `benchmarks/campaign-2026-07-25/`:

| Directory | What it is |
|---|---|
| `results-0728/` | Before: the 2026-07-28 sweep |
| `results-1118-js2/` | After: the 29 JavaScript targets (`.js`, `.mjs`) |
| `results-1118-ts2/` | After: the 8 TypeScript targets (`.ts`, `.tsx`) |

## Reproduce

```sh
cd benchmarks/campaign-2026-07-25
BHF_BIN=<bhf> python3 go1_rerun.py results-0728 results-1118-js2 \
  --lang javascript --class JS-2 --all-lanes
BHF_BIN=<bhf> python3 go1_rerun.py results-0728 results-1118-ts2 \
  --lang typescript --class JS-2 --all-lanes
```

`--all-lanes` reads every lane's rows: most of these targets are in projects the sweep chose for another language (Hugo's live-reload script, the Rails asset bundle, Gitea's front end).

## Before and after

| | Before | After |
|---|---:|---:|
| JS-2 targets re-run | 37 | 37 |
| Built and fuzzed | 0 | 23 |
| Skipped for a missing browser global (JS-2) | 37 | 0 |
| Not loadable for another reason | 0 | 14 |

By project, after:

| Project | Targets | Built and fuzzed | What stops the rest |
|---|---:|---:|---|
| jquery/jquery | 5 | 5 | |
| firefly-iii/firefly-iii | 5 | 5 | |
| rails/rails (Turbo) | 5 | 5 | |
| go-gitea/gitea | 5 | 5 | |
| open-webui/open-webui | 2 | 2 | |
| jeecgboot/JeecgBoot | 1 | 1 | |
| gorhill/uBlock | 5 | 0 | `chrome.declarativeNetRequest`, a browser-extension API |
| hakimel/reveal.js | 5 | 0 | the minified plugin's exports are not functions (`BHF_JS_EXPORT 'A' is not a function`) |
| gohugoio/hugo | 3 | 0 | the same: the live-reload bundle's exports are not functions |
| github-linguist/linguist | 1 | 0 | `React is not defined`: a JSX sample with no React import |

Once the missing global is stood in for, the 14 stop at the next precondition: an extension API, exports that are not functions, or a missing React import. The driver stands in for page globals only, so these stay unloadable.

## What it took

The first version installed the stand-ins and retried `require` in the same process. That reached 16 of the 37 targets. Three more changes brought it to 23:

- **An ES module keeps its error.** jQuery's sources are ES modules loaded through `require`. Node keeps a module whose evaluation threw in its errored state, so a retry in the same process throws again. The driver now records the names it stood in for, and installs them before the target loads. The build's load-only gate runs again while that record grows.
- **The page has a head and a body.** The reveal.js plugin calls `document.getElementsByTagName('head')[0].appendChild(...)`. The stand-in document now finds its own `html`, `head` and `body`.
- **More than three names.** Turbo needs `customElements` and `HTMLFormElement`, and open-webui's receiver touches `document` in its constructor. The driver stands in for any `HTML…Element`, `SVG…Element` or `…Observer` name a module hits, and retries a receiver's construction as well as its module's load.

## Findings

The re-run reported one finding: firefly-iii's bundled Leaflet `LatLng` throws `Invalid LatLng object` for input it rejects (BHF-210). That is the library's own input check, and the stand-ins play no part in it. Its fidelity record names the browser globals the target ran with, as every such finding's does.
