# Feature completion report (v0.1.0)

Legend: ✅ implemented and tested here · 🟡 implemented, only partly verifiable in the build environment · ⛔ not implemented

| Area | Status | Verification |
|---|---|---|
| Schema, tiers, invariants, masking, salted hashing | ✅ | unit tests |
| SQLite store, settings, exclusions | ✅ | unit + API tests |
| Hash-chained audit log + tamper detection | ✅ | unit test (tamper → detected at the right row) |
| Shield: threaded scan, smart/deep modes, signatures, imported hash lists, PE import analysis, decoded PowerShell payloads, rule engine, ZIP/Office/OLE inspection | ✅ | ~40 unit tests incl. a real crafted PE with import table, real archives, false-positive traps |
| Shield: calibrated danger levels (test-file spec, ruleset-likeness, precision caps, corroboration), hash-manifest self-trust, tamper detection, trust-by-hash, scan cache | ✅ | 25 tests incl. scanning a copy of the real project (clean with its manifest, flagged without it) and a browser test that scans Ultrimater's folder through the UI |
| Shield: scopes + permission model (engine-enforced, audited), bulk quarantine, coverage reports | ✅ | unit + HTTP + browser tests, including declining permission |
| Shield: Downloads watcher (user-space), startup/hosts review | ✅/🟡 | watcher tested live (new-file, growing-file, consent, restart); registry/hosts reading is Windows-only and tested with injected data |
| Native file/folder dialogs | 🟡 | engine, API and UI tested with a stand-in dialog and the unavailable-fallback; **the real Windows dialog could not be opened in the Linux build environment** |
| Shield: quarantine / restore | ✅ | byte-identical round trip, no-overwrite, tamper blocks restore |
| Shield: Windows Defender status/detections/scan, Authenticode | 🟡 | parser tested with mocks; **needs a run on Windows** |
| Vision: PII, credentials, validators | ✅ | unit tests |
| Vision: EXIF, DOCX props, OCR, redaction, metadata stripping | ✅ | real files + real Tesseract in this environment |
| Vision: PDF text | 🟡 | needs PyMuPDF/pdftotext; not exercised by tests |
| Inference: entity linking, 6 rules, graph, labelled hypotheses | ✅ | integration tests on demo persona |
| Sentinel: URL/text/header/injection, scoring, ordinal output | ✅ | unit tests |
| Sentinel: Ollama provider | 🟡 | validated against a fake provider; **no Ollama in the build environment** |
| API security (token, Host, CSP, limits, traversal, keep-alive bodies) | ✅ | API tests; keep-alive bug found and fixed by browser test |
| UI: 8 pages, minimal royal liquid glass, sharp corners, no purple, graph, confirmations, safe rendering | ✅ | real Chromium test: every element has square corners and no purple on every page visited; static design-rule tests |
| Desktop shell: app window, single instance, close = quit, clear error if no Edge/Chrome | ✅ | 7 lifecycle tests with a stub window |
| Packaging: PyInstaller `.exe` + Inno Setup installer (local script + GitHub Actions cloud build) | 🟡 | scripts written (`build_windows.bat`, `installer/ultrimater.iss`); **could not be built in the Linux environment, first run must happen on Windows** |
| Responsiveness: background-cached probes, single-flight, skeleton-first navigation, request timeouts, auto lite-glass on slow GPUs | ✅ | 7 perf tests + browser test with a simulated 4 s Defender: tab switches 54-244 ms |
| Appearance customisation: 10 themes, accent/background/glass/layout/type controls, live apply, persistence (browser + engine), import/export/reset, strict validation | ✅ | 7 schema/API unit tests + 18 browser checks driving the real controls |
| Light mode, radar/HUD/grid/donut/glow effects, purple palette | removed by design | tested absent |
| Fix & review (Response Centre): server-side search/filter/sort/pagination, selection, bulk actions | ✅ | 8 unit tests + browser tests with 80 extra findings (page of 25, search, chips, pagination, select-all-matching) |
| Diagnostics + scanner self-test + masked shareable report | ✅ here / 🟡 on Windows | 10 unit tests, browser test; Windows-only checks report "not Windows" here and need a run on your PC |
| Robustness: fuzzing of all parsers, pathological-regex tests | ✅ | 8 tests; found and fixed a real crash (corrupt zip entries) |
| Browser protection: consent-gated read-only access to the main browser (downloads, recent addresses, extensions, homepage), automatic checks, auto-watch + Quick-scan of its download folder | ✅ | 17 tests on fake Chrome/Firefox profiles (consent enforced, no passwords/cookies/titles/query strings stored, browser files untouched, revoke, restart) + real-browser UI test; **real Chrome/Edge/Firefox profiles and the Windows default-browser lookup need a run on your PC** |
| Gmail protection: connect-to-enable, read-only (`gmail.readonly`) phishing screening of the inbox via your own Google client ID (OAuth + PKCE), automatic checks, revoke on disconnect | ✅ | 10 tests against a local stand-in for Google (consent enforced, PKCE + state, read-only scope, no mail content stored, never writes, disconnect revokes + deletes token, restart) + real-browser UI test; **never run against real Google: needs your own client ID and a run on your PC** |
| Kernel-level real-time protection, scheduling, cloud lookup, PUA database, YARA, behavioural/emulation analysis | ⛔ | listed as "not implemented" in Settings |

Test totals: 183 unit/integration tests + 105 browser checks, all passing in the build environment (Linux, Python 3.12).
