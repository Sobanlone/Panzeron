# Roadmap (honest status and plan)

## Where the project stands
**Solid and tested:** the scanner and calibrated danger model, permission model, native-dialog flow, Downloads watcher, quarantine, privacy analysis, exposure graph, phishing analysis, audit chain, the interface, Response Centre at scale, diagnostics, and fuzz/robustness tests (183 unit + 105 browser checks).

**The biggest risk is unchanged: it has never run on Windows.** Everything is tested on Linux (Chromium). Windows-only code (Defender, registry, hosts file, native dialogs, Authenticode, packaging) is verified with mocks only. **Step zero for any next session: run Settings → Diagnostics on the Windows laptop and send the report.**

## Done in this iteration
1. Redesign: minimal, royal, sharp-cornered liquid glass; purple, glow, radar, HUD, grid, donut and light mode removed; sample data moved to Settings and labelled synthetic; the sidebar no longer claims "nothing leaves this device" when a remote AI host is allowed; design rules enforced by tests.
2. Robustness: fuzzing + pathological-regex tests (found and fixed a corrupted-zip crash).
3. Response Centre at scale (search, filters, pagination, bulk).
4. Diagnostics, scanner self-test and a shareable report.

## Next, in priority order
| # | Item | Why | Effort |
|---|---|---|---|
| 1 | Run on Windows; fix what Diagnostics shows | Closes the largest unverified area | 1 session |
| 2 | Mark-of-the-Web origin (where a file was downloaded from, via Zone.Identifier) shown as evidence | Strong real-world signal; cheap | small |
| 3 | `.eml` analysis: parse headers/links/attachments, flag **link text that differs from its real destination**, look-alike (IDN) domains, scan attachments | Biggest gap in phishing detection | medium |
| 4 | Script obfuscation scoring (char-code arrays, split keywords, long base64) | Catches hidden scripts | small |
| 5 | More secret/ID detectors (more API-key formats, Aadhaar with checksum, crypto wallets) | Wider privacy coverage | small |
| 6 | Database schema versioning + migrations; mark interrupted scans on restart | Safe updates and crash recovery | small |
| 7 | Scan history detail view (past coverage report and findings), re-run | Usability | small |
| 8 | Ctrl+K command palette; printable HTML report | Productivity, demo polish | small |
| 9 | "Explain this finding" with the local model (masked data only, deterministic fallback, labelled AI-assessed) | Uses the AI where it genuinely helps | medium |
| 10 | Code-sign the installer (needs a certificate) | Real fix for manifest/installer trust | external |

## Deliberately not planned
Kernel-level real-time protection (needs a signed driver), cloud reputation lookup (conflicts with local-first privacy unless opt-in), behavioural/emulation analysis, mobile apps.
