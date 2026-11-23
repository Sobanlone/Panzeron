# Panzeron — protect the device, the identity, the person

A local-first digital protection platform. Antivirus tools look at *objects* (files, URLs); harm to people usually comes from
*combinations of exposure and manipulation*. Panzeron analyses files, screenshots, documents and messages on your device,
links the findings into an **exposure graph**, and explains every conclusion with its evidence and how strong that evidence is.

> Status: v0.1.0 working prototype for the Microsoft/The Garage "AI that Protects" track. See `docs/FEATURE_STATUS.md` for
> exactly what works today, and `docs/LIMITATIONS.md` for what does not.

## Install and run (Windows 11)

Panzeron is a desktop application: it opens in its own window (no browser tabs or address bar), has its own icon, and closing the window quits it.
Pick whichever route suits you:

**1. Get a real installer without installing any tools (easiest).** Push this folder to a GitHub repository, open the **Actions** tab,
run **Build Windows app**, and download `Panzeron-Setup-0.1.0.exe` (and a portable zip) from the finished run. Double-click it: per-user install, Start menu + optional desktop shortcut. Tag a version (`git tag v0.1.0 && git push --tags`) and the installer is also attached to a **GitHub Release**, which gives you a public download link to share.

**2. Build the installer on your own PC.** With Python 3.11+ installed, double-click `build_windows.bat`. It produces `dist\Panzeron\Panzeron.exe`, a portable `dist\Panzeron-portable-0.1.0.zip` and,
if [Inno Setup](https://jrsoftware.org/isinfo.php) is installed, `installer\Output\Panzeron-Setup-0.1.0.exe`.

**3. Run it right now from the folder (no build).** Double-click `Create Desktop Shortcut.bat` once. You get an **Panzeron** icon on your Desktop and in the Start menu
that launches the app with no console window. (Or double-click `Panzeron.pyw` directly.)

The window is rendered by Microsoft Edge's engine (WebView2/Chromium, included in Windows 11), the same technology behind apps like VS Code and Teams. Chrome is used if Edge is absent.
Developer mode: `python -m panzeron --server-only` serves on localhost and opens a normal browser tab.

The core needs no `pip install`. For image/OCR/PDF capability:

```
pip install -r requirements.txt     # Pillow + pytesseract (images/OCR/EXIF), PyMuPDF (PDF text)
```
Plus the **Tesseract OCR engine** (https://github.com/UB-Mannheim/tesseract/wiki) for reading text inside images, and
**Ollama** (https://ollama.com) with `ollama pull qwen2.5:3b` for optional local AI commentary. Everything degrades
gracefully and the app tells you what is missing; nothing pretends to work. User data lives in `%LOCALAPPDATA%\Panzeron`.

First look: click **Load synthetic demo data** on the Home. It creates harmless fictional files for the persona
"Maya Khan" and runs them through the *real* analyzers.

## The interface: floating liquid glass

A near-black field lit by soft blue, violet, teal and crimson light; a blue glass sidebar and a floating glass header bar; rounded translucent cards with a bright top edge; pill buttons and status chips; a dark/light toggle in the header (remembered on this device). **Nothing on screen is invented**: every number, status and label comes from the real engine (unavailable things say "Unavailable", never zero). The synthetic sample data is optional, labelled synthetic, and loads from the header button on the Home (removal is in Settings). The rules that matter (rounded tokens, glass material, working theme toggle, no invented claims) are enforced by `tests/test_design_rules.py`.

## Make it yours: Settings → Appearance

Applies instantly and is remembered (also by the engine, so it survives a cleared browser profile):

* **7 royal themes:** Royal, Sapphire, Gold, Emerald, Platinum, Obsidian, Crimson Ops.
* **Colour:** 8 accents or any custom colour (button text adapts for readability), 7 cool background light-fields, pure black.
* **Glass:** quality (Automatic / Full / Lite), blur 0–40 px, tint, pointer highlight.
* **Layout & type:** density, content width, sidebar (full / icons only), font, text size, animations.
* **Share or back up:** export / copy / import a theme file (validated), reset to defaults.

## Startup: the dragon and starting with Windows

* **Startup intro.** The orb ignites and a Matrix-style cyber dragon flies around it in 3D perspective, passing in front and behind the ball. The dragon uses the supplied Matrix artwork with animated green code rain and a depth-scaled flight loop. Click, Enter, Space or Esc skips it. The regular Panzeron mascot remains painted in your **accent colour** in Settings → Appearance. The **app icon** (`assets/panzeron.ico`: exe, installer, desktop and Start-menu shortcuts, plus the window/taskbar icon) uses the Panzeron dragon artwork.
* **It never traps you.** If a script fails or the engine does not answer, the intro still ends (at most 7 s; a second failsafe at 9 s does not depend on the app script). When Windows has reduced motion on, you get a still splash with no movement instead of nothing. It is off when *Startup animation* or *Interface animations* is off (Settings → Appearance → Startup; *Replay intro* previews it).
* **Start when I sign in to Windows** (per-user, off by default). If you once switched Panzeron off in Task Manager › Startup apps, Windows ignores the entry; Settings now says so and turning the option on clears that block for Panzeron only. If the entry points at an old location, Settings tells you to switch it off and on to repair it.

## Scale and reliability

* **Fix & review at scale:** server-side search, severity chips with live counts, area filter, sorting, pagination, per-row selection, *Select all N matching*, and bulk actions (resolve, false positive, reopen, quarantine files). Row actions load only when a row is opened.
* **Diagnostics (Settings → Diagnostics):** 15 real checks with timings (app window, file dialogs, OCR, PowerShell startup, Windows Security access, database, audit chain, integrity), a built-in **scanner self-test**, a synthetic scan-speed benchmark, and a copyable report with your user name and folders masked. Run it first on a new computer.
* **Robustness:** every parser is fuzz-tested with random, truncated and mutated data, and every text analyser is tested against inputs built to make regexes backtrack; a corrupted archive can never crash a scan.

## Browser protection (you decide, and can switch it off any time)

On **Shield → Browser protection**, press *Allow browser protection…*. Panzeron detects your main browser (Windows default; Chrome, Edge, Brave, Vivaldi, Opera or Firefox), shows exactly which files it would read, and reads nothing until you confirm. You pick what it may look at, all on by default:

* **Downloads:** scans new downloads, surfaces the browser's own "dangerous download" flags.
* **Recent addresses:** screens visited links for phishing and look-alike sites (only risky ones are kept, without query strings).
* **Extensions:** lists extensions that can see or change all your browsing, or that change your search/homepage.
* **Homepage & start-up:** flags a hijacked homepage.

With **Automatic** on (the default), it does this at start-up and about every 15 minutes while Panzeron is open, adds the browser's download folder to the Downloads watcher and to Quick scans, and shows the status on the Home. It never reads saved passwords, cookies, autofill or page contents. *Turn off* stops it immediately; every grant, check and revoke is in the audit log.

## Gmail protection (connect it yourself, disconnect any time)

On **Check a message → Gmail protection**, add your own Google client ID (the card walks you through it), press *Connect Gmail…*, read the permission sheet, and sign in on Google's own page. Panzeron asks for **read-only** access (`gmail.readonly`): it cannot send, delete, move or change mail. It screens recent inbox mail with the same fixed Sentinel rules as the Threat page, locally, at start-up and about every 15 minutes in Automatic mode, and keeps **only findings** (never message bodies or subjects). The sign-in is encrypted with Windows DPAPI. *Disconnect* deletes it and asks Google to revoke it.

## Protection: what Shield does

**Choose what to scan with the real Windows dialogs:** *Choose a folder…* / *Choose files…* open the native file and folder pickers (no typing paths; manual entry remains as a fallback if a dialog cannot open).

**Permission first.** Anything broader than what you picked yourself needs your explicit approval, enforced by the engine (not just the UI) and written to the audit log:

| Choice | What is read | Permission |
|---|---|---|
| Quick scan | Downloads, Desktop, Documents, temp and startup folders | asks, listing the exact folders |
| My user folders | Your whole Windows profile | asks |
| Entire computer | Every internal drive except protected Windows system files | asks, listing what is skipped and why |
| Folder / files you pick | Just those | no extra prompt: you chose them |

**Detection (static and read-only; nothing is executed):** exact signatures and known-bad hash lists you import; Windows program (PE) structure, entry point and **import-table** analysis; hidden PowerShell `-EncodedCommand` payloads are decoded and inspected; a rule engine (ransom notes, web shells, miners, credential-dumper strings, reverse shells, risky shortcuts, download-and-run tricks, keylogger+exfiltration, PDF auto-actions, autorun.inf); inside ZIP archives (disguised programs, nested archives, bombs, password-protected contents); Office macros, remote templates and DDE; startup items and the hosts file; plus an optional **Downloads watcher** for new files in folders you approve.

**Trustworthy danger levels (not alarmism):**
* **Panzeron never flags its own files.** They contain the very strings a scanner looks for, so Panzeron recognises them by their **SHA-256 hash** against a shipped manifest (not by folder name, which malware could imitate). A file that no longer matches is reported as *modified* (tamper detection) and Panzeron's own files can never be quarantined. Check or rebuild trust in Settings → Protection → *Panzeron's own files*.
* **A test file is not a danger.** The EICAR/Panzeron test strings count as a test file only when the file is just that string (the EICAR specification); inside a larger file it is a harmless mention. Test files get a calm *"Only antivirus test files found"* verdict. The demo's *simulated* threat is clearly labelled SIMULATED.
* **One weak signal never reaches High.** Rules whose patterns also appear in documentation are capped at Medium, source-code files are lowered one level, files that match several unrelated attack families look like rule files or research notes (Info), and severity rises only when **independent kinds of check agree**. Every adjustment is written into the finding's evidence.
* **You stay in control:** *Trust this exact file* remembers a file's hash so that exact content is never flagged again (changed files are re-checked). Panzeron's quarantine vault and demo data are skipped in broad scans.
* **Faster repeat scans:** unchanged files that were clean last time are skipped (never files with findings; Deep mode re-reads everything).

**Speed and honesty:** multithreaded; *Smart* mode reads programs, scripts, documents and archives in full and quick-checks big media files, *Deep* reads everything. Every scan ends with a **coverage report** (read in full, quick-checked, skipped locations and why, access denied, unreadable).

## What it does

| Module | What is real today |
|---|---|
| **Shield** | Threaded scans with scopes and a permission model, native file/folder pickers, signatures + imported hash lists, PE import analysis, decoded script payloads, rule engine, archive/Office inspection, startup & hosts review, Downloads watcher, exclusions, history, coverage reports, reversible (bulk) quarantine, read-only Windows Defender status/detections, user-triggered Defender scan |
| **Vision** | PII/credential/location detection (regex + Luhn/IBAN/mod-97 validators), EXIF GPS & device metadata, DOCX author properties, OCR on images, PDF text, masked values only, redacted/metadata-free **copies** |
| **Inference** | Cross-source entity linking via salted hashes, 6 transparent rules, published identifiability formula, labelled hypotheses |
| **Sentinel** | URL, text, header and prompt-injection indicators; ordinal confidence; "insufficient evidence" is a valid answer; optional local LLM that can add but never lower or declare safe |
| **Graph** | Interactive SVG exposure graph, evidence panel per node, edges tagged with the rule that created them |
| **Response** | Prioritised findings, confirmation-gated actions, restore, false-positive reporting, re-assessment, action history |
| **Settings/History** | AI config, exclusions, privacy controls, scan history, hash-chained audit log, JSON report export |

## The evidence-tier model (the core idea)

Every finding and every piece of evidence carries a tier, shown in the UI:

* **verified**: deterministic and reproducible (byte match, checksum, EXIF field)
* **derived**: a fixed rule applied to verified facts
* **ai_assessed**: a model's judgement (code *prevents* AI output from ranking above this)
* **speculative**: a hypothesis, always labelled

Confidence is ordinal (low/medium/high), never a made-up percentage.

## Safety and privacy by design

* Binds to `127.0.0.1` only, per-launch session token, Host-header check, no CORS.
* Raw sensitive values are **never stored**: only masked forms and salted hashes.
* Nothing is executed. Nothing is deleted: quarantine copies, verifies a hash, then moves; restore never overwrites.
* Redaction and EXIF stripping write copies; originals are untouched.
* Windows Defender is never disabled or reconfigured.
* A non-local AI host is refused unless you explicitly consent in Settings.
* The audit log is a hash chain; tampering is detected and shown.

## Tests

```
python -m unittest discover -s tests -t .      # 183 tests (1 skipped when run as root), standard library only
python scripts/ui_smoke.py                     # real-browser smoke test (needs: pip install playwright; playwright install chromium)
```
