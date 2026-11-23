# Known limitations (read before demoing)

**Not implemented (and not claimed):**
* **Real-time protection.** Shield scans on demand. Windows Security provides real-time protection; Ultrimater only reports its status.
* Cloud hash reputation (VirusTotal etc.), scan scheduling, potentially-unwanted-application database, trained ML malware classifier, YARA rules.
* Face/logo/scene recognition. Schools are detected from text only ("… University"), by design (no identification of people).
* Hardware security integration (architecture allows it; nothing is simulated).

**Detection quality:**
* Shield finds exact known test signatures/hashes and a few static indicators. It will not catch real-world novel malware. Do not rely on it instead of Defender.
* Names are detected only when labelled ("Name:", "my name is"). Organisations only via fixed suffixes (University, High School, …). English-centric.
* Phone detection is format-based and can produce false positives on long digit groups.
* OCR quality depends on Tesseract and image clarity; **image redaction can miss text OCR missed** and says so. Cross-line PII is not redacted in images.
* Sentinel is rule-based: new scam wording can evade it. "No indicators found" never means "safe". Brand look-alike detection covers a small brand list.
* Registrable-domain logic is a heuristic (no full public-suffix list).
* The identifiability formula is a transparent heuristic, not a calibrated probability.

**Platform:**
* Windows-only features (Defender, Authenticode) are implemented through documented PowerShell interfaces but **could not be executed in the Linux build environment**; they are unit-tested with mocks only. Test them on Windows.
* Defender may delete or flag test fixtures it considers malicious. Ultrimater's fixtures use its own harmless marker; the EICAR string is built at runtime and is never written to disk by the tests.
* PDF text needs PyMuPDF or `pdftotext`; DOCX is supported; legacy `.doc`/XLSX are not.
* The graph layout is a simple force layout; it can look crowded above ~50 nodes.
* Single local user; no authentication beyond the per-launch token.

* **Glass rendering** depends on the window engine (Edge/Chromium, GPU-accelerated). On very old GPUs or with Windows *transparency effects* off, Ultrimater falls back to solid surfaces. Window-level Mica/Acrylic (blur of your desktop behind the window) is not available in Edge app mode; the glass blurs Ultrimater's own light field.
* Graph labels can overlap in dense areas; drag nodes or use the filter chips to declutter.

* **Slow-machine behaviour was simulated, not measured on your hardware.** A 4-second Windows Security lookup was injected in testing; real PowerShell timings on your PC are unmeasured. If tabs still feel slow, set Settings → Appearance → Glass quality = Lite and tell me.
* The GitHub Actions workflow and `create_shortcut.ps1` have not been run (Linux build environment). The workflow also runs this test suite on real Windows, which is the first Windows verification the project will get.

* Appearance settings are per Windows user and per install; there is no cloud sync. Imported themes can change appearance only (validated whitelist); unknown values are ignored.
* Custom fonts are limited to the four built-in system stacks (fonts installed on the PC). Bundling web fonts is deliberately avoided to keep the app fully offline.
* Very low-contrast custom accents (e.g. near-black on dark) are possible; the app adapts link and button text colours but cannot make every combination beautiful. Reset appearance restores defaults in one click.

## Antivirus capability: what this is and is not
* Ultrimater is a **static, read-only** scanner with heuristics. It does **not** run or emulate files, so it cannot see what a program does, and it will not catch novel or well-hidden malware that a commercial engine (with cloud reputation and behavioural monitoring) would. **Keep Windows Security on; Ultrimater complements it and does not replace it.**
* **No kernel-level real-time protection.** The Downloads watcher polls folders you approved (about every 3 s) while the app is open; it reports quickly but cannot block or terminate anything.
* Office macro source is stored compressed, so Ultrimater can confirm macros exist and spot some risky strings but cannot read all of what they do. Archives: ZIP only (no RAR/7z); encrypted contents cannot be inspected.
* PE analysis covers structure, entry point and imports, not code semantics. Scoring weights are conservative heuristics, not calibrated probabilities.
* **Entire-computer scans** skip the Windows folder and other protected locations by default, and cannot read folders that need administrator rights (they are listed in the coverage report). A full scan in Smart mode is a quick-check for large media files; use Deep for everything.
* Not verified in the Linux build environment (needs a Windows run): the native file/folder dialogs, startup-item reading from the registry, hosts-file location, Authenticode validation, and real scan throughput on your disk.
* Custom rules are literal-text only by design (they can never slow down or break a scan).

## Danger levels and self-trust: known limits
* The integrity manifest protects against accidental flagging and casual tampering, **not** against an attacker who can write to Ultrimater's folder (they could rewrite the manifest too). Code-signing the installer is the real fix and is not done.
* "Looks like a ruleset" downgrades a file that matches three or more unrelated rule families to Info. A real attack toolkit could hit that too; the other checks (PE structure, scripts, hashes, archives) still run independently, but rule-only evidence in such a file is reported as Info.
* The scan cache is stat-based (path, size, modified time) like most antivirus caches; a file altered while preserving its timestamp would be skipped until the rules or hash lists change. Deep mode bypasses it.
* Severity weights and caps are conservative heuristics tuned on this project's tests, not calibrated against a large malware corpus.

## Design and data honesty
* The dashboard shows only real data. The sample data (Settings → Protection & privacy → Demonstration data) is synthetic, labelled as such, and removable; its simulated threat is a harmless marker file.
* The diagnostics benchmark uses synthetic files in a temporary folder; real scan speed on your disk will differ.
* The Windows-only diagnostics (PowerShell timing, Windows Security) report "not Windows" on other systems rather than guessing.

## Browser protection

* It reads only what you allow (downloads, recent addresses, extensions, homepage/start-up pages) and only from the browser you choose. It deliberately does **not** read saved passwords, cookies/sessions, autofill or page contents, so it cannot "see everything" the browser holds.
* Browser data formats change between versions. If a database cannot be read (for example because the browser has it locked), the check says so and retries; it never guesses.
* Link screening is rule-based (look-alike domains, raw IPs, shorteners, ...). It cannot know whether a site is genuinely malicious, and it does not check a reputation service (nothing leaves your computer).
* Extension findings are prompts to review, not verdicts: ad blockers and password managers legitimately hold broad permissions.
* Not verified on a real Windows profile in the build environment; the default-browser lookup uses the Windows registry and needs a run on your PC.

## Gmail protection

* Verified only against a local stand-in for Google's endpoints. It has not been run against real Google; expect to debug the first sign-in on your PC.
* You must create your own free Google client ID (Google Cloud project, Gmail API, OAuth consent screen with yourself as a test user, Desktop-app credential). Google marks apps in "Testing" as unverified and expires their sign-ins after 7 days, so you may need to reconnect weekly unless you publish the client yourself.
* `gmail.readonly` is a Google "restricted" scope. That is fine for your own account with your own client ID; distributing Ultrimater to other people with a shared client ID would require Google's verification and security assessment.
* Read-only by design: it can flag a message but cannot move, delete or report it. You do that in Gmail.
* Screening is rule-based (look-alike senders, Reply-To mismatch, failed SPF/DKIM/DMARC, urgent credential/payment language, risky links); it will miss well-written scams and can flag odd but harmless mail.
* The refresh token is encrypted with Windows DPAPI; on other platforms it is only encoded and protected by file permissions.
* Only the inbox is checked (last 7 days at first, then new mail, up to 100 messages per check). Spam, other labels and attachments are not read.
