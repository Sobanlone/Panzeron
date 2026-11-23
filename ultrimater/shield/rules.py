"""Detection rule engine (pure Python, no dependencies).

A rule matches when enough GROUPS of patterns hit. Built-in rules use bounded regexes; USER rules (JSON files in the rules
folder) may only use literal strings, so a user-supplied rule can never cause catastrophic regex backtracking.
Every hit is reported with its offset so the finding can show exactly what matched. These are heuristics: severity and
confidence are deliberately conservative, and each rule explains what it does NOT prove.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..core.log import get_logger
from ..core.models import Confidence, Severity

log = get_logger("rules")
MAX_SCAN_BYTES = 4 * 1024 * 1024
FLAGS = re.I


def _wide(lit: str) -> bytes:
    return re.escape(lit.encode("utf-16le")).replace(b"\\ ", b" ")


def lit(text: str, wide: bool = False) -> re.Pattern[bytes]:
    """Case-insensitive literal; with wide=True also matches the UTF-16LE form (used in .lnk files, resources)."""
    alts = [re.escape(text.encode())]
    if wide:
        alts.append(re.escape(text.encode("utf-16le")))
    return re.compile(b"|".join(alts), FLAGS)


def rx(pattern: str) -> re.Pattern[bytes]:
    return re.compile(pattern.encode(), FLAGS)


@dataclass
class Group:
    patterns: list[tuple[str, re.Pattern[bytes]]]    # (label, compiled)
    min_hits: int = 1


@dataclass
class Rule:
    id: str
    name: str
    description: str          # plain language: what it means AND what it does not prove
    severity: Severity
    confidence: Confidence
    groups: list[Group]
    applies_ext: set[str] = field(default_factory=set)       # empty = any
    applies_family: set[str] = field(default_factory=set)    # empty = any
    max_size: int = 0                                          # 0 = no limit
    min_groups: int = 0                                        # 0 = all groups must match
    tags: list[str] = field(default_factory=list)              # e.g. MITRE ATT&CK ids
    precision: str = "medium"                                   # 'high' = the pattern is rarely innocent; 'medium' = also appears in docs/tools, severity is capped


@dataclass
class RuleHit:
    rule: Rule
    matches: list[tuple[str, int]]     # (label, offset)


def evaluate(rules: Iterable[Rule], name: str, ext: str, family: str | None, data: bytes) -> list[RuleHit]:
    out: list[RuleHit] = []
    window = data[:MAX_SCAN_BYTES]
    for r in rules:
        if r.applies_ext and ext not in r.applies_ext:
            continue
        if r.applies_family and family not in r.applies_family:
            continue
        if r.max_size and len(data) > r.max_size:
            continue
        matched_groups, matches = 0, []
        for g in r.groups:
            hits = []
            for label, pat in g.patterns:
                m = pat.search(window)
                if m:
                    hits.append((label, m.start()))
            if len(hits) >= g.min_hits:
                matched_groups += 1
                matches += hits
        need = r.min_groups or len(r.groups)
        if matched_groups >= need:
            out.append(RuleHit(r, matches))
    return out


S, C = Severity, Confidence
SCRIPT_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".sh", ".py"}
WEB_EXT = {".php", ".phtml", ".asp", ".aspx", ".jsp", ".jspx", ".cfm"}

BUILTIN_RULES: list[Rule] = [
    Rule("RL-RANSOM-NOTE", "Ransom-note language",
         "The text reads like a ransomware note. A real note means files may already be encrypted. Security awareness material can contain the same phrases, so check whether your files are actually unreadable.",
         S.HIGH, C.MEDIUM,
         [Group([("'your files are encrypted'", rx(r"(your|all)\s+(important\s+)?files\s+(have\s+been|are|were)\s+(encrypted|locked)")),
                 ("decrypt demand", rx(r"decrypt(ion)?\s+(your\s+)?(files|key|tool)")),
                 ("bitcoin payment", rx(r"(bitcoin|btc|monero|xmr)\s+(address|wallet|payment)|send\s+\d+(\.\d+)?\s*(btc|bitcoin)")),
                 ("tor contact", rx(r"tor\s+browser|\.onion")),
                 ("deadline threat", rx(r"(within|in)\s+\d+\s+(hours|days).{0,60}(price|double|lost|deleted|permanently)"))], min_hits=3)],
         max_size=200_000, tags=["T1486"]),
    Rule("RL-WEBSHELL", "Web-shell code pattern",
         "Server-side script that executes commands taken straight from web requests. This is how attackers keep remote control of a web server. A genuine admin tool could look similar, so confirm you wrote it.",
         S.HIGH, C.MEDIUM,
         [Group([("eval of request/base64", rx(r"eval\s*\(\s*(base64_decode|gzinflate|str_rot13|\$_(POST|GET|REQUEST|COOKIE))")),
                 ("command from request", rx(r"(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)")),
                 ("assert from request", rx(r"assert\s*\(\s*\$_(POST|GET|REQUEST)")),
                 ("ASP eval request", rx(r"eval\s*\(\s*request[\.\(]")),
                 ("JSP exec request", rx(r"Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter"))])],
         applies_ext=WEB_EXT, tags=["T1505.003"]),
    Rule("RL-MINER", "Cryptocurrency-miner indicators",
         "Strings used by cryptocurrency mining software. Miners that run without your knowledge steal CPU and power. Intentional mining tools match too.",
         S.MEDIUM, C.MEDIUM,
         [Group([("stratum pool URL", rx(r"stratum\+(tcp|ssl)://")), ("xmrig", lit("xmrig")), ("donate level flag", lit("--donate-level")),
                 ("cryptonight", lit("cryptonight")), ("randomx", lit("randomx")), ("monero wallet flag", rx(r"--(user|wallet)[= ]4[0-9AB][1-9A-HJ-NP-Za-km-z]{90,}"))], min_hits=2)],
         tags=["T1496"]),
    Rule("RL-CRED-DUMP", "Credential-dumping tool strings",
         "Strings of tools that extract passwords from Windows memory. They are used in attacks, but also in penetration tests and security training documents.",
         S.HIGH, C.MEDIUM,
         [Group([("sekurlsa", lit("sekurlsa::")), ("lsadump", lit("lsadump::")), ("mimikatz", lit("mimikatz")),
                 ("lsass minidump", rx(r"(procdump|comsvcs\.dll).{0,60}(lsass|minidump)")), ("kerberos ticket export", lit("kerberos::golden"))])],
         tags=["T1003"]),
    Rule("RL-REVSHELL", "Reverse-shell command",
         "A command that hands remote control of this computer to another machine. Legitimate only in penetration tests or when you wrote it yourself.",
         S.HIGH, C.MEDIUM,
         [Group([("bash /dev/tcp", rx(r"bash\s+-i\s*>&\s*/dev/tcp/")), ("netcat exec", rx(r"\bnc(\.exe)?\s+(-\w+\s+)*-e\s+(/bin/(ba)?sh|cmd)")),
                 ("python socket shell", rx(r"python[23]?\s+-c\s+.{0,80}socket.{0,120}(subprocess|pty\.spawn|dup2)")),
                 ("PowerShell TCPClient", rx(r"System\.Net\.Sockets\.TCPClient.{0,300}(GetStream|Invoke-Expression|iex)"))])],
         tags=["T1059"]),
    Rule("RL-LNK-LOLBIN", "Shortcut launches a script engine with risky arguments",
         "This shortcut starts PowerShell, mshta, wscript or similar with a download, encoded command or hidden window. Shortcuts are a common way to deliver malware in emails and archives.",
         S.HIGH, C.MEDIUM,
         [Group([(l, lit(l, wide=True)) for l in ("powershell", "mshta", "wscript", "cscript", "regsvr32", "rundll32", "cmd.exe")]),
          Group([("http download", lit("http", wide=True)), ("encoded command", lit("-enc", wide=True)), ("hidden window", lit("hidden", wide=True)),
                 ("bypass policy", lit("bypass", wide=True)), ("javascript:", lit("javascript:", wide=True)), ("frombase64", lit("frombase64", wide=True))])],
         applies_ext={".lnk"}, tags=["T1204.002"]),
    Rule("RL-KEYLOGGER-EXFIL", "Keylogging combined with sending data out",
         "Script that records keystrokes and also has code to upload or email data. Parental-control or accessibility tools can look similar.",
         S.MEDIUM, C.LOW,
         [Group([("GetAsyncKeyState", lit("GetAsyncKeyState")), ("SetWindowsHookEx", lit("SetWindowsHookEx")), ("pynput listener", lit("pynput")), ("keyboard hook", rx(r"keyboard\.on_press|on_key_press"))]),
          Group([("smtp mail", lit("smtplib")), ("http upload", rx(r"requests\.post|Invoke-WebRequest|UploadString|WebClient")), ("ftp upload", lit("ftplib")), ("discord/telegram webhook", rx(r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot"))])],
         applies_ext=SCRIPT_EXT, tags=["T1056.001"]),
    Rule("RL-PDF-ACTIVE", "PDF with automatic actions and script",
         "PDF that runs JavaScript or launches something when opened. Most PDFs have none; some forms use JavaScript legitimately.",
         S.MEDIUM, C.LOW,
         [Group([("JavaScript", rx(r"/(JavaScript|JS)\b"))]), Group([("OpenAction / AA", rx(r"/(OpenAction|AA)\b")), ("Launch action", rx(r"/Launch\b")), ("embedded file", rx(r"/EmbeddedFile\b"))])],
         applies_family={"pdf"}, tags=["T1204.002"]),
    Rule("RL-AUTORUN-INF", "Autorun.inf that launches a program",
         "An autorun.inf file that starts a program when a drive is opened. A classic way malware spreads through USB drives.",
         S.MEDIUM, C.MEDIUM,
         [Group([("[autorun] section", lit("[autorun]"))]), Group([("open=", rx(r"^\s*(open|shellexecute|shell\\\w+\\command)\s*=")), ("ShellExecute", lit("shellexecute"))])],
         applies_ext={".inf"}, max_size=20_000, tags=["T1091"]),
    Rule("RL-CERTUTIL-DROP", "Download-and-run using built-in Windows tools",
         "Uses certutil, bitsadmin or similar Windows tools to fetch a file, a technique attackers use to avoid detection. Administrators occasionally use the same commands.",
         S.MEDIUM, C.MEDIUM,
         [Group([("certutil download", rx(r"certutil(\.exe)?\s+.{0,40}-urlcache\s+.{0,20}-f")), ("bitsadmin download", rx(r"bitsadmin(\.exe)?\s+/transfer")),
                 ("curl/wget to temp", rx(r"(curl|wget)\s+.{0,80}(%temp%|\\appdata\\|/tmp/)")), ("msiexec remote", rx(r"msiexec(\.exe)?\s+.{0,20}/i\s+https?://"))])],
         applies_ext=SCRIPT_EXT | {".txt", ".lnk"}, tags=["T1105"]),
]


for _r in BUILTIN_RULES:   # rules whose patterns are rarely innocent keep their full severity; the rest are capped until corroborated
    _r.precision = "high" if _r.id in {"RL-RANSOM-NOTE", "RL-WEBSHELL", "RL-REVSHELL"} else "medium"


def load_user_rules(rules_dir: Path) -> tuple[list[Rule], list[str]]:
    """JSON rules, LITERAL STRINGS ONLY. Returns (rules, human-readable problems). Invalid files never stop a scan.
    Example file: {"id":"MY-1","name":"Internal marker","severity":"medium","confidence":"low","strings":["secret-project"],"min_hits":1,"extensions":[".txt"]}"""
    rules, problems = [], []
    if not rules_dir.is_dir():
        return rules, problems
    for f in sorted(rules_dir.glob("*.json"))[:200]:
        try:
            raw = json.loads(f.read_text(encoding="utf-8"))
            for spec in (raw if isinstance(raw, list) else [raw])[:100]:
                strings = [str(s) for s in spec["strings"]]
                if not strings or len(strings) > 200 or any(not s or len(s) > 300 for s in strings):
                    raise ValueError("'strings' must hold 1-200 non-empty strings of at most 300 characters")
                rules.append(Rule(
                    id="USER-" + re.sub(r"[^\w.-]", "_", str(spec["id"]))[:40], name=str(spec["name"])[:120],
                    description=str(spec.get("description", "Matched a rule you added."))[:400],
                    severity=Severity(spec.get("severity", "low")), confidence=Confidence(spec.get("confidence", "low")),
                    groups=[Group([(s[:60], lit(s)) for s in strings], min_hits=max(1, int(spec.get("min_hits", 1))))],
                    applies_ext={str(e).lower() for e in spec.get("extensions", [])}))
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
            problems.append(f"{f.name}: {e}")
            log.warning("invalid user rule file", extra={"ctx": {"file": f.name, "error": str(e)}})
    return rules, problems
