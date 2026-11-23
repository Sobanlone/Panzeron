"""Panzeron SENTINEL: scam / phishing analysis.

Deterministic indicators produce the verdict. An optional local LLM may ADD an explanation and may raise
"no indicators" to "suspicious" (labelled AI-assessed) but can never lower a deterministic verdict and can
never declare content "safe". Output is never binary: assessments include "insufficient evidence".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, parse_qs

from ..ai.provider import LLMProvider, ProviderError, validate_scam_judgement
from ..core.log import get_logger
from ..core.models import (Confidence, Entity, Evidence, EvidenceTier as T, Finding, Module, Severity, make_entity)
from ..vision import pii

log = get_logger("sentinel")

STRONG, MEDIUM, WEAK = 3, 2, 1

BRANDS = {
    "paypal": {"paypal.com"}, "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"},
    "google": {"google.com", "gmail.com", "youtube.com"}, "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in"}, "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"}, "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"}, "dhl": {"dhl.com"}, "fedex": {"fedex.com"}, "linkedin": {"linkedin.com"},
    "easypaisa": {"easypaisa.com.pk"}, "jazzcash": {"jazzcash.com.pk"}, "hbl": {"hbl.com"},
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "gq", "tk", "ml", "cf", "work", "support", "country", "loan", "rest", "icu"}
TWO_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}

URL_RX = re.compile(r"(?i)\bhttps?://[^\s<>\"')\]]+")

TEXT_RULES: list[tuple[str, int, re.Pattern[str], str]] = [
    ("urgency", MEDIUM, re.compile(r"(?i)\b(urgent(ly)?|immediately|act now|within \d+ ?(hours?|hrs?|minutes?)|final (notice|warning)|expires? (today|soon)|last chance|right away)\b"),
     "Artificial urgency pressures you to act before thinking"),
    ("threat", MEDIUM, re.compile(r"(?i)\b(account (will be |has been )?(suspended|closed|locked|terminated|disabled|limited)|legal action|you will be (arrested|fined)|unauthori[sz]ed (login|access|activity))"),
     "Threat of account loss or penalty"),
    ("credential_request", STRONG, re.compile(r"(?i)(verify your (account|identity|password|details)|confirm your (password|login|credentials|identity|details)|enter your (password|pin|otp|card)|log ?in to (verify|confirm|restore|secure)|update your (payment|billing) (details|information))"),
     "Asks you to verify or enter credentials"),
    ("otp_request", STRONG, re.compile(r"(?i)(share|send|tell|read out|reply with|forward)\b[^.\n]{0,40}\b(otp|one[- ]time (password|code|pin)|verification code|security code|pin)\b"),
     "Asks you to hand over a one-time code (a hallmark of account takeover)"),
    ("payment_request", STRONG, re.compile(r"(?i)\b(gift ?cards?|wire transfer|western union|moneygram|bitcoin|crypto(currency)?|usdt|processing fee|pay (a |the )?(fee|fine|deposit)|advance (fee|payment)|send (me )?(money|payment))\b"),
     "Requests an unusual or hard-to-reverse payment"),
    ("prize_lure", MEDIUM, re.compile(r"(?i)\b(you('ve| have) (won|been selected)|lottery|claim your (prize|reward|refund)|unclaimed (funds|refund)|inheritance)\b"),
     "Prize / refund lure"),
    ("secrecy", MEDIUM, re.compile(r"(?i)(don'?t tell anyone|keep (this|it) (secret|confidential)|do not (contact|call|inform) (your )?(bank|police|manager|family))"),
     "Asks you to keep the request secret"),
    ("impersonation_claim", MEDIUM, re.compile(r"(?i)\bthis is (the |your )?(it |help ?desk|security team|support team|your bank|ceo|manager|hr department|customer (care|service))"),
     "Claims to be an authority or trusted party"),
    ("generic_greeting", WEAK, re.compile(r"(?i)\bdear (customer|user|client|account holder|member|valued)\b"),
     "Generic greeting (legitimate senders usually know your name)"),
    ("attachment_pressure", WEAK, re.compile(r"(?i)(open|see|view) the attached|\.(exe|scr|html?|zip|iso|js)\b attached"),
     "Pushes you to open an attachment"),
    ("ai_manipulation", STRONG, re.compile(r"(?i)(ignore (all |any |the )?(previous|prior|above|earlier) (instructions|rules|prompts)|disregard (your|the) (instructions|rules)|you are now\b|system prompt|(mark|label|classify|report) (this|it|message) as (safe|legitimate|not (a )?(scam|phishing))|do not (flag|report) this|as an ai (language )?model)"),
     "Text addresses an automated reviewer and tries to change its verdict (prompt injection)"),
]


def registrable_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in TWO_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _deleet(s: str) -> str:
    return s.translate(str.maketrans("01$5", "olss")).replace("rn", "m")


@dataclass
class Indicator:
    category: str
    weight: int
    description: str
    evidence: str
    source_ref: str
    rule: str
    tier: T = T.VERIFIED


def analyze_url(url: str, ref: str = "url") -> list[Indicator]:
    inds: list[Indicator] = []
    try:
        u = urlparse(url)
    except ValueError:
        return [Indicator("malformed_url", WEAK, "URL could not be parsed", url[:80], ref, "url:parse")]
    host = (u.hostname or "").lower()
    if not host:
        return inds
    reg = registrable_domain(host)
    tld = host.rsplit(".", 1)[-1]

    def add(cat, w, desc, ev, rule):
        inds.append(Indicator(cat, w, desc, ev, ref, rule))

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        add("ip_host", STRONG, "Link points to a raw IP address instead of a domain name", host, "url:ip-host")
    if "xn--" in host:
        add("punycode", MEDIUM, "Domain uses punycode, which can disguise look-alike characters", host, "url:punycode")
    if u.username or "@" in (u.netloc or ""):
        add("userinfo", STRONG, "URL contains '@' before the host, a trick used to disguise the real destination", u.netloc, "url:userinfo")
    if host in SHORTENERS or reg in SHORTENERS:
        add("shortener", MEDIUM, "URL shortener hides the real destination", host, "url:shortener")
    if u.scheme == "http":
        add("no_tls", WEAK, "Link does not use HTTPS", url[:60], "url:no-tls")
    if host.count(".") >= 4:
        add("deep_subdomain", WEAK, "Unusually many subdomain levels", host, "url:subdomains")
    if len(url) > 100:
        add("long_url", WEAK, "Very long URL", f"{len(url)} characters", "url:length")
    if tld in RISKY_TLDS:
        add("risky_tld", WEAK, f"'.{tld}' is a top-level domain frequently abused (also used legitimately)", host, "url:tld")
    for brand, official in BRANDS.items():
        labels = [_deleet(x) for x in host.split(".")]
        raw_has = brand in host
        deleet_has = any(brand in l for l in labels)
        if (raw_has or deleet_has) and reg not in official:
            kind = "look-alike spelling of" if (deleet_has and not raw_has) else "mentions"
            add("brand_impersonation", STRONG,
                f"Domain {kind} '{brand}' but its real registered domain is '{reg}', not an official {brand} domain",
                host, "url:brand-mismatch")
            break
    if re.search(r"(?i)(login|signin|verify|secure|account|update|confirm|wallet|password)", u.path + "?" + (u.query or "")):
        add("credential_path", WEAK, "URL path suggests a login or verification page", u.path[:60], "url:path-keywords")
    qs = parse_qs(u.query)
    if any(v and re.match(r"(?i)https?://", v[0]) for v in qs.values()):
        add("open_redirect", WEAK, "URL carries another URL as a parameter (possible redirect)", u.query[:60], "url:redirect-param")
    return inds


def analyze_headers(text: str, ref: str) -> list[Indicator]:
    inds: list[Indicator] = []
    hdr = {}
    for m in re.finditer(r"(?im)^(from|reply-to|return-path|authentication-results)\s*:\s*(.+)$", text):
        hdr[m.group(1).lower()] = m.group(2).strip()
    if not hdr:
        return inds
    frm = hdr.get("from", "")
    fm = re.search(r"([\w.+-]+@[\w.-]+\.\w+)", frm)
    f_dom = registrable_domain(fm.group(1).split("@")[1]) if fm else ""
    rt = re.search(r"([\w.+-]+@[\w.-]+\.\w+)", hdr.get("reply-to", ""))
    if rt and f_dom and registrable_domain(rt.group(1).split("@")[1]) != f_dom:
        inds.append(Indicator("reply_to_mismatch", MEDIUM, "Reply-To domain differs from the From domain",
                              f"From {f_dom} / Reply-To {registrable_domain(rt.group(1).split('@')[1])}", ref, "hdr:reply-to"))
    disp = re.sub(r"<.*?>", "", frm).lower()
    for brand, official in BRANDS.items():
        if brand in disp and f_dom and f_dom not in official:
            inds.append(Indicator("display_name_spoof", STRONG,
                                  f"Display name mentions '{brand}' but the sender domain is '{f_dom}'", frm[:80], ref, "hdr:display-name"))
            break
    auth = hdr.get("authentication-results", "")
    fails = re.findall(r"(?i)\b(spf|dkim|dmarc)=(fail|softfail|none)\b", auth)
    if fails:
        inds.append(Indicator("auth_failure", STRONG, "Email authentication check failed: " + ", ".join(f"{a}={b}" for a, b in fails),
                              auth[:100], ref, "hdr:auth-results",
                              T.VERIFIED))
    return inds


@dataclass
class Assessment:
    verdict: str            # likely_scam | suspicious | insufficient_evidence | no_indicators_found
    confidence: Confidence
    score: int
    categories: int
    indicators: list[Indicator]
    explanation: str
    recommended_action: str
    ai: dict[str, Any] | None = None
    ai_note: str = ""
    finding: Finding | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "confidence": self.confidence.value, "score": self.score,
                "distinct_categories": self.categories, "explanation": self.explanation,
                "recommended_action": self.recommended_action,
                "indicators": [{"category": i.category, "weight": i.weight, "description": i.description,
                                "evidence": i.evidence, "source_ref": i.source_ref, "rule": i.rule, "tier": i.tier.value}
                               for i in self.indicators],
                "ai": self.ai, "ai_note": self.ai_note, "finding": self.finding.to_dict() if self.finding else None,
                "scoring_rule": "score = sum of the strongest weight per category (strong=3, medium=2, weak=1). "
                                "likely_scam: score>=7 and >=3 categories (high) or score>=5 and >=2 categories (medium); "
                                "suspicious: score>=3; insufficient_evidence: score 1-2; otherwise no_indicators_found."}


def _score(inds: list[Indicator]) -> tuple[int, int]:
    best: dict[str, int] = {}
    for i in inds:
        best[i.category] = max(best.get(i.category, 0), i.weight)
    return sum(best.values()), len(best)


def _verdict(score: int, cats: int) -> tuple[str, Confidence]:
    if score >= 7 and cats >= 3:
        return "likely_scam", Confidence.HIGH
    if score >= 5 and cats >= 2:
        return "likely_scam", Confidence.MEDIUM
    if score >= 3:
        return "suspicious", (Confidence.MEDIUM if cats >= 2 else Confidence.LOW)
    if score >= 1:
        return "insufficient_evidence", Confidence.LOW
    return "no_indicators_found", Confidence.LOW


_ACTIONS = {
    "likely_scam": "Do not click links, open attachments, reply, or send money or codes. Block the sender and report it. If you already acted, change the affected passwords and contact your bank.",
    "suspicious": "Do not click links or share information. Verify the sender through an independent channel (call the organisation using a number from its official website).",
    "insufficient_evidence": "Only weak signals were found. Verify through an official channel before acting on any request for money or information.",
    "no_indicators_found": "No scam indicators were found. This does NOT prove the message is safe; Panzeron cannot verify who sent it. Stay cautious with unexpected requests.",
}
_SEV = {"likely_scam": Severity.HIGH, "suspicious": Severity.MEDIUM, "insufficient_evidence": Severity.LOW, "no_indicators_found": Severity.INFO}

AI_SYSTEM = ("Assess whether the message is a scam or phishing attempt. Return JSON: "
             '{"likelihood":"low|medium|high","intent":"one sentence on what the sender wants","reasons":["short reason", "..."]}')


def analyze(text: str, salt: bytes, source: str = "pasted message", provider: LLMProvider | None = None) -> Assessment:
    text = text.strip()
    inds: list[Indicator] = []
    for cat, weight, rx, desc in TEXT_RULES:
        m = rx.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            inds.append(Indicator(cat, weight, desc, f"“{m.group()[:80]}”", f"{source} @ line {line}", f"text:{cat}"))
    urls = list(dict.fromkeys(URL_RX.findall(text) + (
        [text] if re.fullmatch(r"(?i)(https?://)?[\w.-]+\.[a-z]{2,}(/\S*)?", text) and "\n" not in text else [])))
    for i, url in enumerate(urls[:10]):
        full = url if re.match(r"(?i)https?://", url) else "http://" + url
        inds += analyze_url(full, f"{source} @ URL {i + 1}")
    inds += analyze_headers(text, source)

    # Entities: reuse the same detectors as Vision so findings link across modules in the exposure graph
    ents: dict[str, Entity] = {}
    for h in pii.detect(text):
        if h.kind in ("email", "phone", "username", "person_name", "org", "location"):
            e = make_entity(h.kind, h.raw, salt, h.subtype)
            ents[e.id] = e
    greet = re.search(r"(?m)\b(?:Dear|Hi|Hello|Hey)\s+([A-Z][a-z]{2,})\b(?!\s+(?:customer|user|client|member))", text)
    if greet and greet.group(1) not in ("Sir", "Madam", "Team", "All", "There"):
        e = make_entity("person_name", greet.group(1), salt, "greeting")
        ents[e.id] = e
    for url in urls[:10]:
        host = urlparse(url if re.match(r"(?i)https?://", url) else "http://" + url).hostname
        if host:
            e = make_entity("url", host, salt)
            e.display_masked = host
            ents[e.id] = e

    score, cats = _score(inds)
    verdict, conf = _verdict(score, cats)
    a = Assessment(verdict, conf, score, cats, inds, "", _ACTIONS[verdict])

    # Optional, strictly additive AI step
    if provider is not None:
        try:
            j = validate_scam_judgement(provider.generate_json(AI_SYSTEM, text, "Analyse the message below."))
            a.ai = j
            if j["likelihood"] == "high" and verdict in ("no_indicators_found", "insufficient_evidence"):
                a.verdict, a.confidence = "suspicious", Confidence.LOW
                a.ai_note = "The language model judged this message likely to be a scam although no deterministic indicator fired; verdict raised to 'suspicious' (AI-assessed, low confidence)."
            else:
                a.ai_note = "Model commentary added; it cannot lower or override the deterministic assessment."
        except ProviderError as e:
            a.ai_note = f"AI step skipped: {e}. The assessment above is fully deterministic."

    cat_names = sorted({i.category for i in inds})
    a.explanation = (f"{len(inds)} indicator(s) across {cats} categor{'y' if cats == 1 else 'ies'} (score {score}): "
                     f"{', '.join(c.replace('_', ' ') for c in cat_names) or 'none'}. ") + (
        "Indicators come from fixed, inspectable rules." if inds else "No fixed rule matched.")

    if a.verdict != "no_indicators_found":
        evid = [Evidence(f"{i.description}: {i.evidence}", i.source_ref, i.rule, i.tier) for i in inds]
        evid.append(Evidence(f"Scoring rule: score {score} from {cats} categor{'y' if cats == 1 else 'ies'} → {verdict}",
                             source, "rule:SN-SCORE", T.DERIVED))
        if a.ai:
            evid.append(Evidence(f"Model view: likelihood {a.ai['likelihood']}. {a.ai['intent']} {' '.join(a.ai['reasons'])}".strip(),
                                 source, f"ai:{getattr(provider, 'name', 'llm')}", T.AI_ASSESSED))
        a.finding = Finding(Module.SENTINEL, {"likely_scam": "Likely scam or phishing attempt", "suspicious": "Suspicious message",
                                              "insufficient_evidence": "Weak scam signals in message"}[a.verdict],
                            _SEV[a.verdict], a.confidence, a.explanation + " " + _ACTIONS[a.verdict], evid, source,
                            list(ents.values()), [_ACTIONS[a.verdict]], category=f"sentinel.{a.verdict}")
    return a
