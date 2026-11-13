"""Deterministic compromise scanner.

Detection is deliberately NOT delegated to the model: these are byte-level
signatures, they must be reproducible, and a regex costs nothing next to an
inference call. Both signatures below come from confirmed real cases (hospital
names withheld):
  - Case A: foreign-language gambling article injected into the billing page's
    CMS content.
  - Case B: cloaked <marquee> backlink block injected sitewide via a wp_footer
    hook, hidden off-screen at 1px.
"""
from __future__ import annotations
import re

# Cloaking: off-screen / zero-size containers used to hide link blocks from
# humans while leaving them crawlable.
CLOAK = re.compile(
    r"(?:left\s*:\s*-\s*9{3,}px)"
    r"|(?:position\s*:\s*absolute\s*;[^\"'>]{0,120}?(?:height\s*:\s*1px|width\s*:\s*1px))"
    r"|(?:text-indent\s*:\s*-\s*\d{4,}px)",
    re.I,
)
MARQUEE = re.compile(r"<marquee", re.I)

# Spam vocabulary. Turkish/Russian black-hat SEO terms plus generic gambling.
SPAM_TERMS = re.compile(
    r"\b(?:hacklink|hack\s*link|backlink\s*sat|scommess\w*|scommezoid|casizoid"
    r"|marsbahis|casibom|бэклинк\w*|slot\s*gacor|situs\s*judi|togel)\b",
    re.I,
)
GAMBLING = re.compile(
    r"slot\s*machine|slots?\s*online|online\s*slots?"
    r"|online\s*casino|casino\s*online|casino\s*bonus|casino\s*siteleri"
    r"|sports?\s*betting|betting\s*site|betting\s*odds|bet(?:ting)?\s*bonus"
    r"|online\s*poker|poker\s*online"
    r"|bahis\s*siteleri|bahis\s*site|deneme\s*bonusu"
    r"|guvenilir\s*bahis|canli\s*casino",
    re.I)

# A parked / expired-domain page is not a compromise but IS a real problem: the
# hospital's domain has lapsed and someone else now controls what visitors see.
# Found on a lapsed hospital domain that now serves a domain-marketplace page.
PARKED = re.compile(
    r"expireddomains\.com|domain\s+(?:is\s+)?(?:for\s+sale|has\s+expired|expired)"
    r"|buy\s+this\s+domain|parked\s+(?:free\s+)?(?:at|by)|sedoparking|hugedomains"
    r"|this\s+domain\s+(?:is\s+)?available",
    re.I)

# Obfuscated JS — indicates a dropper rather than plain SEO spam.
OBFUSCATION = re.compile(r"\b(?:eval\s*\(|atob\s*\(|fromCharCode|document\.write\s*\(\s*unescape)", re.I)


# Cloaking classes with recognized accessibility names are never a compromise.
ACCESSIBILITY_CLASS = re.compile(
    r"screen-?reader-?text|visually-?hidden|sr-only|skip-?link|assistive-?text"
    r"|element-invisible|hidden-?accessible|show-on-focus", re.I)

# Extract the contents of a cloaked container so we can ask the decisive question:
# does anything actually LINK out from inside it? Both confirmed compromises put
# external links there (case B: 10 anchors; case C: a hidden div of them). Every benign case found so far -- skip-links, "top of page", comment-form
# labels, WordPress .screen-reader-text -- contains no links at all.
# NOTE: `display:none` is deliberately EXCLUDED here. It is ordinary UI -- JS-toggled
# alert bars, accordions, modals, event overlays -- and including it produced 25 false
# positives on a national run (a health system's accordion linking to medicare.gov, a
# hospital's own notice banner, a hidden event overlay linking to Google Maps).
# Off-screen / zero-size positioning is the anomalous form: it hides content from humans
# while leaving it crawlable, which is the entire point of a link-injection block.
CLOAKED_BLOCK = re.compile(
    r"<(?:div|span|p|section)[^>]*(?:left\s*:\s*-\s*9{3,}px"
    r"|text-indent\s*:\s*-\s*\d{4,}px"
    r"|position\s*:\s*absolute\s*;[^\"'>]{0,140}?(?:height\s*:\s*1px|width\s*:\s*1px))"
    r"[^>]*>(.{0,4000}?)</(?:div|span|p|section)>", re.I | re.S)
ANCHOR_HREF = re.compile(r'href=["\'](https?://[^"\']+)', re.I)


def _cloak_has_external_links(html: str, page_url: str) -> bool:
    from urllib.parse import urlparse
    own = urlparse(page_url).netloc.lower().replace("www.", "")
    for m in CLOAKED_BLOCK.finditer(html):
        for u in ANCHOR_HREF.findall(m.group(1)):
            h = urlparse(u).netloc.lower().replace("www.", "")
            if h and own and h != own and not h.endswith(own):
                return True
    return False


def scan(html: str, page_url: str) -> dict:
    """Return a finding dict. severity: none | low | high."""
    if not html:
        return {"severity": "none", "signals": [], "page": page_url, "detail": ""}

    signals, detail = [], []

    # Two distinct things, deliberately separated:
    #   cloak        = off-screen/zero-size positioning ANYWHERE on the page. Extremely
    #                  common as accessibility markup, so it is only a weak signal.
    #   hidden_links = a hidden container that actually contains EXTERNAL links. This is
    #                  the shape both confirmed compromises take, and no benign page
    #                  examined has ever had it. `display:none` containers are not counted
    #                  (see the CLOAKED_BLOCK note above).
    cloak = bool(CLOAK.search(html))
    hidden_links = _cloak_has_external_links(html, page_url)
    if cloak and not hidden_links:
        cloak = False          # bare cloaking is accessibility markup, not a finding
    marquee = bool(MARQUEE.search(html))
    spam_hits = SPAM_TERMS.findall(html)
    gambling_hits = GAMBLING.findall(html)
    obf = OBFUSCATION.findall(html)
    # A single atob(/eval( appears in ordinary minified analytics and embed
    # code on most modern sites. Only a cluster is meaningful, and even then
    # it never escalates on its own (see severity ladder below).
    obf_meaningful = len(obf) >= 4

    parked = bool(PARKED.search(html[:60000]))
    if parked:
        signals.append("domain_parked_or_expired")
    if spam_hits:
        signals.append("spam_vocabulary")
        detail.append(f"terms={sorted(set(t.lower() for t in spam_hits))[:6]}")
    if hidden_links:
        signals.append("hidden_external_links")
    if cloak:
        signals.append("cloaked_container")
    if marquee:
        signals.append("marquee_tag")
    if obf_meaningful:
        signals.append("obfuscated_js")
        detail.append(f"js={sorted(set(o.lower() for o in obf))[:4]}")
    # gambling words alone are weak — a hospital page may legitimately mention
    # "problem gambling" services — so only count them alongside another signal.
    if gambling_hits and (cloak or marquee or spam_hits):
        signals.append("gambling_vocabulary")

    # Severity ladder. Named spam vocabulary is the only definitive signal;
    # everything else is corroboration. Learned the hard way: cloaking alone is
    # usually a legitimate accessibility skip-link, and a lone atob() is normal
    # minified JS -- both produced false "high" verdicts on clean hospital sites.
    if hidden_links:
        sev = "high"                      # concealed block linking off-site: the shape
                                          # both confirmed compromises take
    elif spam_hits and (cloak or marquee):
        sev = "high"                      # case B signature: unambiguous
    elif spam_hits:
        sev = "high"                      # case A signature: injected article
    elif parked:
        sev = "high"                      # domain lapsed -- third party controls the site
    elif cloak and gambling_hits:
        sev = "high"                      # cloaked gambling PHRASES (not bare tokens)
    elif (cloak or marquee) and obf_meaningful:
        sev = "low"
    elif cloak or marquee or obf_meaningful:
        sev = "low"                       # ambiguous on its own -- review, do not report
    else:
        sev = "none"

    return {
        "severity": sev,
        "signals": signals,
        "page": page_url,
        "detail": "; ".join(detail)[:300],
    }


# A cloaked container present on essentially EVERY page, with no other signal,
# is a site-template accessibility skip-link -- not an injection. Measured on
# Vermont: 5 of 8 hospitals hit this, at 40/40, 40/40, 39/39, 33/40 and 27/31
# pages. Left unsuppressed it would put ~850 US hospitals in the review bucket.
# Real injections look different: case A was 2 of 396 pages (rare), and
# case B carried spam vocabulary and a <marquee> alongside the
# cloaking (corroborated) -- so neither is suppressed by this rule.
UBIQUITY_SUPPRESS = 0.80


def merge(findings: list[dict]) -> dict:
    """Collapse per-page findings into one hospital-level verdict."""
    rank = {"none": 0, "low": 1, "high": 2}
    worst = max(findings, key=lambda f: rank[f["severity"]], default=None) if findings else None
    if not worst or worst["severity"] == "none":
        return {"severity": "none", "pages_flagged": 0, "signals": [], "page": "", "detail": ""}
    flagged = [f for f in findings if f["severity"] != "none"]
    sigs = sorted({s for f in flagged for s in f["signals"]})
    sev = worst["severity"]
    note = ""

    # template-cloaking suppression (see UBIQUITY_SUPPRESS above)
    if (sev == "low" and sigs == ["cloaked_container"] and findings
            and len(flagged) / len(findings) >= UBIQUITY_SUPPRESS):
        sev = "none"
        note = (f"suppressed: cloaked container on {len(flagged)}/{len(findings)} pages "
                "with no corroborating signal — site-template accessibility pattern")

    return {
        "severity": sev,
        "pages_flagged": len(flagged),
        "pages_scanned": len(findings),
        "signals": sigs,
        "page": worst["page"],
        "detail": note or worst["detail"],
        "suppressed": bool(note),
    }