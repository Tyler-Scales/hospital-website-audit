"""Content checks for sites that block automated fetches, using recent Wayback Machine captures.

Pulls the most recent capture of up to CAP distinct pages captured since SINCE and runs the
same spam / hidden-link / malicious-JS checks scan.py runs on live pages. Cloaking cannot be
tested this way (the archive fetches as one client), so report these sites as archive-checked.
This is the alternative to getting past a bot wall: never try to get past one.

usage: python wayback_scan.py <domains...> --out <dir> [--since 20260501] [--cap 12]
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import archive  # noqa: E402
import scan  # noqa: E402  (shared detection patterns)


def check_body(body, url, allow):
    body = scan.COMMENT.sub(" ", body)
    flags = []
    txt = scan.text_of(body)
    for m in scan.SPAM.finditer(txt):
        s = max(0, m.start() - 80)
        flags.append(f"spam-text: {m.group(0)} :: {txt[s:m.end() + 80]}")
    for h in scan.HREF.findall(body):
        if scan.SPAM.search(urllib.parse.unquote(h).replace("-", " ")):
            flags.append(f"spam-href: {h[:160]}")
    if scan.CJK.search(txt):
        flags.append(f"cjk-text: {scan.CJK.search(txt).group(0)[:40]}")
    for tag, rx in scan.BADJS:
        m = rx.search(body)
        if m:
            flags.append(f"js-{tag}: {m.group(0)[:120]}")
    for m in re.finditer(r"<(div|span|p|section|font|ul)\b[^>]*style=[\"']([^\"']*)[\"'][^>]*>([\s\S]{0,4000}?)</\1>", body, re.I):
        if scan.HIDDEN.search(m.group(2)):
            outs = [h for h in scan.HREF.findall(m.group(3)) if h.startswith("http") and scan.reg_domain(urllib.parse.urlsplit(h).hostname) not in allow]
            if len(outs) >= 2 or any(scan.SPAM.search(o) for o in outs):
                flags.append(f"hidden-outbound-links: {outs[:6]}")
    scripts = sorted({urllib.parse.urljoin(url, s) for s in scan.SCRIPT_SRC.findall(body)})
    return sorted(set(flags)), scripts


def run(domain, outdir, since, cap):
    rows = archive.cdx(url=domain, matchType="domain", fl="timestamp,original,mimetype,statuscode",
                       filter=["statuscode:200", "mimetype:text/html"], **{"from": since}, limit=3000)
    latest = {}
    for ts, orig, mime, st in rows:
        key = re.sub(r"^https?://(www\.)?", "", orig).split("?")[0].rstrip("/").lower()
        if scan.SKIP.search(orig):
            continue
        if key not in latest or ts > latest[key][0]:
            latest[key] = (ts, orig)
    # homepage first, then the most recently captured pages
    keys = sorted(latest, key=lambda k: (k != domain and k != "www." + domain, -int(latest[k][0])))[:cap]
    pages = []
    for k in keys:
        ts, orig = latest[k]
        try:
            body = archive.get(archive.capture(ts, orig))
        except Exception as e:
            pages.append({"url": orig, "ts": ts, "error": str(e)})
            continue
        flags, scripts = check_body(body, orig, {domain})
        m = re.search(r"<title[^>]*>([\s\S]*?)</title>", body, re.I)
        pages.append({"url": orig, "ts": ts, "title": re.sub(r"\s+", " ", m.group(1)).strip()[:140] if m else "",
                      "flags": flags, "scripts": scripts, "len": len(body)})
        time.sleep(archive.PAUSE)
    out = {"domain": domain, "since": since, "captures_in_window": len(rows), "distinct_pages": len(latest), "pages": pages}
    with open(os.path.join(outdir, domain + ".json"), "w") as f:
        json.dump(out, f, indent=1)
    print(f"{domain}: {len(rows)} captures since {since}, {len(latest)} distinct pages, checked {len(pages)}, "
          f"flagged {sum(1 for p in pages if p.get('flags'))}, newest {max((p['ts'] for p in pages), default='-')}", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("domains", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--since", default="20260501")
    ap.add_argument("--cap", type=int, default=12)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for d in a.domains:
        try:
            run(d, a.out, a.since, a.cap)
        except Exception as e:
            print(f"{d}: failed {type(e).__name__}: {e}", flush=True)
