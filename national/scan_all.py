#!/usr/bin/env python3
"""Scan every CAH website for compromise. Deterministic — no model calls.

This is the scanner from the national critical access hospital study (August 2026).
It reads a roster of hospitals with websites: either a plain list of
{ccn, name, city, state, website} records or the output of scanner/roster.py once
each hospital's "url" has been filled in.

Usage:
  python3 scan_all.py --roster roster.json              # every hospital in the roster
  python3 scan_all.py --roster roster.json --state IA   # one state
  python3 scan_all.py --workers 40                      # hospitals at a time (default 30)
  python3 scan_all.py --pages 40                        # max pages per hospital

Each hospital's pages are fetched one at a time, --delay seconds apart (default 2.5;
the national run used 0.3, and later work slowed down after Wordfence rate limits).

Writes findings.json + findings.csv, and evidence/<ccn>/*.html for flagged pages.
Resumable: already-scanned CCNs in findings.json are skipped unless --fresh.
"""
from __future__ import annotations
import argparse, json, os, re, sys, time, random, csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import requests
import signatures as scanner

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
UA_ALT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
TIMEOUT = 15
ASSET_EXT = re.compile(
    r"\.(?:css|js|mjs|json|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf"
    r"|pdf|zip|csv|xlsx?|docx?|mp4|webm|mp3|xml|map)(?:$|\?)", re.I)
PRIORITY = re.compile(
    r"billing|financial|pay[-_]?(?:your[-_]?)?bill|payment|price|pricing|charge"
    r"|estimate|insurance|surprise|good[-_]?faith|transparen"
    # patient/visitor INFO sections only -- bare "patient" matched news titles
    # like "patient experience" and ate 50% of the crawl budget on one site.
    r"|patient[-_](?:information|visitor|resources|rights|portal|forms)"
    r"|patients[-_]?(?:and[-_]?visitors|visitors)?/",
    re.I)

# Editorial content: still sampled, but must not consume the priority budget.
DEPRIORITIZE = re.compile(
    r"/(?:news|blog|podcast|press|event|events|story|stories|article|articles"
    r"|category|tag|author|archive|page)/", re.I)
SITEMAPS = ["wp-sitemap.xml", "sitemap_index.xml", "sitemap.xml", "sitemap-index.xml"]


def fetch_home(s, site):
    p = urlparse(site); root = f"{p.scheme}://{p.netloc}"
    tries = [(site, UA), (site, UA_ALT)]
    if p.path.rstrip("/"): tries.append((root, UA))
    if p.scheme == "https": tries.append((f"http://{p.netloc}", UA))
    last = ""
    for url, ua in tries:
        try:
            s.headers["User-Agent"] = ua
            r = s.get(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == 200 and r.text and "text/html" in (
                    r.headers.get("Content-Type") or "text/html").lower():
                return r.text, str(r.url), ("" if url == site and ua == UA else f"recovered via {url}")
            last = f"http {r.status_code} at {url}"
        except Exception as e:
            last = f"{type(e).__name__} at {url}"
    return "", site, last


def sitemap_urls(s, root):
    out = []
    for name in SITEMAPS:
        try:
            r = s.get(f"{root}/{name}", timeout=TIMEOUT)
            if r.status_code != 200 or "<" not in r.text[:200]: continue
            locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text, re.I)
            kids = [u for u in locs if u.lower().endswith(".xml")]
            out += [u for u in locs if not u.lower().endswith(".xml")]
            for c in kids[:8]:
                try:
                    rc = s.get(c, timeout=TIMEOUT)
                    if rc.status_code == 200:
                        out += re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", rc.text, re.I)
                except Exception: pass
            if out: break
        except Exception: continue
    return [u for u in dict.fromkeys(out) if u.startswith("http") and not ASSET_EXT.search(u)]


def pick(root, home, sm, budget):
    norm = lambda u: u.rstrip("/")
    chosen = [norm(root)]; seen = {norm(root)}
    for u in [x for x in sm if PRIORITY.search(urlparse(x).path)]:
        if norm(u) not in seen: seen.add(norm(u)); chosen.append(u)
    rest = [x for x in sm if norm(x) not in seen]
    # Spread across REAL content first; only dip into editorial archives to fill
    # remaining slots. Concatenating then striding samples both halves evenly,
    # which is what kept news pages at ~50% of the budget.
    main = [x for x in rest if not DEPRIORITIZE.search(x)]
    edit = [x for x in rest if DEPRIORITIZE.search(x)]
    room = budget - len(chosen)
    pool = []
    if main and room > 0:
        step = max(1, len(main)//room); pool += main[::step][:room]
    if edit and len(pool) < room:
        r2 = room - len(pool); step = max(1, len(edit)//r2); pool += edit[::step][:r2]
    for u in pool:
        if norm(u) not in seen: seen.add(norm(u)); chosen.append(u)
    if len(chosen) < 5 and home:
        for href in re.findall(r'href=["\']([^"\']+)["\']', home)[:400]:
            if href.startswith(("#","mailto:","tel:","javascript:")): continue
            u = urljoin(root, href).split("#")[0]
            if ASSET_EXT.search(u): continue
            if urlparse(u).netloc == urlparse(root).netloc and norm(u) not in seen:
                seen.add(norm(u)); chosen.append(u)
            if len(chosen) >= budget: break
    return chosen[:budget]


def scan_one(h, budget, evidence_dir, delay):
    ccn = h["ccn"]; site = (h.get("website") or "").rstrip("/")
    out = {"ccn": ccn, "name": h["name"], "city": h["city"], "state": h["state"],
           "website": site, "reachable": False, "severity": "none", "signals": [],
           "pages_scanned": 0, "pages_flagged": 0, "sitewide": None, "flagged": [], "error": ""}
    if not site:
        out["error"] = "no website"; return out
    s = requests.Session()
    home, final, note = fetch_home(s, site)
    if not home:
        out["error"] = f"unreachable: {note}"; return out
    site = final.rstrip("/"); out["reachable"] = True
    if note: out["fetch_note"] = note
    root = f"{urlparse(site).scheme}://{urlparse(site).netloc}"
    targets = pick(site, home, sitemap_urls(s, root), budget)

    findings, flagged = [], []
    for u in targets:
        if ASSET_EXT.search(u): continue
        try:
            if u == site: html = home
            else:
                if delay: time.sleep(delay)
                r = s.get(u, timeout=TIMEOUT, allow_redirects=True)
                if "text/html" not in (r.headers.get("Content-Type") or "").lower(): continue
                html = r.text
        except Exception: continue
        if not html: continue
        f = scanner.scan(html, u); findings.append(f)
        if f["severity"] != "none":
            flagged.append(f)
            d = os.path.join(evidence_dir, ccn); os.makedirs(d, exist_ok=True)
            nm = re.sub(r"[^A-Za-z0-9._-]", "_", urlparse(u).path.strip("/"))[:70] or "root"
            try: open(os.path.join(d, nm + ".html"), "w", errors="replace").write(html)
            except Exception: pass

    m = scanner.merge(findings)
    out.update({"severity": m["severity"], "signals": m["signals"],
                "pages_scanned": len(findings), "pages_flagged": len(flagged),
                "detail": m.get("detail",""), "flagged": [f["page"] for f in flagged][:20]})
    if m["severity"] == "high":
        try:
            p = s.get(f"{root}/zzz-not-a-real-{random.randint(10**6,10**7)}/", timeout=TIMEOUT)
            out["sitewide"] = scanner.scan(p.text or "", "404")["severity"] == "high"
        except Exception: pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--roster", default="roster.json")
    ap.add_argument("--state"); ap.add_argument("--workers", type=int, default=30)
    ap.add_argument("--pages", type=int, default=40)
    ap.add_argument("--delay", type=float, default=2.5, help="seconds between requests to the same site")
    ap.add_argument("--out", default="findings.json"); ap.add_argument("--fresh", action="store_true")
    a = ap.parse_args()

    raw = json.load(open(a.roster))
    roster = raw["hospitals"] if isinstance(raw, dict) else raw   # roster.py output or a plain list
    for h in roster:
        h["website"] = h.get("website") or h.get("url") or ""
    roster = [h for h in roster if h["website"]]
    if a.state: roster = [h for h in roster if h["state"] == a.state.upper()]
    done = {}
    if os.path.exists(a.out) and not a.fresh:
        try: done = {r["ccn"]: r for r in json.load(open(a.out))}
        except Exception: pass
    todo = [h for h in roster if h["ccn"] not in done]
    print(f"{len(roster)} hospitals in scope; {len(done)} already scanned; {len(todo)} to do")
    print(f"workers={a.workers} pages={a.pages} delay={a.delay}s", flush=True)

    results = list(done.values()); t0 = time.time(); n = 0
    ev = "evidence"; os.makedirs(ev, exist_ok=True)
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(scan_one, h, a.pages, ev, a.delay): h for h in todo}
        for fu in as_completed(futs):
            n += 1
            try: r = fu.result()
            except Exception as e:
                h = futs[fu]; r = {"ccn": h["ccn"], "name": h["name"], "state": h["state"],
                                   "severity": "none", "error": f"crash {type(e).__name__}"}
            results.append(r)
            if r.get("severity") == "high":
                print(f"  !! HIGH  {r['state']} {r['name'][:40]:42} {r.get('signals')}", flush=True)
            if n % 25 == 0:
                el = time.time()-t0
                print(f"  {n}/{len(todo)}  {el/60:.1f}m  ({n/max(el,1):.1f}/s)  "
                      f"high={sum(1 for x in results if x.get('severity')=='high')}", flush=True)
                json.dump(results, open(a.out,"w"), indent=1)
    json.dump(results, open(a.out, "w"), indent=1)

    with open("findings.csv","w",newline="") as f:
        w = csv.writer(f)
        w.writerow(["ccn","name","city","state","website","severity","signals",
                    "pages_flagged","pages_scanned","sitewide","error"])
        for r in sorted(results, key=lambda x:{"high":0,"low":1,"none":2}.get(x.get("severity"),3)):
            w.writerow([r.get("ccn"),r.get("name"),r.get("city"),r.get("state"),r.get("website"),
                        r.get("severity"),"; ".join(r.get("signals") or []),r.get("pages_flagged"),
                        r.get("pages_scanned"),r.get("sitewide"),r.get("error")])

    hi = [r for r in results if r.get("severity")=="high"]
    lo = [r for r in results if r.get("severity")=="low"]
    un = [r for r in results if r.get("error")]
    print(f"\n=== DONE in {(time.time()-t0)/60:.1f} min ===")
    print(f"  scanned {len(results)}   HIGH {len(hi)}   low {len(lo)}   unreachable/error {len(un)}")
    print(f"  pages fetched {sum(r.get('pages_scanned',0) for r in results):,}")
    for r in hi:
        print(f"  HIGH  {r['state']} {r['name'][:44]:46} sitewide={r.get('sitewide')} {r.get('signals')}")

if __name__ == "__main__":
    sys.exit(main())