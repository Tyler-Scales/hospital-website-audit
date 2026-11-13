"""Check one hospital website for the federal notices and files patients rely on.

Three federal rules, the scope of the early compliance audits:
  - CMS hospital price transparency (45 CFR 180): a cms-hpt.txt discovery file at the domain
    root, a machine-readable standard-charges file, and a price estimator or shoppable list.
  - No Surprises Act: the balance-billing rights notice, and the Good Faith Estimate notice for
    uninsured and self-pay patients.
  - ACA Section 1557: a nondiscrimination notice and language-assistance taglines.

It lists which pages mention each topic (home page links first, then the sitemap), checks
cms-hpt.txt, and verifies every charge file it finds: HTTP status, format, CMS-standard file
name, CMS template header and date. It reports facts; it does not decide compliance. In the
audits a reviewer (an AI agent working from a rubric, then a person) read the pages, and these
verified file facts settled the price-transparency questions page text alone could not.

usage: python compliance.py https://www.example-hospital.org [--max-pages 80] [--delay 1.5] [--json out.json]
"""
import argparse
import gzip
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
CTX = ssl.create_default_context()
LAX = ssl._create_unverified_context()

TOPICS = {
    "price_transparency": r"price transparency|standard charges|machine.readable|shoppable|price estimator|cost estimator|chargemaster",
    "no_surprises": r"no surprises|surprise (medical )?bill|balance bill|rights and protections",
    "good_faith_estimate": r"good faith estimate",
    "nondiscrimination": r"nondiscrimination|non-discrimination|section 1557|discriminate on the basis",
    "language_assistance": r"language assistance|interpret(er|ation) services|free of charge.{0,40}(language|interpret)|ATENCI[OÓ]N|Espa[nñ]ol",
    "accessibility": r"auxiliary aids|accessibility statement|\bTTY\b|\b711\b",
}
LINK_HINT = re.compile(r"price|pricing|transparen|charge|estimate|surprise|good.?faith|balance.?bill|nondiscrimin|non-discrimin|1557"
                       r"|language|accessib|interpret|financial|billing|patient rights", re.I)
FILE_LINK = re.compile(r'href=["\']([^"\']+?\.(?:csv|json|xlsx|xls|zip|txt))["\']', re.I)
CMS_NAMED = re.compile(r"\d{9,10}_[^/]*?_standardcharges\.(csv|json)", re.I)
DATE_IN_TEXT = re.compile(r"(20\d{2})[-/](\d{1,2})[-/](\d{1,2})|(\d{1,2})[-/](\d{1,2})[-/](20\d{2})")
STALE_MONTHS = 18  # CMS expects the file updated at least annually; flag anything clearly older


class Client:
    def __init__(self, delay):
        self.delay, self.last = delay, 0.0

    def get(self, url, maxbytes=None, timeout=30):
        wait = self.delay - (time.time() - self.last)
        if wait > 0:
            time.sleep(wait)
        self.last = time.time()
        for ctx in (CTX, LAX):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip"})
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as f:
                    d = f.read(maxbytes) if maxbytes else f.read()
                    if f.headers.get("Content-Encoding") == "gzip":
                        try:
                            d = gzip.decompress(d)
                        except Exception:
                            pass
                    return f.status, f.geturl(), dict(f.headers), d
            except urllib.error.HTTPError as e:
                return e.code, url, dict(e.headers or {}), b""
            except Exception as e:
                if ctx is CTX and "CERTIFICATE" in str(e).upper():
                    continue
                return None, url, {}, str(e).encode()
        return None, url, {}, b""


def text_of(html):
    t = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.S | re.I)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t)).strip()


def sitemap_urls(c, root):
    st, _, _, robots = c.get(root + "/robots.txt")
    maps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", robots.decode("utf-8", "replace")) if st == 200 else []
    maps = maps or [root + "/sitemap_index.xml", root + "/sitemap.xml", root + "/wp-sitemap.xml"]
    urls, seen = [], set()
    for sm in maps:
        st, _, _, body = c.get(sm)
        if st != 200:
            continue
        locs = re.findall(r"<loc>\s*([^<\s]+)", body.decode("utf-8", "replace"))
        for child in [u for u in locs if u.lower().endswith(".xml")][:10]:
            if child not in seen:
                seen.add(child)
                urls += re.findall(r"<loc>\s*([^<\s]+)", c.get(child)[3].decode("utf-8", "replace"))
        urls += [u for u in locs if not u.lower().endswith(".xml")]
        if urls:
            break
    return [u for u in dict.fromkeys(urls) if not re.search(r"\.(jpe?g|png|gif|webp|svg|pdf)$", u, re.I)]


def check_cms_hpt(c, root):
    out = {"url": root + "/cms-hpt.txt", "present": False, "mrf_urls": [], "fields": []}
    st, _, _, body = c.get(out["url"], maxbytes=20000)
    t = body.decode("utf-8", "replace")
    if st == 200 and "<html" not in t[:400].lower():
        # the CMS format names each file on an "mrf-url:" line; vendor-hosted files often have no .csv/.json extension
        urls = re.findall(r"(?im)^\s*mrf-url\s*:\s*(\S+)", t) + re.findall(r"https?://\S+?\.(?:csv|json)\b", t, re.I)
        out.update(present=True, mrf_urls=list(dict.fromkeys(urls))[:6],
                   fields=sorted({k.lower() for k in re.findall(r"(?m)^\s*([a-z-]+)\s*:", t)}))
    return out


def verify_file(c, url):
    info = {"url": url, "http": None, "format": "unknown", "cms_named": bool(CMS_NAMED.search(url)), "cms_template": False,
            "first_line": "", "date_seen": "", "stale": None}
    st, final, hdr, head = c.get(url, maxbytes=8192, timeout=45)
    info["http"] = st
    path = url.lower().split("?")[0]
    info["format"] = next((f for ext, f in ((".csv", "CSV"), (".json", "JSON"), (".xlsx", "XLSX"), (".xls", "XLS"), (".zip", "ZIP"), (".txt", "TXT"))
                           if path.endswith(ext)), "unknown")
    text = head.decode("utf-8", "replace")
    if info["format"] == "unknown":  # vendor download URLs: go by the response instead of the extension
        ctype = (hdr.get("Content-Type") or "").lower()
        info["format"] = ("JSON" if "json" in ctype or text.lstrip().startswith("{") else
                          "CSV" if "csv" in ctype or (text.count(",") > 5 and "<html" not in text[:300].lower()) else
                          "XLSX" if "spreadsheet" in ctype or head[:2] == b"PK" else "unknown")
    info["first_line"] = text.splitlines()[0][:220] if text.strip() else ""
    info["cms_template"] = "45 CFR 180" in text or "last_updated_on" in text
    m = DATE_IN_TEXT.search(text) or DATE_IN_TEXT.search(url)
    if m:
        g = m.groups()
        y, mo = (int(g[0]), int(g[1])) if g[0] else (int(g[5]), int(g[3]))
        now = datetime.now(timezone.utc)
        info["date_seen"] = f"{y:04d}-{mo:02d}"
        info["stale"] = (now.year - y) * 12 + (now.month - mo) > STALE_MONTHS
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("site")
    ap.add_argument("--max-pages", type=int, default=80)
    ap.add_argument("--delay", type=float, default=1.5)
    ap.add_argument("--json")
    a = ap.parse_args()
    c = Client(a.delay)
    p = urllib.parse.urlsplit(a.site if "://" in a.site else "https://" + a.site)
    root = f"{p.scheme}://{p.netloc}"
    st, final, _, home = c.get(root + "/")
    home = home.decode("utf-8", "replace")
    report = {"site": root, "home_status": st, "home_links": {}, "pages_checked": 0, "topics": {k: [] for k in TOPICS}}

    for href, label in re.findall(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', home, re.S | re.I):
        if LINK_HINT.search(text_of(label)) or LINK_HINT.search(href):
            report["home_links"][urllib.parse.urljoin(root + "/", href)] = text_of(label)[:60]

    # pages to read: the home page, its compliance-looking links, then sitemap pages whose path looks relevant, then the rest
    sm = sitemap_urls(c, root)
    relevant = [u for u in sm if LINK_HINT.search(urllib.parse.urlsplit(u).path)]
    pages = list(dict.fromkeys([root + "/"] + [u for u in report["home_links"] if urllib.parse.urlsplit(u).netloc == p.netloc]
                               + relevant + sm))[:a.max_pages]
    file_links = set()
    for u in pages:
        st, _, hdr, body = (200, u, {}, home.encode()) if u == root + "/" else c.get(u)
        if st != 200 or "html" not in (hdr.get("Content-Type", "text/html") or "").lower():
            continue
        html = body.decode("utf-8", "replace")
        report["pages_checked"] += 1
        t = text_of(html)
        for k, rx in TOPICS.items():
            n = len(re.findall(rx, t, re.I))
            if n:
                report["topics"][k].append((n, u))
        file_links |= {urllib.parse.urljoin(u, h) for h in FILE_LINK.findall(html)}

    report["cms_hpt"] = check_cms_hpt(c, root)
    cands = list(dict.fromkeys(report["cms_hpt"]["mrf_urls"] + sorted(file_links, key=lambda x: (not CMS_NAMED.search(x), x))))[:6]
    report["charge_files"] = [verify_file(c, u) for u in cands]

    print(f"{root}  (home HTTP {report['home_status']}, {report['pages_checked']} pages read of {len(sm)} in the sitemap)\n")
    print("Home page links about billing, pricing, rights or language access:")
    for u, label in report["home_links"].items():
        print(f"  {label:<45} {u}")
    print("\nPages mentioning each topic:")
    for k, hits in report["topics"].items():
        hits.sort(reverse=True)
        print(f"  {k:<20} {len(hits):>3} pages" + ("; top: " + "; ".join(f"{u.replace(root, '')} ({n})" for n, u in hits[:3]) if hits else "  <- none found"))
    h = report["cms_hpt"]
    print(f"\ncms-hpt.txt: {'present' if h['present'] else 'NOT FOUND'} at {h['url']}")
    if h["present"]:
        missing = {"location-name", "source-page-url", "mrf-url", "contact-name", "contact-email"} - set(h["fields"])
        print("  all five required fields present" if not missing else f"  missing fields: {', '.join(sorted(missing))}")
    for u in h["mrf_urls"]:
        print(f"  declares {u}")
    print("\nCharge files found:" if report["charge_files"] else "\nNo charge-file links found on the pages read.")
    for f in report["charge_files"]:
        bits = [f"HTTP {f['http']}", f["format"]] + (["CMS file name"] if f["cms_named"] else []) + (["CMS template header"] if f["cms_template"] else [])
        if f["date_seen"]:
            bits.append(f"dated {f['date_seen']}" + (" (stale)" if f["stale"] else ""))
        print(f"  {f['url'][:110]}  [{', '.join(bits)}]")
    if a.json:
        json.dump(report, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
