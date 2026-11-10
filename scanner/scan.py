"""Scan hospital sites for injected malicious content, one site per worker.

Each site is crawled single-threaded with DELAY seconds between requests (or the site's own
robots.txt crawl-delay, if longer). Every page is fetched as a browser, as Googlebot and as a
mobile visitor arriving from Google, so cloaked spam that only search engines or search
visitors see is caught.

usage: python scan.py <jobs.json> <out-dir> [parallel-sites] [delay]
jobs.json: [{"key": "...", "seeds": [...], "cap": 40, "allow": ["example.org"], "hosts": [...]}]
"""
import concurrent.futures as cf
import gzip
import json
import os
import random
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

PROFILES = {
    "browser": {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"},
    "googlebot": {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
    "google-referer": {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                       "Referer": "https://www.google.com/"},
}
COMMON = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.9"}

# gambling / pharma / adult / SEO-spam vocabulary, English and Indonesian (the usual hospital-site injections)
SPAM = re.compile(r"\b(slot ?gacor|slot ?online|situs ?slot|slot ?(88|777|thailand|demo|deposit|pulsa|dana)|judi ?(online|bola)|togel|toto ?(slot|macau|4d)|maxwin|gacor|rtp ?(live|slot)|scatter ?hitam|bandar ?(togel|judi|bola)|sbobet|pragmatic ?play|mahjong ?ways|online ?casino|casino ?online|crypto ?casino|bitcoin ?casino|no ?deposit ?bonus|free ?spins|sportsbook|betting ?(site|tips|odds)|poker ?online|baccarat|roulette ?online|viagra|cialis|levitra|kamagra|tadalafil|sildenafil|buy .{0,25} without (a )?prescription|online ?pharmacy|porn|xxx|escort ?service|onlyfans|payday ?loans?|replica ?(watch|bag)|essay ?writing ?service|write my essay)\b", re.I)
CJK = re.compile(r"[぀-ヿ一-鿿]{6,}")
HIDDEN = re.compile(r"(display\s*:\s*none|visibility\s*:\s*hidden|(left|top)\s*:\s*-\d{3,}px|font-size\s*:\s*0(px)?\s*[;\"']|height\s*:\s*[01]px\s*;\s*overflow\s*:\s*hidden|position\s*:\s*absolute\s*;\s*(left|top)\s*:\s*-\d{3,})", re.I)
BADJS = [
    ("eval-decoder", re.compile(r"eval\s*\(\s*(atob|unescape|function\s*\(p,a,c,k,e|String\.fromCharCode)", re.I)),
    ("charcode-blob", re.compile(r"String\.fromCharCode\(\s*\d+(\s*,\s*\d+){40,}")),
    ("hex-blob", re.compile(r"(\\x[0-9a-fA-F]{2}){60,}")),
    ("docwrite-unescape", re.compile(r"document\.write\s*\(\s*unescape", re.I)),
    ("atob-blob", re.compile(r"atob\(\s*['\"][A-Za-z0-9+/=]{200,}")),
    # ClearFake / EtherHiding: page script reads its payload from a smart contract
    ("blockchain-loader", re.compile(r"(bsc-dataseed|bsc-testnet|binance\.org|data-seed-prebsc|eth_call|0x[0-9a-fA-F]{40}.{0,200}(Contract|ethers|web3))", re.I | re.S)),
    # ClickFix / fake CAPTCHA: copies a PowerShell command to the clipboard
    ("clipboard-command", re.compile(r"clipboard\.writeText\([^)]{0,300}(powershell|mshta|cmd\s*/c|iex|Invoke-)", re.I)),
    ("fake-update", re.compile(r"(update your (browser|chrome)|browser update required|chrome is out of date)", re.I)),
    # SocGholish style beacons
    ("socgholish", re.compile(r"/report\?r=[A-Za-z0-9+/=]{20,}|[\"']data-[a-z]+=[\"'][A-Za-z0-9+/=]{100,}", re.I)),
]
SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)", re.I)
IFRAME_SRC = re.compile(r"<iframe[^>]+src=[\"']([^\"']+)", re.I)
HREF = re.compile(r"<a\b[^>]*href=[\"']([^\"'#]+)", re.I)
META_REFRESH = re.compile(r"<meta[^>]+http-equiv=[\"']?refresh[^>]*url=([^\"'>]+)", re.I)
JS_REDIRECT = re.compile(r"(window|document|top)\.location(\.href)?\s*=\s*['\"](https?://[^'\"]+)", re.I)
# HTML comments never render or run; dropping them removes IE-only notices and commented-out scripts from the checks
COMMENT = re.compile(r"<!--[\s\S]*?-->")
SKIP = re.compile(r"\.(png|jpe?g|gif|webp|svg|ico|css|js|pdf|docx?|xlsx?|pptx?|csv|json|xml|zip|mp[34]|mov|avi|wmv|txt|ics|vcf|eps|tiff?)(\?|$)|/wp-json|xmlrpc|/feed/?$|/wp-admin|/wp-login|/login|/signin|/cart|/checkout|mailto:|tel:|javascript:|/print/|\?(s|search|q|replytocom|share|print)=", re.I)
CHALLENGE = re.compile(r"(Just a moment\.\.\.|Attention Required! \| Cloudflare|cf-chl-|Checking your browser|Access Denied</TITLE>|_Incapsula_Resource|Request unsuccessful\. Incapsula|sucuri_cloudproxy|Pardon Our Interruption)", re.I)

CTX = ssl.create_default_context()
LAX = ssl._create_unverified_context()


def fetch(url, headers, timeout=30, maxbytes=3_000_000):
    h = dict(COMMON, **headers)
    for ctx in (CTX, LAX):
        req = urllib.request.Request(url, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.geturl(), r.headers.get("Content-Type", ""), r.read(maxbytes), ctx is LAX
        except urllib.error.HTTPError as e:
            try:
                body = e.read(maxbytes) or b""
            except Exception:
                body = b""
            return e.code, e.geturl() or url, (e.headers or {}).get("Content-Type", ""), body, ctx is LAX
        except Exception as e:
            if ctx is CTX and ("CERTIFICATE" in str(e).upper()):
                continue
            return 0, url, "", f"{type(e).__name__}: {e}".encode(), ctx is LAX
    return 0, url, "", b"tls failure", True


def text_of(html):
    t = re.sub(r"<(script|style|noscript)[\s\S]*?</\1>", " ", html, flags=re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    return re.sub(r"\s+", " ", t)


def reg_domain(host):
    # good enough for hospital domains; not a public-suffix list (a host under us.com comes out as "us.com")
    host = (host or "").lower().split(":")[0]
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "gov", "ac") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class Site:
    def __init__(self, job, out, delay):
        self.job, self.out, self.delay = job, out, delay
        self.allow = {reg_domain(urllib.parse.urlsplit(s).hostname) for s in job["seeds"]} | set(job.get("allow", []))
        self.prefix = job.get("prefix")  # optional path prefix to keep big multi-state system crawls on one state's pages
        self.last = 0.0
        self.log = []

    def get(self, url, profile="browser", **kw):
        wait = self.delay - (time.time() - self.last)
        if wait > 0:
            time.sleep(wait)
        res = fetch(url, PROFILES[profile], **kw)
        self.last = time.time()
        st, final, ctype, raw, lax = res
        if st == 503 and b"wordfence" in raw.lower():
            self.log.append(f"wordfence 503 on {url}; backing off")
            time.sleep(90)
            res = fetch(url, PROFILES[profile], **kw)
            self.last = time.time()
        return res

    def ours(self, url):
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ("http", "https") or reg_domain(p.hostname) not in self.allow:
            return False
        if self.job.get("hosts") and p.hostname not in self.job["hosts"]:
            return False  # stay on one subdomain when the rest of the domain is behind a bot wall
        return not self.prefix or any(p.path.startswith(x) for x in self.prefix)

    # ---- robots.txt and sitemaps ------------------------------------------------------------
    def sitemaps(self, root):
        res = {"robots": None, "sitemap_files": [], "urls": 0, "spam_urls": [], "offsite_sitemaps": []}
        st, final, ctype, raw, _ = self.get(urllib.parse.urljoin(root, "/robots.txt"))
        robots = raw.decode("utf-8", "replace") if st == 200 and b"<html" not in raw[:500].lower() else ""
        res["robots"] = robots[:4000]
        m = re.search(r"(?im)^\s*crawl-delay:\s*([\d.]+)", robots)
        if m:
            self.delay = min(max(self.delay, float(m.group(1))), 10.0)
        maps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", robots) or [urllib.parse.urljoin(root, "/sitemap.xml"), urllib.parse.urljoin(root, "/sitemap_index.xml")]
        seen, urls, queue = set(), [], list(dict.fromkeys(maps))
        while queue and len(seen) < 25:
            sm = queue.pop(0)
            if sm in seen:
                continue
            seen.add(sm)
            if reg_domain(urllib.parse.urlsplit(sm).hostname) not in self.allow:
                res["offsite_sitemaps"].append(sm)
                continue
            st, final, ctype, raw, _ = self.get(sm, timeout=45, maxbytes=20_000_000)
            if st != 200:
                continue
            if sm.endswith(".gz") or raw[:2] == b"\x1f\x8b":
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    continue
            res["sitemap_files"].append(sm)
            try:
                root_el = ET.fromstring(raw)
            except Exception:
                continue
            for el in root_el.iter():
                if el.tag.endswith("loc") and el.text:
                    loc = el.text.strip()
                    if re.search(r"sitemap[^/]*\.xml(\.gz)?$", loc, re.I) and loc not in seen:
                        queue.append(loc)
                    else:
                        urls.append(loc)
        res["urls"] = len(urls)
        for u in urls:
            path = urllib.parse.unquote(u)
            if SPAM.search(path.replace("-", " ").replace("_", " ")) or CJK.search(path):
                res["spam_urls"].append(u)
            elif not self.ours(u) and not self.prefix:
                res["spam_urls"].append("OFFSITE " + u)
        res["spam_urls"] = res["spam_urls"][:200]
        self.sitemap_urls = [u for u in urls if self.ours(u) and not SKIP.search(u)]
        return res

    # ---- page analysis ------------------------------------------------------------------------
    def analyze(self, url):
        res = {"url": url, "profiles": {}}
        bodies = {}
        for name in PROFILES:
            st, final, ctype, raw, lax = self.get(url, name)
            body = raw.decode("utf-8", "replace")
            bodies[name] = body
            outs = sorted({reg_domain(urllib.parse.urlsplit(urllib.parse.urljoin(final, h)).hostname)
                           for h in HREF.findall(COMMENT.sub(" ", body)) if urllib.parse.urljoin(final, h).startswith("http")} - self.allow)
            res["profiles"][name] = {"status": st, "final": final, "ctype": ctype[:60], "len": len(raw), "out_domains": outs,
                                     "challenge": bool(CHALLENGE.search(body[:20000])), "tls_unverified": lax}
            if name == "browser" and (st == 0 or res["profiles"][name]["challenge"]):
                break  # site unreachable or behind a bot wall: don't hammer it with the other profiles
        clean = {name: COMMENT.sub(" ", body) for name, body in bodies.items()}
        b = clean["browser"]
        flags = []
        for name, body in clean.items():
            txt = text_of(body)
            for m in SPAM.finditer(txt):
                s = max(0, m.start() - 80)
                flags.append(f"spam-text[{name}]: {m.group(0)} :: {txt[s:m.end() + 80]}")
            for h in HREF.findall(body):
                if SPAM.search(urllib.parse.unquote(h).replace("-", " ")):
                    flags.append(f"spam-href[{name}]: {h[:160]}")
            if CJK.search(txt):
                flags.append(f"cjk-text[{name}]: {CJK.search(txt).group(0)[:40]}")
            for tag, rx in BADJS:
                m = rx.search(body)
                if m:
                    flags.append(f"js-{tag}[{name}]: {m.group(0)[:120]}")
            for m in META_REFRESH.finditer(body):
                tgt = urllib.parse.urljoin(url, m.group(1).strip())
                if not self.ours(tgt):
                    flags.append(f"meta-refresh-offsite[{name}]: {tgt[:160]}")
            for m in JS_REDIRECT.finditer(body):
                if not self.ours(m.group(3)):
                    flags.append(f"js-redirect-offsite[{name}]: {m.group(3)[:160]}")
            # hidden containers that hold outbound links: the classic SEO-spam link block
            for m in re.finditer(r"<(div|span|p|section|font|ul)\b[^>]*style=[\"']([^\"']*)[\"'][^>]*>([\s\S]{0,4000}?)</\1>", body, re.I):
                if HIDDEN.search(m.group(2)):
                    outs = [h for h in HREF.findall(m.group(3)) if h.startswith("http") and not self.ours(h)]
                    if len(outs) >= 2 or any(SPAM.search(o) for o in outs):
                        flags.append(f"hidden-outbound-links[{name}]: {outs[:6]}")
        # cloaking: what a search engine or a search visitor gets that a browser does not
        pb = res["profiles"]["browser"]
        for name in ("googlebot", "google-referer"):
            p = res["profiles"].get(name)
            if not p:
                continue
            fh, bh = urllib.parse.urlsplit(p["final"]).hostname, urllib.parse.urlsplit(pb["final"]).hostname
            if fh and bh and reg_domain(fh) != reg_domain(bh) and reg_domain(fh) not in self.allow:
                flags.append(f"cloak-redirect[{name}]: {pb['final'][:100]} vs {p['final'][:100]}")
            extra = set(p["out_domains"]) - set(pb["out_domains"])
            if extra and pb["status"] == 200 and p["status"] == 200:
                res.setdefault("cloak_extra_domains", {})[name] = sorted(extra)
            if pb["status"] == 200 and p["status"] == 200 and pb["len"] and abs(p["len"] - pb["len"]) / pb["len"] > 0.5:
                res.setdefault("cloak_len", {})[name] = [pb["len"], p["len"]]
        res["flags"] = sorted(set(flags))
        base = pb["final"]
        res["scripts"] = sorted({urllib.parse.urljoin(base, s) for s in SCRIPT_SRC.findall(b)})
        res["iframes"] = sorted({urllib.parse.urljoin(base, s) for s in IFRAME_SRC.findall(b)})
        res["out_links"] = sorted({urllib.parse.urljoin(base, h) for h in HREF.findall(b)
                                   if urllib.parse.urljoin(base, h).startswith("http") and not self.ours(urllib.parse.urljoin(base, h))})[:300]
        res["in_links"] = [u for u in dict.fromkeys(urllib.parse.urljoin(base, h).split("#")[0] for h in HREF.findall(b)) if self.ours(u)]
        m = re.search(r"<title[^>]*>([\s\S]*?)</title>", b, re.I)
        res["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:160] if m else ""
        m = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", b, re.I)
        res["generator"] = m.group(1)[:80] if m else ""
        if res["flags"] or res.get("cloak_extra_domains") or url in self.job["seeds"]:
            # keep the raw pages (comments included) as evidence for hand review
            d = os.path.join(self.out, self.job["key"], "html")
            os.makedirs(d, exist_ok=True)
            fn = (re.sub(r"[^\w]+", "_", urllib.parse.urlsplit(url).path).strip("_") or "home")[:120]
            for name, body in bodies.items():
                with gzip.open(os.path.join(d, f"{fn}.{name}.html.gz"), "wt") as f:
                    f.write(body)
        return res

    def run(self):
        job = self.job
        t0 = time.time()
        out = {"key": job["key"], "seeds": job["seeds"], "pages": [], "log": self.log}
        try:
            self.sitemap_urls = []
            out["sitemaps"] = self.sitemaps(job["seeds"][0])
            cap = job.get("cap", 40)
            queue, seen = list(job["seeds"]), set()
            rnd = random.Random(job["key"])
            sample = rnd.sample(self.sitemap_urls, min(len(self.sitemap_urls), cap // 2)) if self.sitemap_urls else []
            blocked = 0
            while queue and len(out["pages"]) < cap:
                url = queue.pop(0)
                key = url.rstrip("/").replace("://www.", "://").replace("http://", "https://")
                if key in seen or SKIP.search(url):
                    continue
                seen.add(key)
                r = self.analyze(url)
                out["pages"].append(r)
                pb = r["profiles"]["browser"]
                if pb["status"] == 0 or pb["challenge"]:
                    blocked += 1
                    if blocked >= 2 or len(out["pages"]) == 1:
                        out["blocked"] = "unreachable" if pb["status"] == 0 else "bot-challenge"
                        break
                    continue
                links = [l for l in r["in_links"] if not SKIP.search(l)]
                if len(out["pages"]) == 1:
                    # homepage: nav links first, then a random draw from the sitemap for deep content
                    queue += links[:cap] + sample
                else:
                    queue += links
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
        out["seconds"] = round(time.time() - t0)
        with open(os.path.join(self.out, job["key"] + ".json"), "w") as f:
            json.dump(out, f, indent=1)
        n_flag = sum(1 for p in out["pages"] if p["flags"])
        return f"{job['key']}: {len(out['pages'])} pages, {n_flag} flagged, sitemap urls {out.get('sitemaps', {}).get('urls')}, {out.get('blocked', '')} {out.get('error', '')} ({out['seconds']}s)"


if __name__ == "__main__":
    jobs = json.load(open(sys.argv[1]))
    outdir = sys.argv[2]
    par = int(sys.argv[3]) if len(sys.argv) > 3 else 16
    delay = float(sys.argv[4]) if len(sys.argv) > 4 else 2.5
    os.makedirs(outdir, exist_ok=True)
    # finished sites are skipped, so an interrupted run picks up where it stopped
    jobs = [j for j in jobs if not os.path.exists(os.path.join(outdir, j["key"] + ".json"))]
    with cf.ThreadPoolExecutor(par) as ex:
        for fut in cf.as_completed([ex.submit(Site(j, outdir, delay).run) for j in jobs]):
            print(fut.result(), flush=True)
