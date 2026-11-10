"""Fetch each URL's home page once and record where it lands and what it says.

Use it to confirm a roster's websites: the title and opening text should name the hospital.

usage: python probe.py <urls-file> <out.json>
"""
import concurrent.futures as cf
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
CTX = ssl.create_default_context()
LAX = ssl._create_unverified_context()


def fetch(url, ctx):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*", "Accept-Language": "en-US"})
    try:
        with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
            return r.status, r.geturl(), dict(r.headers), r.read(400000)
    except urllib.error.HTTPError as e:
        return e.code, e.url or url, dict(e.headers or {}), (e.read() or b"")[:400000]


def probe(url):
    host = urllib.parse.urlsplit(url).hostname
    res = {"url": url, "host": host}
    try:
        res["ips"] = sorted({a[4][0] for a in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except Exception as e:
        res["ips"] = []
        res["dns_error"] = str(e)
        return res
    for ctx, tag in ((CTX, ""), (LAX, "tls-unverified")):
        try:
            st, final, hdr, raw = fetch(url, ctx)
            res["tls_note"] = tag
            break
        except Exception as e:
            res["error"] = f"{type(e).__name__}: {e}"[:200]
            if "CERTIFICATE" not in str(e).upper() and "SSL" not in str(e).upper():
                # plain http fallback for sites without https
                try:
                    st, final, hdr, raw = fetch(url.replace("https://", "http://", 1), ctx)
                    res["tls_note"] = "http-only"
                    break
                except Exception as e2:
                    res["error"] = f"{type(e2).__name__}: {e2}"[:200]
                    return res
    else:
        return res
    res.pop("error", None)
    body = raw.decode("utf-8", "replace")
    res.update(status=st, final=final, server=hdr.get("Server", ""), powered=hdr.get("X-Powered-By", ""),
               ctype=hdr.get("Content-Type", ""), size=len(raw))
    m = re.search(r"<title[^>]*>([\s\S]*?)</title>", body, re.I)
    res["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:160] if m else ""
    m = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", body, re.I)
    res["generator"] = m.group(1) if m else ""
    text = re.sub(r"<(script|style)[\s\S]*?</\1>", " ", body, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    res["text"] = re.sub(r"\s+", " ", text).strip()[:600]
    return res


if __name__ == "__main__":
    urls = list(dict.fromkeys(l.strip() for l in open(sys.argv[1]) if l.strip()))
    with cf.ThreadPoolExecutor(16) as ex:
        out = list(ex.map(probe, urls))
    json.dump(out, open(sys.argv[2], "w"), indent=1)
    for r in out:
        print(r.get("status", "ERR"), r["url"], "->", r.get("final", r.get("error", r.get("dns_error", "")))[:90], "|", r.get("title", "")[:70])
