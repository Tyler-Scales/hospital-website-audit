"""Year-by-year Wayback titles for a domain, to show who used it and when it changed hands.

One capture per year, paced archive.PAUSE seconds apart. Expect a minute or two per domain.

usage: python history.py <out.json> <domain...>
"""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import archive  # noqa: E402


def title_and_text(body):
    m = re.search(r"<title[^>]*>([\s\S]*?)</title>", body, re.I)
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
    t = re.sub(r"<(script|style)[\s\S]*?</\1>", " ", body, flags=re.I)
    return title, re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", t)).strip()[:240]


def history(domain):
    rows = archive.cdx(url=f"{domain}/", fl="timestamp,original,statuscode", filter="statuscode:200", collapse="timestamp:4", limit=60)
    hist = []
    for ts, orig, st in rows:
        time.sleep(archive.PAUSE)
        try:
            title, text = title_and_text(archive.get(archive.capture(ts, orig)))
        except Exception as e:
            title, text = f"(unavailable: {e})", ""
        hist.append((ts[:8], title, text))
    return hist


if __name__ == "__main__":
    out = {}
    for domain in sys.argv[2:]:
        try:
            out[domain] = history(domain)
        except Exception as e:
            print(f"== {domain}: index unavailable ({e})", flush=True)
            continue
        print(f"== {domain} ({len(out[domain])} yearly captures)", flush=True)
        for ts, title, text in out[domain]:
            print(f"   {ts} | {title[:80]} | {text[:120]}", flush=True)
        json.dump(out, open(sys.argv[1], "w"), indent=1)
