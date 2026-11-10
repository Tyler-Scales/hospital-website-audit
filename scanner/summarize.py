"""Summarize scan output: per-site coverage, every flag for hand review, and third-party script hosts.

usage: python summarize.py <scan-out-dir> <summary.json>
"""
import collections
import glob
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan import reg_domain  # noqa: E402

outdir, dest = sys.argv[1], sys.argv[2]
sites, flags, script_hosts, iframe_hosts, out_domains = [], [], collections.Counter(), collections.Counter(), collections.defaultdict(set)
for f in sorted(glob.glob(os.path.join(outdir, "*.json"))):
    d = json.load(open(f))
    key = d["key"]
    pages = d.get("pages", [])
    ok = [p for p in pages if p["profiles"]["browser"]["status"] == 200 and not p["profiles"]["browser"]["challenge"]]
    three = [p for p in ok if all(p["profiles"].get(n, {}).get("status") == 200 for n in ("googlebot", "google-referer"))]
    gb_blocked = [p for p in ok if p["profiles"].get("googlebot", {}).get("status") not in (200, None)]
    sm = d.get("sitemaps", {})
    gens = collections.Counter(p.get("generator", "") for p in ok if p.get("generator"))
    s = {"key": key, "pages": len(pages), "ok_pages": len(ok), "three_profile_pages": len(three),
         "googlebot_non200": len(gb_blocked), "blocked": d.get("blocked", ""), "error": d.get("error", ""),
         "sitemap_urls": sm.get("urls", 0), "sitemap_spam": sm.get("spam_urls", [])[:30], "offsite_sitemaps": sm.get("offsite_sitemaps", []),
         "generator": gens.most_common(1)[0][0] if gens else "", "seconds": d.get("seconds"), "log": d.get("log", []),
         "home_status": pages[0]["profiles"]["browser"]["status"] if pages else None,
         "home_final": pages[0]["profiles"]["browser"]["final"] if pages else None}
    sites.append(s)
    for p in pages:
        for fl in p["flags"]:
            flags.append({"site": key, "url": p["url"], "flag": fl})
        for name, extra in (p.get("cloak_extra_domains") or {}).items():
            flags.append({"site": key, "url": p["url"], "flag": f"cloak-extra-outbound[{name}]: {extra[:8]}"})
        for name, lens in (p.get("cloak_len") or {}).items():
            flags.append({"site": key, "url": p["url"], "flag": f"cloak-length[{name}]: {lens}"})
        for sc in p.get("scripts", []):
            h = urllib.parse.urlsplit(sc).hostname
            if h and reg_domain(h) != reg_domain(urllib.parse.urlsplit(p["url"]).hostname):
                script_hosts[(reg_domain(h), key)] += 1
        for fr in p.get("iframes", []):
            h = urllib.parse.urlsplit(fr).hostname
            if h:
                iframe_hosts[(reg_domain(h), key)] += 1
        for o in p.get("out_links", []):
            h = urllib.parse.urlsplit(o).hostname
            if h:
                out_domains[reg_domain(h)].add(key)

by_host = collections.defaultdict(set)
for (h, site), n in script_hosts.items():
    by_host[h].add(site)
ifr = collections.defaultdict(set)
for (h, site), n in iframe_hosts.items():
    ifr[h].add(site)
json.dump({"sites": sites, "flags": flags,
           "script_hosts": {h: sorted(v) for h, v in sorted(by_host.items(), key=lambda kv: -len(kv[1]))},
           "iframe_hosts": {h: sorted(v) for h, v in sorted(ifr.items(), key=lambda kv: -len(kv[1]))},
           "out_domains": {h: sorted(v) for h, v in out_domains.items()}},
          open(dest, "w"), indent=1)
print(f"sites {len(sites)}  pages {sum(s['pages'] for s in sites)}  ok {sum(s['ok_pages'] for s in sites)}  three-profile {sum(s['three_profile_pages'] for s in sites)}")
print(f"flags {len(flags)} on {len({(f['site'], f['url']) for f in flags})} pages across {len({f['site'] for f in flags})} sites")
print(f"third-party script hosts {len(by_host)}, iframe hosts {len(ifr)}, outbound domains {len(out_domains)}")
