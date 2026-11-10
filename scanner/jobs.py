"""Group a verified roster into crawl jobs, one per website.

Hospitals in a system usually share the system's site. They become one job whose seeds are the
site's home page plus each hospital's page, with a larger page cap so every hospital gets coverage.

usage: python jobs.py roster.json > jobs.json
"""
import collections
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan import reg_domain  # noqa: E402

roster = json.load(open(sys.argv[1]))
groups = collections.OrderedDict()
for h in roster["hospitals"]:
    if not h.get("url"):
        print(f"no url yet: {h['ccn']} {h['name']}", file=sys.stderr)
        continue
    p = urllib.parse.urlsplit(h["url"])
    j = groups.setdefault(reg_domain(p.hostname), {"key": reg_domain(p.hostname), "seeds": [f"{p.scheme}://{p.hostname}/"], "ccns": []})
    if h["url"] not in j["seeds"]:
        j["seeds"].append(h["url"])
    j["ccns"].append(h["ccn"])
for j in groups.values():
    n = len(j["ccns"])
    j["cap"] = 40 if n == 1 else min(40 + 8 * n, 140)
json.dump(list(groups.values()), sys.stdout, indent=1)
print(f"{len(groups)} jobs for {sum(len(j['ccns']) for j in groups.values())} hospitals", file=sys.stderr)
