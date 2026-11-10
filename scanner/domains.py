"""Check former hospital domains: does the hospital still hold them, and what has happened to them?

For each domain: DNS (A, www, NS), RDAP registration dates, registrar and nameservers, and a
year-by-year Wayback capture index (status and page size), so a name that changed hands shows up
as a reset creation date, a parking or marketplace nameserver, or a break in what was archived.
Run history.py on the domains that look wrong to read the archived page titles.

usage: python domains.py <domains.txt> <out.json>
"""
import concurrent.futures as cf
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import archive  # noqa: E402

UA = archive.UA


def dig(name, rtype):
    try:
        out = subprocess.run(["dig", "+short", rtype, name], capture_output=True, text=True, timeout=20).stdout
        return [l.strip() for l in out.splitlines() if l.strip()]
    except Exception:
        return []


def rdap(domain):
    req = urllib.request.Request(f"https://rdap.org/domain/{domain}", headers={"User-Agent": UA, "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"status": "not-found" if e.code == 404 else f"http {e.code}"}
    except Exception as e:
        return {"status": f"error {type(e).__name__}"}
    ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    registrar = ""
    for ent in d.get("entities", []):
        if "registrar" in ent.get("roles", []):
            v = ent.get("vcardArray", [None, []])[1]
            registrar = next((x[3] for x in v if x[0] == "fn"), "") or ent.get("handle", "")
    return {"status": ",".join(d.get("status", [])), "created": ev.get("registration"), "updated": ev.get("last changed"),
            "expires": ev.get("expiration"), "registrar": registrar,
            "nameservers": [n.get("ldhName", "").lower() for n in d.get("nameservers", [])]}


def wayback(domain):
    try:
        rows = archive.cdx(url=f"{domain}/", fl="timestamp,statuscode,length", collapse="timestamp:4", limit=60)
    except Exception as e:
        return {"error": str(e)[:120]}
    if not rows:
        return {}
    ok = [r for r in rows if r[1] == "200"]
    return {"years": [(r[0][:4], r[1], r[2]) for r in rows],
            "first_200": ok[0][0][:8] if ok else None, "last_200": ok[-1][0][:8] if ok else None, "last": rows[-1][0][:8]}


def check(domain):
    res = {"domain": domain, "a": dig(domain, "A"), "www": dig("www." + domain, "A") + dig("www." + domain, "CNAME"),
           "ns": dig(domain, "NS"), "rdap": rdap(domain), "wayback": wayback(domain)}
    if res["rdap"].get("status") == "not-found" and res["ns"]:
        # some registries (.us, many country codes) aren't in RDAP; a name with nameservers is registered
        res["rdap"]["status"] = "no RDAP record, but registered (has nameservers)"
    return res


if __name__ == "__main__":
    domains = list(dict.fromkeys(l.strip().lower() for l in open(sys.argv[1]) if l.strip() and not l.startswith("#")))
    with cf.ThreadPoolExecutor(4) as ex:  # the CDX index tolerates this; playback (history.py) does not
        out = list(ex.map(check, domains))
    json.dump(out, open(sys.argv[2], "w"), indent=1)
    for r in out:
        d, w = r["rdap"], r["wayback"]
        print(f"{r['domain']:32} A={','.join(r['a'][:2]) or '-':32} created={str(d.get('created'))[:10]:10} "
              f"exp={str(d.get('expires'))[:10]:10} {d.get('registrar', d.get('status', ''))[:24]:24} "
              f"ns={','.join(d.get('nameservers', []) or r['ns'])[:40]:40} archive={w.get('first_200')}..{w.get('last_200')}")
