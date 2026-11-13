#!/usr/bin/env python3
"""
Domain provenance verification for the CAH website compromise study.

For each flagged domain, answers two questions with calibrated probabilities:
  1. Did this domain ever host the official website of THIS specific hospital?
  2. What is the domain serving now?

Replaces brittle token matching with TypeSafe/Jev System One judgments. Five archived
captures spread across each domain's history, plus the live page, are each judged for
"did this belong to the hospital?", "is there enough content to tell?" and "what kind
of page is it?". In the national study this is what separated real takeovers of
hospital domains from roster mistakes (domains that never belonged to the hospital).

Needs a TypeSafe API key in TYPESAFE_API_KEY or ~/.config/typesafe/key.

usage: python verify_provenance.py --findings findings.json --roster roster.json [--out provenance.json]
"""
import argparse, json, os, re, ssl, time, pathlib, urllib.request, urllib.error, gzip, sys


def api_key():
    key = os.environ.get("TYPESAFE_API_KEY")
    path = pathlib.Path.home() / ".config/typesafe/key"
    if not key and path.exists():
        key = path.read_text().strip()
    if not key:
        sys.exit("Set TYPESAFE_API_KEY or put the key in ~/.config/typesafe/key")
    return key


UA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
# certificate checks off: lapsed and parked hospital domains often serve broken or mismatched certificates,
# and the point is to read what they serve, not to trust it
CTX = ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE

def fetch(url, timeout=35, tries=4):
    last=None
    for i in range(tries):
        try:
            r=urllib.request.Request(url, headers={"User-Agent":UA})
            with urllib.request.urlopen(r, timeout=timeout, context=CTX) as f:
                d=f.read()
                if f.headers.get("Content-Encoding")=="gzip":
                    try: d=gzip.decompress(d)
                    except Exception: pass
                return f.status, f.geturl(), d.decode("utf-8","replace")
        except Exception as e:
            last=str(e); time.sleep(min(30, 5*(2**i)))
    return None, None, last

def visible_text(html, limit=3500):
    t=re.sub(r"<(script|style|noscript)[^>]*>.*?</\1>"," ",html,flags=re.S|re.I)
    t=re.sub(r"<[^>]+>"," ",t)
    t=re.sub(r"&nbsp;?"," ",t); t=re.sub(r"\s+"," ",t).strip()
    return t[:limit]

def title_of(html):
    m=re.search(r"<title[^>]*>(.{0,120}?)</title>",html,re.S|re.I)
    return re.sub(r"\s+"," ",m.group(1)).strip() if m else ""

def jev(state, questions, tries=3):
    body={"model":"jev-latest","state":state,"questions":questions}
    for i in range(tries):
        try:
            req=urllib.request.Request("https://api.typesafe.ai/v1/systemone",
                data=json.dumps(body).encode(),
                headers={"Authorization":f"Bearer {api_key()}","Content-Type":"application/json"})
            with urllib.request.urlopen(req,timeout=90) as f:
                return json.loads(f.read())
        except urllib.error.HTTPError as e:
            msg=e.read().decode()[:200]
            if e.code in (429,500,502,503) and i<tries-1: time.sleep(5*(i+1)); continue
            return {"error":f"HTTP {e.code} {msg}"}
        except Exception as e:
            if i<tries-1: time.sleep(5*(i+1)); continue
            return {"error":str(e)}

OWNERSHIP = {
  "type":"noul",
  "instructions":("Was this web page, at the time it was captured, the official website of the specific "
                  "hospital named in `hospital.name`, located in `hospital.city`, `hospital.state`? "
                  "Judge only whether this page belonged to that particular organization."),
  "criteria":{
    "true":("The page is the official site of that named hospital, or of the health system or facility that "
            "operates it under a different brand, or an obvious earlier or later version of that hospital's site."),
    "false":("The page belongs to some other organization entirely: a different hospital, a town or chamber of "
             "commerce, an unrelated business, a domain reseller or parking page, a spam or gambling site, "
             "or an error or empty page.")}}

SUFFICIENCY = {
  "type":"noul",
  "instructions":("Does `page` contain enough substantive content to identify which organization the site "
                  "belongs to? Judge the page content only. Do not use the domain name."),
  "criteria":{
    "true":"There is real content: an organization's name, services, contact details, navigation, or article text.",
    "false":("The page is blank, a bare directory listing, a default web-server placeholder such as 'IIS Windows "
             "Server' or 'Apache Test Page', an error page, or shows only the domain name itself.")}}

CATEGORY = {
  "type":"choice",
  "instructions":"What kind of page is this? Judge the page as a whole, from its visible text and title.",
  "criteria":{
    "hospital_or_clinic":"The website of a hospital, clinic, or healthcare provider organization.",
    "domain_for_sale":"A domain reseller, parking, or 'this domain is for sale' listing page.",
    "gambling_or_spam":"A gambling, betting, casino, or search-engine-spam page.",
    "other_legitimate_org":"A legitimate website for something else: a town, school, business, or other organization.",
    "error_or_empty":"An error page, placeholder, or page with essentially no content."}}

def ask(hospital, domain, when, html):
    state={"hospital":{"name":hospital["name"],"city":hospital["city"],"state":hospital["state"]},
           "domain":domain,"captured":when,
           "page":{"title":title_of(html),"text":visible_text(html)}}
    r=jev(state,{"belonged_to_hospital":OWNERSHIP,"category":CATEGORY,"has_content":SUFFICIENCY})
    if "error" in r: return {"error":r["error"]}
    a=r.get("answers",{})
    return {"belonged_to_hospital":a.get("belonged_to_hospital",{}).get("noul"),
            "has_content":a.get("has_content",{}).get("noul"),
            "category":a.get("category",{}).get("choice"),
            "category_confidence":a.get("category",{}).get("confidence"),
            "category_probs":a.get("category",{}).get("probabilities"),
            "title":title_of(html),
            "tokens":r.get("usage",{})}

def archived(domain):
    """Return (n_snapshots, [(timestamp, html), ...]) sampled across history."""
    st,_,body=fetch(f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json"
                    f"&filter=statuscode:200&collapse=timestamp:6&fl=timestamp&limit=400")
    if st is None: return 0,[],body
    try: stamps=[x[0] for x in json.loads(body)[1:]]
    except Exception: return 0,[],"cdx parse error"
    if not stamps: return 0,[],"no snapshots"
    pick=[stamps[0]]
    for i in (1,2,3): pick.append(stamps[i*len(stamps)//4])
    pick.append(stamps[-1])
    out=[]
    for ts in dict.fromkeys(pick):
        s,_,h=fetch(f"http://web.archive.org/web/{ts}id_/http://{domain}/")
        if s is not None: out.append((ts,h))
        time.sleep(3)
    return len(stamps),out,""

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--findings", default="findings.json", help="scan_all.py output")
    ap.add_argument("--roster", default="roster.json", help="roster used for the scan (for each hospital's city)")
    ap.add_argument("--out", default="provenance.json")
    a=ap.parse_args()
    api_key()   # fail fast before any fetching
    fj=json.loads(pathlib.Path(a.findings).read_text())
    rows=fj if isinstance(fj,list) else fj.get("results",fj.get("findings"))
    raw=json.loads(pathlib.Path(a.roster).read_text())
    ros={r["ccn"]:r for r in (raw["hospitals"] if isinstance(raw,dict) else raw)}
    targets=[r for r in rows if r.get("severity")=="high"]
    dom=lambda r:(r.get("website") or "").lower().replace("https://","").replace("http://","").replace("www.","").split("/")[0]

    out=[]
    for i,rec in enumerate(targets,1):
        d=dom(rec); meta=ros.get(rec["ccn"],{})
        h={"name":rec["name"],"city":meta.get("city",""),"state":rec["state"]}
        print(f"[{i}/{len(targets)}] {rec['name'][:34]:34} {d}", flush=True)
        entry={"ccn":rec["ccn"],"hospital":rec["name"],"city":h["city"],"state":rec["state"],
               "domain":d,"scanner_signals":rec.get("signals"),
               "website_source":meta.get("website_source"),"historical":[],"current":None}

        n,snaps,err=archived(d)
        if n==0 and err and "503" in str(err):
            time.sleep(25); n,snaps,err=archived(d)
        entry["archive_snapshots"]=n; entry["archive_error"]=err
        for ts,html in snaps:
            j=ask(h,d,f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}",html)
            j["timestamp"]=ts
            entry["historical"].append(j)
            p=j.get("belonged_to_hospital")
            hc=j.get("has_content")
            gate = "" if hc is None else ("" if hc>=0.5 else "  [no content - belonged not usable]")
            print(f"      {ts[:8]}  belonged={p if p is None else round(p,3)}  has_content={hc if hc is None else round(hc,2)}  {j.get('category')}{gate}", flush=True)
            time.sleep(0.6)

        st,fin,html=fetch(f"https://{d}/")
        if st is None: st,fin,html=fetch(f"http://{d}/")
        if st is not None:
            j=ask(h,d,"now",html); j["http_status"]=st; j["final_url"]=fin
            entry["current"]=j
            print(f"      NOW       belonged={None if j.get('belonged_to_hospital') is None else round(j['belonged_to_hospital'],3)}  {j.get('category')}  <- {fin}", flush=True)
        else:
            entry["current"]={"error":html[:120]}
            print(f"      NOW       unreachable", flush=True)
        out.append(entry)
        pathlib.Path(a.out).write_text(json.dumps(out,indent=2))
        time.sleep(1)
    print(f"\nwrote {a.out}  ({len(out)} domains)")

if __name__=="__main__":
    main()