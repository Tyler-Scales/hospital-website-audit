"""Build a hospital roster from CMS provider data, with historical websites from HIFLD.

The roster lists every CMS-certified hospital in a state (or the whole country): acute care,
critical access, psychiatric, children's and VA hospitals (Hospital General Information) plus
freestanding inpatient rehabilitation and long-term care hospitals. With --cah it keeps only
critical access hospitals, the scope of the national scan. CMS publishes no websites, so each
entry carries candidate sites from the HIFLD hospital layer (2016-2018 records) in the same city.
Treat those as leads: confirm each hospital's current site with probe.py and record it in "url".
The full HIFLD list is also the starting set of former domains for domains.py.

usage: python roster.py <STATE|ALL> [--cah] > roster.json
"""
import argparse
import datetime
import json
import os
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scan import reg_domain  # noqa: E402

CMS = "https://data.cms.gov/provider-data/api/1/datastore/query/{}/0"
# dataset id -> (ccn field, name field, type field or fixed type)
DATASETS = {
    "xubh-q36u": ("facility_id", "facility_name", "hospital_type"),                  # Hospital General Information
    "7t8x-u3ir": ("cms_certification_number_ccn", "provider_name", "=Rehabilitation"),  # Inpatient rehabilitation facilities
    "azum-44iv": ("cms_certification_number_ccn", "provider_name", "=Long-term care"),  # Long-term care hospitals
}
CAH = "Critical Access Hospitals"
# HIFLD "Hospitals" layer as mirrored on ArcGIS (the HIFLD Open portal itself was retired)
HIFLD = "https://services2.arcgis.com/FiaPA4ga0iQKduv3/arcgis/rest/services/Hospitals/FeatureServer/0/query"


def get_json(url):
    # no custom User-Agent: the CMS API answers 403 to any request that sets one, and 200 to urllib's default
    with urllib.request.urlopen(url, timeout=90) as r:
        return json.load(r)


def cms_rows(dataset, state):
    rows, offset = [], 0
    while True:
        q = {"limit": 500, "offset": offset}
        if state != "ALL":
            q.update({"conditions[0][property]": "state", "conditions[0][value]": state})
        page = get_json(CMS.format(dataset) + "?" + urllib.parse.urlencode(q)).get("results", [])
        rows += page
        if len(page) < 500:
            return rows
        offset += 500


def hifld_rows(state):
    rows, offset = [], 0
    while True:
        q = {"where": "1=1" if state == "ALL" else f"STATE='{state}'", "outFields": "NAME,CITY,STATE,TYPE,STATUS,WEBSITE,SOURCEDATE",
             "returnGeometry": "false", "f": "json", "resultOffset": offset, "resultRecordCount": 1000}
        d = get_json(HIFLD + "?" + urllib.parse.urlencode(q))
        rows += [f["attributes"] for f in d.get("features", [])]
        if not d.get("exceededTransferLimit"):
            return rows
        offset += 1000


def main(state, cah_only):
    hospitals = {}
    for ds, (ccn_f, name_f, type_f) in DATASETS.items():
        if cah_only and ds != "xubh-q36u":
            continue
        for r in cms_rows(ds, state):
            ccn = r.get(ccn_f, "")
            # rehab and LTC datasets also list hospital-based units (CCNs like 16T030); those belong to a hospital already listed
            if not ccn or not ccn[:6].isalnum() or (ds != "xubh-q36u" and not ccn.isdigit()):
                continue
            kind = type_f[1:] if type_f.startswith("=") else r.get(type_f, "")
            if cah_only and kind != CAH:
                continue
            hospitals.setdefault(ccn, {
                "ccn": ccn, "name": r.get(name_f, ""), "city": r.get("citytown", ""), "state": r.get("state", ""),
                "type": kind, "ownership": r.get("hospital_ownership", r.get("ownership_type", "")), "url": "", "candidates": []})
    hifld = []
    for a in hifld_rows(state):
        site = (a.get("WEBSITE") or "").strip()
        sourcedate = a.get("SOURCEDATE")
        if isinstance(sourcedate, (int, float)):  # ArcGIS dates are epoch milliseconds
            sourcedate = datetime.datetime.fromtimestamp(sourcedate / 1000, datetime.timezone.utc).date().isoformat()
        hifld.append({"name": a.get("NAME"), "city": a.get("CITY"), "state": a.get("STATE"), "type": a.get("TYPE"),
                      "status": a.get("STATUS"), "website": site if site.startswith("http") else "", "sourcedate": sourcedate})
    by_city = {}
    for h in hifld:
        if h["website"]:
            by_city.setdefault(((h["state"] or "").upper(), (h["city"] or "").upper()), set()).add(h["website"])
    for h in hospitals.values():
        h["candidates"] = sorted(by_city.get((h["state"].upper(), h["city"].upper()), ()))
    former = sorted({reg_domain(urllib.parse.urlsplit(h["website"]).hostname) for h in hifld if h["website"]})
    out = {"scope": state + (" critical access" if cah_only else ""), "built": datetime.date.today().isoformat(),
           "hospitals": sorted(hospitals.values(), key=lambda h: (h["state"], h["name"])), "hifld": hifld,
           "former_domain_candidates": former}
    json.dump(out, sys.stdout, indent=1)
    types, states = {}, set()
    for h in hospitals.values():
        types[h["type"]] = types.get(h["type"], 0) + 1
        states.add(h["state"])
    print(f"{out['scope']}: {len(hospitals)} hospitals in {len(states)} states {types}; "
          f"{len(hifld)} HIFLD records, {len(former)} HIFLD domains", file=sys.stderr)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("state", help="two-letter state code, or ALL")
    ap.add_argument("--cah", action="store_true", help="critical access hospitals only")
    a = ap.parse_args()
    main(a.state.upper(), a.cah)
