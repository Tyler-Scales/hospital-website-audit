"""Build a hospital roster for one state from CMS provider data, with historical websites from HIFLD.

The roster lists every CMS-certified hospital in the state: acute care, critical access,
psychiatric, children's and VA hospitals (Hospital General Information) plus freestanding
inpatient rehabilitation and long-term care hospitals. CMS publishes no websites, so each entry
carries candidate sites from the HIFLD hospital layer (2016-2018 records) in the same city.
Treat those as leads: confirm each hospital's current site with probe.py and record it in "url".
The full HIFLD list is also the starting set of former domains for domains.py.

usage: python roster.py <STATE> > roster.json
"""
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
# HIFLD "Hospitals" layer as mirrored on ArcGIS (the HIFLD Open portal itself was retired)
HIFLD = "https://services2.arcgis.com/FiaPA4ga0iQKduv3/arcgis/rest/services/Hospitals/FeatureServer/0/query"


def get_json(url):
    # no custom User-Agent: the CMS API answers 403 to any request that sets one, and 200 to urllib's default
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)


def cms_rows(dataset, state):
    rows, offset = [], 0
    while True:
        q = {"conditions[0][property]": "state", "conditions[0][value]": state, "limit": 500, "offset": offset}
        page = get_json(CMS.format(dataset) + "?" + urllib.parse.urlencode(q)).get("results", [])
        rows += page
        if len(page) < 500:
            return rows
        offset += 500


def hifld_rows(state):
    rows, offset = [], 0
    while True:
        q = {"where": f"STATE='{state}'", "outFields": "NAME,CITY,TYPE,STATUS,WEBSITE,SOURCEDATE", "returnGeometry": "false",
             "f": "json", "resultOffset": offset, "resultRecordCount": 1000}
        d = get_json(HIFLD + "?" + urllib.parse.urlencode(q))
        rows += [f["attributes"] for f in d.get("features", [])]
        if not d.get("exceededTransferLimit"):
            return rows
        offset += 1000


def main(state):
    hospitals = {}
    for ds, (ccn_f, name_f, type_f) in DATASETS.items():
        for r in cms_rows(ds, state):
            ccn = r.get(ccn_f, "")
            # rehab and LTC datasets also list hospital-based units (CCNs like 16T030); those belong to a hospital already listed
            if not ccn or not ccn[:6].isalnum() or (ds != "xubh-q36u" and not ccn.isdigit()):
                continue
            hospitals.setdefault(ccn, {
                "ccn": ccn, "name": r.get(name_f, ""), "city": r.get("citytown", ""),
                "type": type_f[1:] if type_f.startswith("=") else r.get(type_f, ""),
                "ownership": r.get("hospital_ownership", r.get("ownership_type", "")), "url": "", "candidates": []})
    hifld = []
    for a in hifld_rows(state):
        site = (a.get("WEBSITE") or "").strip()
        sourcedate = a.get("SOURCEDATE")
        if isinstance(sourcedate, (int, float)):  # ArcGIS dates are epoch milliseconds
            sourcedate = datetime.datetime.fromtimestamp(sourcedate / 1000, datetime.timezone.utc).date().isoformat()
        hifld.append({"name": a.get("NAME"), "city": a.get("CITY"), "type": a.get("TYPE"), "status": a.get("STATUS"),
                      "website": site if site.startswith("http") else "", "sourcedate": sourcedate})
    by_city = {}
    for h in hifld:
        if h["website"]:
            by_city.setdefault((h["city"] or "").upper(), set()).add(h["website"])
    for h in hospitals.values():
        h["candidates"] = sorted(by_city.get(h["city"].upper(), ()))
    former = sorted({reg_domain(urllib.parse.urlsplit(h["website"]).hostname) for h in hifld if h["website"]})
    out = {"state": state, "built": datetime.date.today().isoformat(),
           "hospitals": sorted(hospitals.values(), key=lambda h: h["name"]), "hifld": hifld, "former_domain_candidates": former}
    json.dump(out, sys.stdout, indent=1)
    types = {}
    for h in hospitals.values():
        types[h["type"]] = types.get(h["type"], 0) + 1
    print(f"{state}: {len(hospitals)} hospitals {types}; {len(hifld)} HIFLD records, {len(former)} HIFLD domains", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1].upper())
