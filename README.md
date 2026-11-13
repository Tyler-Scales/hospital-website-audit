# Hospital Website Audit

Tools and methods from a series of audits of U.S. hospital websites, built with Claude Code between July and November 2026. The work began as a compliance review of rural hospitals and became a security study once the first compromised hospital sites turned up.

| When | Scope | What was checked | Result |
|---|---|---|---|
| July–August 2026 | 281 rural hospital websites in 9 states | Price transparency, No Surprises Act, Section 1557 | 54 (19%) met all three rules |
| August–October 2026 | All 1,382 critical access hospitals in 45 states | Injected content and lapsed domains | 4 confirmed compromised (0.37% of sites) |
| November 2026 | All 123 Iowa hospitals and their health systems | Injected content, cloaking, former domains | No live site compromised; 3 former hospital domains used for gambling |

Every scan uses only what any visitor can see. Nothing logs in, submits forms or probes for software vulnerabilities, and nothing tries to get past a bot check. Hospital names and domains are left out of this repository.

## 1. Compliance audits (July–August 2026)

Three federal rules every hospital website has to meet:

- **CMS hospital price transparency (45 CFR 180):** a machine-readable standard-charges file, a price estimator or shoppable-services list, and a `cms-hpt.txt` discovery file at the domain root.
- **No Surprises Act:** a notice of patients' balance-billing rights, and a Good Faith Estimate notice for uninsured and self-pay patients.
- **ACA Section 1557:** a nondiscrimination notice, language-assistance taglines, and how to file a civil rights complaint.

| Run | Sites | Price transparency met | No Surprises Act met | Section 1557 met | All three |
|---|---:|---:|---:|---:|---:|
| Iowa | 93 | 78 | 39 | 52 | 23 |
| Alabama, Arkansas, Kentucky, Louisiana, Mississippi, Tennessee | 143 | 93 | 58 | 67 | 24 |
| Georgia | 33 | 28 | 12 | 9 | 2 |
| Florida | 12 | 12 | 6 | 6 | 5 |
| **Total** | **281** | **211 (75%)** | **115 (41%)** | **134 (48%)** | **54 (19%)** |

Price files were usually there; patient notices usually weren't. Over half the sites in the later runs (103 of 188) had no Good Faith Estimate notice, and nearly half of all sites (134 of 281) lacked language-assistance taglines.

Each run was a Claude Code workflow in which AI agents reviewed every hospital's site against a fixed rubric. An agent reading page text can see a link to a price file but not what the file is, so the tooling that followed verifies the files directly (status, format, CMS template, date). [`compliance/compliance.py`](compliance/compliance.py) is that check for a single site. Details in [docs/compliance.md](docs/compliance.md).

## 2. National critical access hospital scan (August–October 2026)

The compliance reviews turned up hospital sites carrying hidden gambling links. So every critical access hospital in the country got a security scan.

| | |
|---|---|
| Critical access hospitals | 1,382 in 45 states (CMS) |
| Distinct websites scanned | 1,075 (44,524 pages) |
| Flagged by the scanner | 16, each checked by hand |
| Confirmed compromised | 4 (0.37% of websites) |
| What they were | 3 hospital sites with hidden gambling links (2 still live at the October recheck), and 1 abandoned hospital domain now hosting gambling |
| Why 16 became 4 | 11 flagged addresses never belonged to the hospital, and 1 pointed to a parent system's clean site |

The scanner itself makes no AI calls: [`national/signatures.py`](national/signatures.py) is a set of byte-level signatures with a severity ladder, tuned against every false positive the run produced. AI did the work around it. Agents found websites for the hospitals the roster was missing, and TypeSafe's Jev model judged archived copies of each flagged domain ("did this page belong to this hospital?", "what kind of page is this?"). That second step is what showed most flags were roster mistakes rather than hacks. Details in [docs/national.md](docs/national.md).

## 3. Iowa statewide audit (November 2026)

Every CMS-certified hospital in one state, not just critical access, plus the health systems that run them, with a deeper scan: three visitor types per page to catch cloaking, and a full check of every former hospital domain.

| | |
|---|---|
| Hospitals | 123 (82 critical access, 30 acute care, 11 psychiatric, rehabilitation, long-term care and VA) |
| Live websites scanned | 85 sites, 3,568 pages |
| Pages compared as browser, Googlebot and Google-search visitor | 3,198 |
| Flagged by the scanner | 22, every one reviewed by hand |
| Confirmed | 2, both former hospital domains now hosting gambling |
| Former hospital domains checked | 58, of which 51 are still held by the hospital or its system |
| Sites behind bot walls | 6, checked through recent Internet Archive captures instead |

No live Iowa hospital website was serving injected content. Every real finding was on an address a hospital had stopped using: two former hospital domains now promote slot gambling and sports betting, and a third carried betting pages in 2021 and is now unregistered, even though a federal hospital dataset still lists it as the hospital's website. Details in [docs/statewide.md](docs/statewide.md).

## What's in the repository

| Folder | What it is | Needs |
|---|---|---|
| [`scanner/`](scanner) | The statewide pipeline (part 3): roster, site confirmation, crawl with three visitor types, flag summary, former-domain checks, archive checks for bot-protected sites | Python 3.10+, `curl`, `dig` |
| [`national/`](national) | The national scanner (part 2): signatures, the parallel runner, and the Jev provenance check | Python 3.10+, `requests`; a TypeSafe API key for the provenance check |
| [`compliance/`](compliance) | The single-site compliance check (part 1) | Python 3.10+ |
| [`docs/`](docs) | Method write-ups for each part | |

### The statewide pipeline

| Step | Script | What it does |
|---|---|---|
| 1 | `roster.py` | Lists every CMS-certified hospital in a state, or every critical access hospital in the country, with candidate websites from the HIFLD hospital dataset |
| 2 | `probe.py` | Loads each candidate home page so you can confirm it belongs to the hospital. Record the confirmed site in the roster's `url` field |
| 3 | `jobs.py` | Groups hospitals by website. Hospitals that share a health system's site become one crawl job with a larger page budget |
| 4 | `scan.py` | Crawls each site and runs the content and cloaking checks |
| 5 | `summarize.py` | Collects every flag, third-party script host and outbound domain for hand review |
| 6 | `domains.py`, `history.py`, `snap.py` | Checks former domains: DNS, registration records, and Internet Archive history |
| 7 | `wayback_scan.py` | Runs the content checks on recent archived pages of sites that block automated visitors |

## Quick start

Build a roster: one state, or every critical access hospital in the country.

```bash
python3 scanner/roster.py IA > roster.json
```

```bash
python3 scanner/roster.py ALL --cah > roster.json
```

Confirm each hospital's site with `scanner/probe.py`, fill in `url` for each entry in `roster.json`, then run the statewide pipeline:

```bash
python3 scanner/jobs.py roster.json > jobs.json
```

```bash
python3 scanner/scan.py jobs.json out 16 2.5
```

```bash
python3 scanner/summarize.py out summary.json
```

Or run the national scanner over the same roster:

```bash
pip install -r national/requirements.txt
```

```bash
python3 national/scan_all.py --roster roster.json --out findings.json
```

```bash
python3 national/verify_provenance.py --findings findings.json --roster roster.json
```

Check one hospital's compliance notices and price files:

```bash
python3 compliance/compliance.py https://www.example-hospital.org
```

`scan.py` runs 16 sites at a time but each site strictly one request at a time; Iowa's 90 sites took about 45 minutes. Both scanners skip finished hospitals on a rerun, so an interrupted scan picks up where it stopped. [examples/jobs.example.json](examples/jobs.example.json) shows the statewide job format.

## Responsible use

- Plain GET requests only. No logins, forms, parameter fuzzing or vulnerability probing.
- One request at a time per site: 2.5 seconds apart by default, or the site's `Crawl-delay` if longer. A Wordfence rate-limit page triggers a back-off.
- A bot challenge (Cloudflare, Akamai, Incapsula, Sucuri) ends the crawl of that site. Check it through the Internet Archive instead; never try to get past a bot check.
- The Googlebot and Google-referral profiles exist only to compare what search engines and search visitors are served with what a browser gets.
- Confirm every flag by reading the saved page, report findings privately to the hospital first, and keep names and domains out of anything public until it has had time to act.

## Limitations

- The scanners sample pages: 40 per site (up to 140 for large system sites), favoring billing and price pages and drawing the rest from the sitemap.
- They see only what visitors see. A backdoor that doesn't change the rendered pages, or an outdated plugin, won't show up.
- They detect the injection campaigns characterized here. "Clean" means none of those was visible, not that a site is uncompromised.
- In the national run about one site in ten was unreachable, mostly behind firewalls or at a bad roster address. A wrong roster address produces convincing false findings, so confirm every website before scanning.
- The compliance check reports where notices and files appear; it does not judge whether their wording satisfies each rule.

## Notes on running it

- The Python that ships with macOS is built on LibreSSL 2.8 and fails TLS handshakes with many hospital sites. Use a Python built on OpenSSL 3, for example `uv venv --python 3.12`.
- The CMS provider-data API answers 403 to requests that set a custom User-Agent, so `roster.py` sends the default one.
- The Internet Archive's page playback answers 429 to bursts. The archive tools fetch one capture every 7 seconds and go through `curl`, which handled networks without a working IPv6 route better than Python's `urllib`.

## License

MIT. See [LICENSE](LICENSE).
