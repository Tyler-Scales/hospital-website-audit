# Hospital Website Audit

A passive security scanner for hospital websites. It looks for the two problems that keep turning up on small and rural hospital sites:

1. **Injected content on live sites.** Hidden gambling and pharmacy links, SEO spam shown only to search engines (cloaking), and malicious JavaScript such as fake browser-update and fake CAPTCHA loaders.
2. **Hijacked former domains.** When a hospital renames or merges, its old domain forwards for a while and then lapses. Gambling and pirate-streaming operators buy these names for the search reputation and inbound links they still carry, and some public directories keep sending people to them.

The scanner uses only what any visitor can see. It never logs in, submits forms or probes for software vulnerabilities, and it stops at bot checks instead of trying to get past them.

## Results: every hospital in Iowa, November 2026

| | |
|---|---|
| Hospitals | 123 (82 critical access, 30 acute care, 11 psychiatric, rehabilitation, long-term care and VA) |
| Live websites scanned | 85 sites, 3,568 pages |
| Pages compared as browser, Googlebot and Google-search visitor | 3,198 |
| Flagged by the scanner | 22, every one reviewed by hand |
| Confirmed | 2, both former hospital domains now hosting gambling |
| Former hospital domains checked | 58, of which 51 are still held by the hospital or its system |
| Sites behind bot walls | 6, checked through recent Internet Archive captures instead |

No live Iowa hospital website was serving injected content. Every real finding was on an address a hospital had stopped using: two former hospital domains now promote slot gambling and sports betting, and a third carried betting pages in 2021 and is now unregistered, even though a federal hospital dataset still lists it as the hospital's website.

Hospital names and domains are left out of this repository until the affected hospitals have been notified.

## How it works

| Step | Script | What it does |
|---|---|---|
| 1 | `roster.py` | Lists every CMS-certified hospital in a state (acute, critical access, psychiatric, children's, VA, rehabilitation, long-term care) and attaches candidate websites from the HIFLD hospital dataset |
| 2 | `probe.py` | Loads each candidate home page so you can confirm it belongs to the hospital. Record the confirmed site in the roster's `url` field |
| 3 | `jobs.py` | Groups hospitals by website. Hospitals that share a health system's site become one crawl job with a larger page budget |
| 4 | `scan.py` | Crawls each site and runs the content and cloaking checks below |
| 5 | `summarize.py` | Collects every flag, third-party script host and outbound domain for hand review |
| 6 | `domains.py`, `history.py`, `snap.py` | Checks former domains: DNS, registration records, and Internet Archive history to see who used each name and when it changed hands |
| 7 | `wayback_scan.py` | Runs the content checks on recent archived pages of sites that block automated visitors |

The method, the false positives to expect and how to read the domain signals are written up in [docs/method.md](docs/method.md).

## What the scanner checks

| Check | How |
|---|---|
| Cloaking | Every page is fetched as desktop Chrome, as Googlebot, and as iPhone Safari arriving from google.com. Different redirects or extra outbound domains for the search-engine views are flagged |
| Spam text and links | English and Indonesian gambling terms, pharmacy and adult terms, and runs of Chinese or Japanese text, in page text and link targets |
| Hidden link blocks | Elements hidden with CSS (`display:none`, off-screen positioning, zero font size) that hold outbound links |
| Injected JavaScript | Packed or encoded loaders, smart-contract loaders (ClearFake / EtherHiding), clipboard-command fake CAPTCHAs (ClickFix), fake browser updates, SocGholish beacons, off-site redirects |
| Sitemaps and robots.txt | Every sitemap URL is read and checked for spam doorway pages and off-site entries |
| Third-party scripts and links | Script, iframe and link domains are collected so lapsed or unfamiliar ones can be checked |

## Quick start

Python 3.10 or newer built against OpenSSL (see the notes below), plus `curl` and `dig`. There are no third-party packages.

```bash
python3 scanner/roster.py IA > roster.json
```

Confirm each hospital's site, then fill in `url` for each entry in `roster.json`:

```bash
python3 scanner/probe.py urls.txt probe.json
```

```bash
python3 scanner/jobs.py roster.json > jobs.json
```

```bash
python3 scanner/scan.py jobs.json out 16 2.5
```

```bash
python3 scanner/summarize.py out summary.json
```

```bash
python3 scanner/domains.py former_domains.txt domains.json
```

```bash
python3 scanner/history.py history.json olddomain.org
```

```bash
python3 scanner/wayback_scan.py blocked-site.org --out archive_out
```

`scan.py` runs 16 sites at a time but each site strictly one request at a time. A 40-page site takes about five minutes; a state of 90 sites took about 45 minutes. Finished sites are skipped on a rerun, so an interrupted scan picks up where it stopped. [examples/jobs.example.json](examples/jobs.example.json) shows the job format.

## Responsible use

- Plain GET requests only. No logins, forms, parameter fuzzing or vulnerability probing.
- One request at a time per site, 2.5 seconds apart or the site's `Crawl-delay` if longer. A Wordfence rate-limit page triggers a 90-second back-off.
- The first bot challenge (Cloudflare, Akamai, Incapsula, Sucuri) ends the crawl of that site. Those sites are checked through the Internet Archive instead; the scanner never tries to get past a bot check.
- The Googlebot and Google-referral profiles exist only to compare what search engines and search visitors are served with what a browser gets.
- Report findings privately to the hospital first, and keep names and domains out of anything public until it has had time to act.

## Limitations

- It samples pages: 40 per site (up to 140 for large system sites), drawn from the home page's links and a random pick from the sitemap.
- It sees only what visitors see. A backdoor that doesn't change the rendered pages, or an outdated plugin, won't show up.
- Sites that refuse a self-declared Googlebot from a non-Google address can only be compared as browser versus search visitor.
- Sites behind bot walls get an archive check, which rules out injected content as of the capture date but not cloaking.
- The keyword lists cover the common English, Indonesian, Chinese and Japanese injections. Other languages need additions.
- Domain grouping uses a short suffix rule, not the full public-suffix list.

## Notes on running it

- The Python that ships with macOS is built on LibreSSL 2.8 and fails TLS handshakes with many hospital sites. Use a Python built on OpenSSL 3, for example `uv venv --python 3.12`.
- The CMS provider-data API answers 403 to requests that set a custom User-Agent, so `roster.py` sends the default one.
- The Internet Archive's page playback answers 429 to bursts. The archive tools fetch one capture every 7 seconds and go through `curl`, which handled networks without a working IPv6 route better than Python's `urllib`.

## License

MIT. See [LICENSE](LICENSE).
