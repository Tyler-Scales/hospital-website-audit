# Statewide audit method (Iowa, November 2026)

This is how a statewide audit runs, start to finish, with what the Iowa run (November 2026) taught about each stage.

## 1. Build the roster

CMS publishes every certified hospital, but not their websites.

- **Hospitals:** `roster.py` pulls three CMS provider-data sets for the state: Hospital General Information (acute care, critical access, psychiatric, children's, VA), Inpatient Rehabilitation Facility, and Long-Term Care Hospital. Hospital-based rehab units (CCNs with a letter in the third position, like `16T030`) are dropped because their parent hospital is already listed.
- **Websites:** each hospital gets candidate sites from the HIFLD hospital layer, a federal dataset with a website field. Its records date from 2016 to 2018, so many are stale. That makes HIFLD a lead list for current sites and the main source of former domains.
- **Confirm each site:** load every candidate with `probe.py` and check that the title or opening text names the hospital. Where it doesn't, search for the hospital's site and confirm that instead. System-owned hospitals usually live on the system's domain.

In Iowa, roughly one site in ten needed a search: domains had changed since the HIFLD records, several hospitals had no website in HIFLD at all, and one hospital's listed domain turned out to host only its VPN login while the public site lived on another name.

## 2. Crawl each site

`scan.py` treats each website as one job and crawls it single-threaded.

- **Pages:** the home page, the links on it, then a random draw from the sitemap so news posts and deep pages are covered, not just the menu. The cap is 40 pages per site, and 40 plus 8 per hospital (up to 140) for a system site serving several hospitals.
- **Three visitor types per page:** desktop Chrome; Googlebot; iPhone Safari with a google.com referrer. Injected spam is often served only to search engines or only to visitors arriving from a search, so each page is compared across all three.
- **Pacing:** 2.5 seconds between requests, or the site's `Crawl-delay` up to 10 seconds. Many hospital WordPress sites run Wordfence, which returns a 503 "access limited" page to fast crawlers; the scanner recognizes it and backs off.
- **Bot walls:** the first Cloudflare, Akamai, Incapsula or Sucuri challenge ends the crawl for that site. Check whether the hospital's pages live on an unprotected subdomain (one system's hospital pages were on a separate `locations.` host), and otherwise use step 5.

Nine Iowa sites refused the Googlebot profile outright, because their firewalls verify that Googlebot comes from Google's addresses. That isn't cloaking. On those sites only the browser and search-visitor views can be compared.

## 3. Review every flag by hand

The checks are tuned to over-report. In Iowa, 19 live sites were flagged and every flag was legitimate content:

| What the scanner saw | Sites | What it was |
|---|---:|---|
| Runs of Chinese characters | 9 | Language-assistance and nondiscrimination notices that hospitals are required to post |
| Extra links for Googlebot or the phone view | 4 | Mobile menus, a page builder pre-rendering for search engines, a donation form rendered server-side |
| Script redirecting off-site | 3 | The "search by Algolia" badge in a WordPress search plugin |
| "Update your browser" | 1 | An Internet Explorer-only notice inside a conditional comment |
| Hidden outbound links | 1 | Collapsed accordion sections holding ordinary links |
| "xxx", "online pharmacy", refresh to another domain | 3 | A phone-number format hint, a health system's own pharmacy link, an old domain forwarding to the current site |

Since that run, the scanner ignores HTML comments, which removes the IE-only notice and commented-out script tags from the checks.

Beyond the flags, `summarize.py` lists every third-party script host and outbound link domain. Resolve each script host: a script loaded from a domain that has lapsed lets whoever registers it run code on the hospital's pages. For outbound links, check domains that no longer resolve against RDAP; an unregistered one can be bought and filled with anything while the hospital's page still links to it.

## 4. Check former domains

This is where Iowa's real findings came from.

**Sources:** every domain in the state's HIFLD records that isn't a current site, plus old names from mergers and rebrands. Expect a share of guessed names never to have belonged to a hospital; in Iowa, 5 of the merger-list names were unrelated organizations or always parked, and 8 had never been registered.

**Signals** (`domains.py`):

| Signal | What it suggests |
|---|---|
| Forwards to the current site, or sits on the system's own nameservers | Still held. This is the right practice for retired names |
| RDAP creation date after the hospital stopped using the name | Re-registered by someone else |
| Marketplace or parking nameservers (Afternic, a registrar's marketplace, a parking network) | For sale or monetized by a domainer |
| RDAP 404 and no nameservers | Unregistered. Anyone can buy it. (Some registries, `.us` among them, aren't in RDAP at all, so a 404 for a name that still has nameservers means nothing) |
| Archive shows parked or unrelated content from the first capture | Never the hospital's; leave it out |

An old creation date does not prove the hospital still owns a name. Registrars' expired-domain auctions transfer names before they are deleted, which keeps the original creation date. Look at the nameservers and the current content too.

**History** (`history.py`, then `snap.py`): read one archived page per year to find the last capture that was the hospital's and the first that wasn't. In Iowa, the pattern was consistent: hospital pages, then a few years of forwarding, then a stranger's blog, pirate-streaming site or betting site.

**What to recommend:**

- Keep retired names registered and forwarding. It costs about $10 a year per name.
- Register any former name that is now unregistered, especially one a public directory still lists.
- For a name that changed hands and uses the hospital's trademark, a UDRP complaint is the formal route back.
- Check printed materials, directory listings and business profiles for old addresses.

## 5. Sites that block automated visitors

`wayback_scan.py` reads the most recent archived copy of up to 12 pages captured since a cutoff date and runs the same content checks. That rules out injected content as of each capture date. It cannot test cloaking, because the archive fetches each page once as a single client. Report these sites as archive-checked, and offer a live scan from an address the hospital allow-lists.

The archive's playback answers 429 to bursts. Fetch one capture every 7 seconds, one domain at a time; the CDX index tolerates more.
