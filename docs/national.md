# National critical access hospital scan (August–October 2026)

Every critical access hospital in the country, scanned for injected malicious content. Scan run August 28–30, 2026; confirmed findings rechecked October 22, 2026. Hospital names are withheld.

## Results

| | |
|---|---|
| Critical access hospitals | 1,382 in 45 states, from CMS |
| Distinct websites scanned | 1,075 (44,524 pages) |
| Flagged by the scanner | 16 |
| Confirmed compromised | 4 (0.37% of websites) |

The four confirmed cases:

- Three hospital sites carried hidden links to gambling and black-hat SEO networks, injected into the page markup. The shapes seen included an off-screen `<marquee>` block of backlinks added to every page through a WordPress footer hook, and a hidden block of links that included a foreign government domain. Two of the three were still live at the October recheck.
- One hospital's abandoned domain had been bought and now serves an Indonesian gambling site.

All four were small, independently run hospitals. That is the base rate, not a pattern: about nine in ten critical access hospital websites belong to a single hospital.

## Why 16 flags became 4

- **11 flagged addresses never belonged to the hospital.** CMS publishes no websites, so the roster's addresses were found by AI agents, and some were wrong: a lapsed domain now listed for sale, a parent system's page, and once a biography site about a famous person who shares the hospital's name. Each scanned "finding" on those addresses was real content on someone else's site.
- **1 pointed to a parent system's clean site.**
- **Every flag was checked against the domain's archive history**, using TypeSafe Jev judgments, and then read by hand.

The lesson: a wrong roster address produces a convincing false finding. Open the saved evidence and check the domain's history before believing any flag.

## How the roster was built

1. CMS Hospital General Information lists every critical access hospital: 1,382 at the time, in 45 states.
2. CMS has no website field. A Claude Code workflow sent AI agents to find each missing hospital's official site. A second, stronger pass retried the 412 that a weaker first pass couldn't resolve. 1,360 hospitals ended up with a website.
3. 228 of those addresses were matched only on hospital name, city and state and never confirmed. Addresses guessed during roster building produced the 11 false flags described below.

`scanner/roster.py ALL --cah` rebuilds the CMS side of this roster and attaches candidate websites from the HIFLD hospital dataset. Confirming each site is still a manual or agent-assisted step.

## How the scanner works

[`national/scan_all.py`](../national/scan_all.py) runs 30 hospitals at a time; each hospital's pages are fetched one after another.

- **Finding the site:** if the home page fails, it retries with a second browser User-Agent, the bare domain, then plain `http`, and records how it got through.
- **Choosing up to 40 pages:** the home page; then sitemap pages about billing, prices, financial assistance, estimates and patient information, because that is where one confirmed injection sat and where compliance content lives; then an even spread across the rest of the sitemap, with news, blog and event archives used only to fill leftover slots. Without that rule, news pages ate half the budget on large sites.
- **Evidence:** every flagged page's HTML is saved under `evidence/<ccn>/`.
- **Sitewide check:** for a high-severity hospital, it requests a made-up URL. Injected footers usually show up on the 404 page too, which separates sitewide injections from a single bad page.

There are no AI calls at scan time. [`national/signatures.py`](../national/signatures.py) is a set of byte-level signatures: reproducible, auditable, and free next to an inference call. AI was used where judgment was needed: finding websites, and deciding whether an archived page belonged to the hospital.

### Signatures and severity

| Signal | What it matches |
|---|---|
| Hidden external links | An off-screen or zero-size container that holds links to another domain. Both confirmed link injections take this shape, and no benign page examined ever did |
| Named spam vocabulary | Terms from known black-hat SEO networks (`hacklink`, `marsbahis`, `casibom`, `scommezoid`, `slot gacor`, `situs judi`, `togel`) |
| Gambling phrases | `online casino`, `slot machine`, `sports betting`, Turkish betting phrases. Counted only alongside another signal, since a hospital may mention problem-gambling services |
| Parked or expired domain | Domain-marketplace and parking-page text |
| Cloaking, `<marquee>`, obfuscated JavaScript | Weak signals on their own; corroboration only |

Hidden external links, named spam vocabulary, a parked domain, or cloaked gambling phrases rate **high**. Cloaking, a `<marquee>` or clustered obfuscation alone rate **low**, which means review it but don't report it.

### False positives fixed along the way

Each of these produced a wrong "high" or flooded the review queue before it was fixed. Don't reintroduce them:

1. **Bare gambling words.** `\bslot\b` matched a Divi theme CSS class and "reserve your time slot". Gambling terms must be phrases.
2. **A single `atob(` or `eval(`.** Ordinary minified analytics code has them. Obfuscation needs four or more hits and never raises severity on its own.
3. **Template skip links.** An off-screen "skip to content" link appears on every page of many themes; in one small state, 5 of 8 hospitals hit it on nearly every page. A cloaked container on 80% or more of a site's pages with no other signal is suppressed. Real injections looked different: one covered 2 of 396 pages, another came with spam vocabulary and a `<marquee>`.
4. **CSS and JavaScript files.** Assets are excluded by file extension and by Content-Type.
5. **Accessibility markup and ordinary hidden UI.** `.screen-reader-text`, `.visually-hidden` and the like are never a finding, and cloaking only counts when the hidden container links off-site. `display:none` is excluded entirely: alert bars, accordions, modals and event overlays use it, and counting it produced 25 false positives in one national pass.

## Provenance check with Jev

[`national/verify_provenance.py`](../national/verify_provenance.py) asks, for each high-severity domain: did this domain ever host *this* hospital's site, and what is it serving now?

- It takes five archived captures spread across the domain's history (first, three quartiles, last) plus the live page.
- For each one, TypeSafe's Jev model answers three structured questions: did this page belong to the named hospital in that city and state (a probability); is there enough content to tell (so "no" can be told apart from "can't tell"); and what kind of page is it (hospital, domain for sale, gambling or spam, another legitimate organization, error or empty).
- A domain whose captures never belonged to the hospital is a roster mistake. One that belonged and later turned into gambling or spam is a takeover.

This replaced brittle name matching, and it is what showed that most flags in the national run were roster mistakes rather than hacked hospitals.

## The serverless prototype

Before the run, the scanner was built as an Azure Durable Functions app (Flex Consumption, Python 3.12) with guardrails: at most 300 hospitals and 40 pages per hospital per run, batches of 25, a kill switch, and a monthly timer that audited one state on rotation, never an unattended national sweep. The national run itself was done locally with the same signatures, and the Azure project was deleted afterward. It isn't included here.

## Limits

- About one site in ten couldn't be reached: firewalls blocking automated visitors, plus bad roster addresses.
- The scanner detects the campaigns characterized here. "Clean" means none of them was visible, not that a site is uncompromised.
- It uses two browser User-Agents only, so it does not test cloaking aimed at search engines. The statewide pipeline in `scanner/` adds that.
