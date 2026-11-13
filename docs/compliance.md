# Compliance audits (July–August 2026)

Where the work started: do rural hospital websites carry what three federal rules require? Hospital names are withheld.

## The rubric

| Rule | What a compliant site has |
|---|---|
| CMS hospital price transparency (45 CFR 180) | A machine-readable standard-charges file in the CMS template (CSV or JSON); a price estimator or a list of shoppable services; a `cms-hpt.txt` discovery file at the domain root naming the file |
| No Surprises Act | A notice of patients' rights and protections against balance billing; a notice that uninsured and self-pay patients can get a Good Faith Estimate |
| ACA Section 1557 | A nondiscrimination notice (including sex discrimination, under the 2024 rule); language-assistance taglines; how to file a complaint with the HHS Office for Civil Rights |

Each rule was scored compliant, partial, noncompliant, or undetermined when the site couldn't be read well enough to tell.

## Results

| Run | Sites | Price transparency met | No Surprises Act met | Section 1557 met | All three | Reviewed |
|---|---:|---:|---:|---:|---:|---|
| Iowa | 93 | 78 | 39 | 52 | 23 | July 27 |
| Alabama, Arkansas, Kentucky, Louisiana, Mississippi, Tennessee | 143 | 93 | 58 | 67 | 24 | August 5 |
| Georgia | 33 | 28 | 12 | 9 | 2 | August 26 |
| Florida | 12 | 12 | 6 | 6 | 5 | August 27 |
| **Total** | **281** | **211 (75%)** | **115 (41%)** | **134 (48%)** | **54 (19%)** | |

The most common gaps:

| Gap | Sites |
|---|---|
| No language-assistance taglines | 134 of 281 |
| No Good Faith Estimate notice | 103 of 188 (counted in the last three runs) |
| No Office for Civil Rights complaint information | 79 of 188 (last three runs) |
| No Section 1557 nondiscrimination notice | 49 of 188 (last three runs) |
| No machine-readable price file | 11 of 281 |

Price transparency was the best-kept rule, likely because CMS enforces it with penalties and vendors sell turnkey price files. The patient notices were the weakest. These are short, model-language notices that are quick to post.

## How the reviews ran

Each run was a Claude Code workflow. AI agents read each hospital's site against the rubric: home page, billing and financial-assistance pages, patient-rights pages and footer links. Each agent recorded what it found, with the page addresses, and a summary step tallied the results. Sites the agents couldn't load or read were scored undetermined rather than guessed.

Two things the agents could not do well led to the tooling here:

- **They can't see inside files.** An agent reading page text sees a link labeled "price transparency" but can't tell whether it leads to a CMS-format CSV, a PDF chargemaster, or a vendor page. The follow-up tooling verifies the files directly.
- **Some answers are facts about bytes.** Whether `cms-hpt.txt` exists at the domain root, whether the file returns 200, whether it carries the CMS template header and a current date: these are checks for code, not judgment.

The six-state review also flagged one hospital site for security reasons. Looking into it found injected gambling links, which led to the national security scan.

## The single-site check

[`compliance/compliance.py`](../compliance/compliance.py) runs the code side of this review on one site:

- lists home-page links about billing, pricing, patient rights and language access
- reads up to 80 pages (home-page links and relevant sitemap pages first) and counts which mention each topic: price transparency, No Surprises Act, Good Faith Estimate, nondiscrimination, language assistance, accessibility
- checks `cms-hpt.txt` and whether it has all five required fields
- verifies each charge file it finds: HTTP status, format (by extension, or by the response for vendor download links), CMS file name, CMS template header, and date

It reports where things appear. It doesn't judge whether a notice's wording satisfies the rule, and it doesn't read PDFs, where many hospitals post their notices; that part is still a reviewer's job.
