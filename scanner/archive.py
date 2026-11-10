"""Polite access to the Internet Archive's CDX index and page playback.

Playback answers HTTP 429 to bursts, so callers pause PAUSE seconds between captures and get()
backs off and retries. Requests go through curl: Python's urllib stalled for minutes against the
archive on networks without a working IPv6 route, while curl falls back to IPv4 on its own.
"""
import json
import subprocess
import time
import urllib.parse

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
PAUSE = 7  # seconds between playback requests; faster than this draws 429s after a few dozen fetches


def get(url, timeout=120, tries=4):
    """Return the body of a 200 response, "" for a 404, or raise after retrying 429/5xx/timeouts."""
    for attempt in range(tries):
        r = subprocess.run(["curl", "-sL", "--max-time", str(timeout), "-A", UA, "-w", "\n%{http_code}", url], capture_output=True)
        body, _, code = r.stdout.decode("utf-8", "replace").rpartition("\n")
        if code == "200":
            return body
        if code == "404":
            return ""
        if code in ("429", "502", "503", "504", "000"):
            time.sleep(15 * (attempt + 1))
            continue
        raise RuntimeError(f"HTTP {code} for {url}")
    raise RuntimeError(f"archive unavailable: {url}")


def cdx(**params):
    """Query the CDX index. Repeat a parameter by passing a list, e.g. filter=["statuscode:200", "mimetype:text/html"].
    Returns the rows without the header row."""
    params.setdefault("output", "json")
    body = get("https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params, doseq=True))
    rows = json.loads(body) if body.strip() else []
    return rows[1:]


def capture(ts, original):
    """URL of the raw archived page (id_ = no archive toolbar or link rewriting)."""
    return f"https://web.archive.org/web/{ts}id_/{original}"
