"""Fetch specific Wayback captures slowly and print each one's title and opening text.

Use it to pin down a hand-off date once domains.py or history.py shows roughly when it happened.

usage: python snap.py <timestamp> <url> [<timestamp> <url> ...]
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import archive  # noqa: E402
from history import title_and_text  # noqa: E402

args = sys.argv[1:]
for i, (ts, url) in enumerate(zip(args[::2], args[1::2])):
    if i:
        time.sleep(archive.PAUSE)
    try:
        title, text = title_and_text(archive.get(archive.capture(ts, url)))
    except Exception as e:
        title, text = f"(unavailable: {e})", ""
    print(f"== {ts[:8]} {url} | {title[:100]}\n   {text[:320]}", flush=True)
