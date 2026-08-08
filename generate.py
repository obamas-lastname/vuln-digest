#!/usr/bin/env python3
"""Build docs/index.html: a daily pick of 3-5 recent low-level vulnerability writeups.

Stdlib only (no pip deps) so it runs unmodified in GitHub Actions.
"""
import html
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

FEEDS = [
    ("Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("Google Security Blog", "https://security.googleblog.com/feeds/posts/default"),
    ("ZDI Blog", "https://www.thezdi.com/blog?format=rss"),
    ("ret2 systems", "https://blog.ret2.io/feed.xml"),
    ("GitHub Security Lab", "https://github.blog/tag/github-security-lab/feed/"),
    ("Exodus Intelligence", "https://blog.exodusintel.com/feed/"),
    ("Trail of Bits", "https://blog.trailofbits.com/feed/"),
    ("willsroot", "https://www.willsroot.io/feeds/posts/default"),
    ("a13xp0p0v (Linux kernel security)", "https://a13xp0p0v.github.io/feed.xml"),
]

# Only used to filter out non-technical announcement/hiring/policy posts.
# The feed list itself is already low-level-vuln-focused, so this is a light filter.
KEYWORDS = re.compile(
    r"\b(kernel|heap|use[- ]after[- ]free|uaf|buffer overflow|overflow|memory corruption|"
    r"exploit|cve-\d|rce|remote code execution|sandbox escape|jit|v8|javascriptcore|"
    r"race condition|toctou|type confusion|rop|jop|side[- ]channel|spectre|meltdown|"
    r"firmware|driver|syscall|pwn|ctf|binary exploitation|fuzz|vulnerab|hypervisor|"
    r"privilege escalation|lpe|out[- ]of[- ]bounds|oob|null pointer|double free|"
    r"format string|integer overflow|stack overflow|zero[- ]day|0day|patch gap|"
    r"disclosure|attack surface|arbitrary (read|write)|code execution)\b",
    re.IGNORECASE,
)

MAX_AGE_DAYS = 14
TARGET_MIN = 3
TARGET_MAX = 5

NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "content": "http://purl.org/rss/1.0/modules/content/",
}


def strip_tags(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


_INVALID_XML_CHARS = re.compile(
    "[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]"
)
_BARE_AMPERSAND = re.compile(r"&(?!#\d+;|#x[0-9a-fA-F]+;|[a-zA-Z]+;)")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (vuln-digest bot)"})
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read()
    text = raw.decode("utf-8", errors="replace")
    text = _INVALID_XML_CHARS.sub("", text)
    text = _BARE_AMPERSAND.sub("&amp;", text)
    return text.encode("utf-8")


def parse_date(s):
    if not s:
        return None
    try:
        return parsedate_to_datetime(s)
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            d = datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def parse_feed(name, url):
    items = []
    try:
        raw = fetch(url)
        root = ET.fromstring(raw)
    except Exception as e:
        print(f"  ! {name}: fetch/parse failed ({e})")
        return items

    # RSS 2.0
    for item in root.findall(".//item"):
        title = strip_tags(item.findtext("title") or "")
        link = (item.findtext("link") or "").strip()
        pub = parse_date(item.findtext("pubDate"))
        desc = strip_tags(
            item.findtext("content:encoded", default="", namespaces=NS)
            or item.findtext("description")
            or ""
        )
        if title and link:
            items.append({"source": name, "title": title, "link": link, "date": pub, "summary": desc})

    # Atom
    for entry in root.findall("atom:entry", NS):
        title = strip_tags(entry.findtext("atom:title", default="", namespaces=NS))
        link_el = entry.find("atom:link[@rel='alternate']", NS)
        if link_el is None:
            link_el = entry.find("atom:link", NS)
        link = link_el.get("href").strip() if link_el is not None else ""
        pub = parse_date(
            entry.findtext("atom:published", default="", namespaces=NS)
            or entry.findtext("atom:updated", default="", namespaces=NS)
        )
        desc = strip_tags(
            entry.findtext("atom:summary", default="", namespaces=NS)
            or entry.findtext("atom:content", default="", namespaces=NS)
            or ""
        )
        if title and link:
            items.append({"source": name, "title": title, "link": link, "date": pub, "summary": desc})

    return items


def collect():
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=MAX_AGE_DAYS)
    all_items = []
    for name, url in FEEDS:
        entries = parse_feed(name, url)
        print(f"  - {name}: {len(entries)} entries")
        all_items.extend(entries)

    recent = [it for it in all_items if it["date"] and it["date"] >= cutoff]
    recent.sort(key=lambda it: it["date"], reverse=True)

    relevant = [it for it in recent if KEYWORDS.search(it["title"] + " " + it["summary"])]
    pool = relevant if len(relevant) >= TARGET_MIN else recent

    picked, seen_sources, seen_links = [], set(), set()
    # First pass: one per source, for diversity.
    for it in pool:
        if len(picked) >= TARGET_MAX:
            break
        if it["source"] in seen_sources or it["link"] in seen_links:
            continue
        picked.append(it)
        seen_sources.add(it["source"])
        seen_links.add(it["link"])
    # Second pass: fill remaining slots regardless of source repeats.
    if len(picked) < TARGET_MAX:
        for it in pool:
            if len(picked) >= TARGET_MAX:
                break
            if it["link"] in seen_links:
                continue
            picked.append(it)
            seen_links.add(it["link"])

    return picked


PAGE_TMPL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vuln-digest</title>
<style>
  :root {{
    color-scheme: light dark;
    --bg: #0b0d10; --fg: #e6e6e6; --muted: #9aa0a6; --card: #14171a; --accent: #7dd3fc; --border: #23262b;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{ --bg: #fafafa; --fg: #16181a; --muted: #5b6167; --card: #ffffff; --accent: #0369a1; --border: #e5e7eb; }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 1.5rem 1rem 3rem; background: var(--bg); color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    max-width: 720px; margin-inline: auto;
  }}
  header {{ margin-bottom: 1.5rem; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 0.25rem; }}
  .sub {{ color: var(--muted); font-size: 0.9rem; }}
  .card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 1rem 1.1rem; margin-bottom: 0.9rem;
  }}
  .source {{ color: var(--accent); font-size: 0.78rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }}
  .card h2 {{ font-size: 1.05rem; margin: 0.3rem 0 0.4rem; line-height: 1.35; }}
  .card h2 a {{ color: inherit; text-decoration: none; }}
  .card h2 a:hover {{ text-decoration: underline; }}
  .summary {{ color: var(--muted); font-size: 0.9rem; line-height: 1.45; margin: 0; }}
  .date {{ color: var(--muted); font-size: 0.78rem; margin-top: 0.5rem; }}
  footer {{ color: var(--muted); font-size: 0.78rem; text-align: center; margin-top: 2rem; }}
  footer a {{ color: var(--muted); }}
</style>
</head>
<body>
<header>
  <h1>vuln-digest</h1>
  <div class="sub">{count} low-level vulnerability writeups &middot; generated {generated}</div>
</header>
{cards}
<footer>Sources: {sources}.<br>Auto-generated daily. <a href="https://github.com/obamas-lastname/vuln-digest">source</a></footer>
</body>
</html>
"""

CARD_TMPL = """<article class="card">
  <div class="source">{source}</div>
  <h2><a href="{link}" target="_blank" rel="noopener">{title}</a></h2>
  <p class="summary">{summary}</p>
  <div class="date">{date}</div>
</article>
"""


def render(items):
    now = datetime.now(timezone.utc)
    cards = []
    for it in items:
        summary = it["summary"]
        if len(summary) > 240:
            summary = summary[:237].rsplit(" ", 1)[0] + "..."
        date_str = it["date"].strftime("%Y-%m-%d") if it["date"] else "unknown date"
        cards.append(CARD_TMPL.format(
            source=html.escape(it["source"]),
            link=html.escape(it["link"]),
            title=html.escape(it["title"]),
            summary=html.escape(summary),
            date=date_str,
        ))
    page = PAGE_TMPL.format(
        count=len(items),
        generated=now.strftime("%Y-%m-%d %H:%M UTC"),
        cards="\n".join(cards) if cards else "<p>No fresh writeups found today.</p>",
        sources=html.escape(", ".join(name for name, _ in FEEDS)),
    )
    return page


def main():
    print("Fetching feeds...")
    picked = collect()
    print(f"Picked {len(picked)} items:")
    for it in picked:
        print(f"  - [{it['source']}] {it['title']}")
    page = render(picked)
    import os
    os.makedirs("docs", exist_ok=True)
    with open("docs/index.html", "w", encoding="utf-8") as f:
        f.write(page)
    print("Wrote docs/index.html")


if __name__ == "__main__":
    main()
