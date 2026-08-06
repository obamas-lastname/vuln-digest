# vuln-digest

A daily-refreshed page with 3-5 recent low-level vulnerability writeups (kernel, browser/JIT,
memory corruption, CTF pwn, hardware side-channels), pulled from a curated set of research blogs.

- **Page:** https://obamas-lastname.github.io/vuln-digest/
- **Generator:** `generate.py` — stdlib-only Python script that fetches a fixed list of RSS/Atom
  feeds, filters for low-level-vuln relevance, picks up to 5 diverse recent entries, and renders
  `docs/index.html`.
- **Schedule:** GitHub Actions (`.github/workflows/digest.yml`) runs it daily at 08:00
  Europe/Bucharest and commits the regenerated page. GitHub Pages serves `docs/` on push.

To add a bookmark-able "check today's picks" shortcut on your phone: open the page in your
mobile browser and use "Add to Home Screen".

## Feeds

Project Zero, Google Security Blog, ZDI Blog, ret2 systems, GitHub Security Lab,
Exodus Intelligence, Trail of Bits, willsroot, a13xp0p0v (Linux kernel security).

## Local run

```
python3 generate.py
```
