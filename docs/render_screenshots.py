"""Render the HTML mockups to PNG using headless Chrome.

Run this any time you change the mock HTML files. The output PNGs are
committed to the repo so the README always has up-to-date screenshots.
"""
import os, subprocess

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = ROOT  # write PNGs directly to the project root / docs sibling
DOCS = os.path.join(ROOT, "docs")
os.makedirs(DOCS, exist_ok=True)

mocks = [
    ("docs/popup_mock.html",    "screenshot-chrome-popup.png", 380, 700),
    ("docs/telegram_mock.html", "screenshot-telegram.png",     540, 1000),
]

for src, dst, w, h in mocks:
    src_path = os.path.join(ROOT, src).replace(os.sep, "/")
    dst_path = os.path.join(DOCS, dst)
    cmd = [
        CHROME, "--headless=new", "--disable-gpu", "--no-sandbox",
        f"--window-size={w},{h}",
        f"--screenshot={dst_path}",
        f"file:///{src_path}",
    ]
    print(f"  rendering {src} -> docs/{dst}  ({w}x{h})")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        print(f"    stderr: {r.stderr.strip()[:200]}")
    else:
        size = os.path.getsize(dst_path)
        print(f"    wrote {dst_path}  ({size:,} bytes)")
