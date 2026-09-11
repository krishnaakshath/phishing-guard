"""
One-off / re-runnable generator for backend/known_favicons.json.

Fetches the real favicon for a curated list of commonly-impersonated
brands and stores its perceptual hash (pHash). This is checked into the
repo as static data - the running app never fetches these at request
time, only the *target* site's favicon (see threat_intel.check_favicon_hash).

Re-run this if a brand changes its favicon and the check starts missing it:
    python3 scripts/generate_favicon_hashes.py
"""

import json
import os
import sys

import imagehash
import requests
from PIL import Image
from io import BytesIO

# domain -> favicon URL. Kept small and deliberately limited to brands
# already treated as high-value impersonation targets elsewhere in this
# codebase (see SUSPICIOUS_KEYWORDS / brand lists in detector.py).
BRAND_FAVICONS = {
    'google.com': 'https://www.google.com/favicon.ico',
    'paypal.com': 'https://www.paypal.com/favicon.ico',
    'microsoft.com': 'https://www.microsoft.com/favicon.ico',
    'apple.com': 'https://www.apple.com/favicon.ico',
    'amazon.com': 'https://www.amazon.com/favicon.ico',
    'facebook.com': 'https://www.facebook.com/favicon.ico',
    'netflix.com': 'https://www.netflix.com/favicon.ico',
    'github.com': 'https://github.com/favicon.ico',
    'linkedin.com': 'https://www.linkedin.com/favicon.ico',
    'dropbox.com': 'https://www.dropbox.com/favicon.ico',
    'instagram.com': 'https://www.instagram.com/favicon.ico',
    'chase.com': 'https://www.chase.com/favicon.ico',
}


def fetch_phash(url: str):
    resp = requests.get(url, timeout=8, headers={'User-Agent': 'Mozilla/5.0 (PhishingGuard favicon fetcher)'})
    resp.raise_for_status()
    img = Image.open(BytesIO(resp.content))
    return str(imagehash.phash(img))


def main():
    output_path = os.path.join(os.path.dirname(__file__), '..', 'known_favicons.json')
    hashes = {}

    for domain, favicon_url in BRAND_FAVICONS.items():
        try:
            phash = fetch_phash(favicon_url)
            hashes[domain] = phash
            print(f"OK   {domain:20} {phash}")
        except Exception as e:
            print(f"SKIP {domain:20} {e}", file=sys.stderr)

    with open(output_path, 'w') as f:
        json.dump(hashes, f, indent=2, sort_keys=True)

    print(f"\nWrote {len(hashes)} favicon hashes to {output_path}")


if __name__ == '__main__':
    main()
