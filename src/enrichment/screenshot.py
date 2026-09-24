"""
screenshot.py
Captures screenshots of live domains using Playwright headless Chromium.
Supports brand-specific reference screenshot management and asset caching.
"""

import os
import shutil
from playwright.sync_api import sync_playwright

SCREENSHOT_DIR = "data/screenshots"
REFERENCE_DIR = "reference_assets"
DEFAULT_REFERENCE_PATH = os.path.join(REFERENCE_DIR, "brand_reference_screenshot.png")
REFERENCE_META_PATH = os.path.join(REFERENCE_DIR, "brand_reference_meta.txt")


def get_brand_reference_path(official_domain=None):
    """
    Returns path to reference screenshot for given brand domain,
    or falls back to default reference asset.
    """
    if not official_domain:
        return DEFAULT_REFERENCE_PATH if os.path.exists(DEFAULT_REFERENCE_PATH) else None

    clean_name = official_domain.lower().replace(".", "_").replace("-", "_")
    brand_path = os.path.join(REFERENCE_DIR, f"{clean_name}_reference.png")
    if os.path.exists(brand_path):
        return brand_path
    
    if os.path.exists(DEFAULT_REFERENCE_PATH):
        return DEFAULT_REFERENCE_PATH

    return None


def capture_screenshot(domain, timeout_ms=15000):
    """
    Attempts to load domain over HTTPS (falls back to HTTP) and captures
    a desktop viewport (1280x800) screenshot.
    Returns: file path on success, None on failure.
    """
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    safe_filename = domain.replace(".", "_").replace("*", "wildcard").replace(":", "_")
    output_path = os.path.join(SCREENSHOT_DIR, f"{safe_filename}.png")

    urls_to_try = [f"https://{domain}", f"http://{domain}"]

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 800})

            for url in urls_to_try:
                try:
                    page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                    page.wait_for_timeout(1500)
                    page.screenshot(path=output_path)
                    browser.close()
                    return output_path
                except Exception:
                    continue

            browser.close()
            return None
    except Exception as e:
        print(f"Playwright screenshot error for {domain}: {e}")
        return None


def ensure_reference_screenshot(official_domain):
    """
    Ensures a reference screenshot exists for the monitored brand.
    Saves brand-specific reference assets and updates fallback reference.
    """
    os.makedirs(REFERENCE_DIR, exist_ok=True)
    clean_name = official_domain.lower().replace(".", "_").replace("-", "_")
    brand_ref_path = os.path.join(REFERENCE_DIR, f"{clean_name}_reference.png")

    if os.path.exists(brand_ref_path):
        return brand_ref_path

    # Check if pre-existing screenshot exists in data/screenshots
    existing_shot = os.path.join(SCREENSHOT_DIR, f"{clean_name}.png")
    if os.path.exists(existing_shot):
        shutil.copy(existing_shot, brand_ref_path)
        return brand_ref_path

    print(f"Capturing reference screenshot for {official_domain}...")
    captured_path = capture_screenshot(official_domain)

    if captured_path:
        shutil.copy(captured_path, brand_ref_path)
        # Also maintain default fallback
        shutil.copy(captured_path, DEFAULT_REFERENCE_PATH)
        with open(REFERENCE_META_PATH, "w") as f:
            f.write(official_domain)
        print(f"Reference screenshot saved for {official_domain}: {brand_ref_path}")
        return brand_ref_path
    else:
        # Fall back to default if present
        if os.path.exists(DEFAULT_REFERENCE_PATH):
            return DEFAULT_REFERENCE_PATH
        print(f"WARNING: Could not capture reference screenshot for {official_domain}.")
        return None


if __name__ == "__main__":
    for d in ["paypal.com", "google.com"]:
        ref = ensure_reference_screenshot(d)
        print(f"Reference for {d}: {ref}")
