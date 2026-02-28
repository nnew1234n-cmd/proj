"""
broadcom_listing.py - Selenium-based fetcher for Broadcom Security Advisory Notifications.

The Broadcom advisory listing page is JS-rendered and protected by CSRF tokens + session cookies.
This module:
  1. Uses Selenium Chrome (headless) to load the page and establish a valid session.
  2. Reads the session cookies and calls the internal advisory listing JSON API directly.
  3. Auto-detects the TOTAL number of pages from the first-page `totalRecords` field.
  4. Fetches ALL pages (with a polite delay between requests) up to a configurable cap.
  5. Sorts all advisories by published date DESCENDING (newest first) before returning.

[FUTURE UPDATE - GitHub Actions]:
  When running in CI, ensure DISPLAY is set or use XVFB for headless mode:
    export DISPLAY=:99 && Xvfb :99 -screen 0 1280x800x24 &
  Or just set options.add_argument('--headless') which is already done.
"""

import logging
import math
import re
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

logger = logging.getLogger(__name__)

LISTING_URL = "https://support.broadcom.com/web/ecx/security-advisory"
API_URL     = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"
SEGMENT     = "VC"     # 'VC' = VMware Cloud Foundation advisories

# Date formats that Broadcom uses in the 'published' and 'updated' fields
_DATE_FORMATS = [
    "%d %B %Y",               # "26 February 2026"
    "%B %d, %Y",              # "February 26, 2026"
    "%Y-%m-%d %H:%M:%S.%f",  # "2026-01-24 05:14:24.820000"  (updated field)
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
]


def _parse_date(raw: Optional[str]) -> datetime:
    """
    Parses a date string from the Broadcom API into a datetime object.
    Falls back to epoch (datetime.min) if the string cannot be parsed.
    """
    if not raw:
        return datetime.min
    raw = raw.strip()
    # Handle trailing fractional seconds that aren't zero-padded (e.g. '.82')
    # Pad to 6 digits so %f works correctly
    raw_padded = re.sub(r'\.(\d{1,5})$', lambda m: '.' + m.group(1).ljust(6, '0'), raw)
    for attempt in [raw_padded, raw]:
        for fmt in _DATE_FORMATS:
            try:
                return datetime.strptime(attempt, fmt)
            except ValueError:
                continue
    # Last-resort: extract YYYY-MM-DD with regex
    m = re.search(r'(\d{4})-(\d{2})-(\d{2})', raw)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass
    logger.debug(f"Could not parse date string: {raw!r}")
    return datetime.min


def _get_selenium_session() -> Tuple[webdriver.Chrome, Dict[str, str], str]:
    """
    Launches a headless Chrome browser, loads the Broadcom advisory listing page
    to establish a valid session, then extracts cookies and the CSRF token.

    Returns:
        (driver, cookies_dict, csrf_token)
    """
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1280,800")
    options.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=options
    )

    logger.info(f"Loading Broadcom listing page for session: {LISTING_URL}")
    driver.get(LISTING_URL)

    # Wait until the advisory table rows appear (max 45s)
    try:
        WebDriverWait(driver, 45).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "table tbody tr"))
        )
        logger.info("Advisory listing table loaded — session established.")
    except Exception:
        logger.warning("Timed out waiting for advisory table. Proceeding with available cookies.")

    # Additional settle time for all AJAX to complete
    time.sleep(3)

    # Extract cookies
    selenium_cookies = driver.get_cookies()
    cookies_dict = {c["name"]: c["value"] for c in selenium_cookies}

    # Try extracting CSRF token: cookie → meta tag → hidden input (priority order)
    csrf_token = cookies_dict.get("CSRF_TOKEN", "")
    if not csrf_token:
        for js_expr in [
            "return document.querySelector('meta[name=\"_csrf\"]')?.content ?? '';",
            "return [...document.querySelectorAll('input')].find(i => i.name.includes('csrf') || i.name.includes('token'))?.value ?? '';",
        ]:
            try:
                csrf_token = driver.execute_script(js_expr) or ""
                if csrf_token:
                    break
            except Exception:
                pass

    logger.info(f"CSRF token: {'[present]' if csrf_token else '[not found — proceeding without]'}")
    return driver, cookies_dict, csrf_token


def _fetch_page(
    page_number: int,
    page_size: int,
    segment: str,
    cookies_dict: Dict[str, str],
    csrf_token: str,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Calls the Broadcom advisory listing API for a single page.

    Returns:
        (items, total_records)
        items        — list of advisory metadata dicts from this page
        total_records — total count from the API (non-zero only on first page)
    """
    payload = {
        "pageNumber": page_number,
        "pageSize":   page_size,
        "searchVal":  "",
        "segment":    segment,
        "sortInfo":   {"column": "", "order": ""},
    }

    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Accept":        "application/json, text/plain, */*",
        "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Referer":       LISTING_URL,
    }
    if csrf_token:
        headers["x-csrf-token"] = csrf_token

    try:
        response = requests.post(
            API_URL,
            json=payload,
            headers=headers,
            cookies=cookies_dict,
            timeout=30,
        )
    except requests.RequestException as e:
        logger.error(f"HTTP error on page {page_number}: {e}")
        return [], 0

    if response.status_code != 200:
        logger.error(f"Page {page_number}: HTTP {response.status_code} — {response.text[:300]}")
        return [], 0

    try:
        data = response.json()
    except Exception as e:
        logger.error(f"Page {page_number}: JSON decode error — {e}")
        return [], 0

    if not data.get("success"):
        logger.warning(f"Page {page_number}: API returned success=false. Response: {str(data)[:200]}")
        return [], 0

    payload_data = data.get("data", {})
    items = payload_data.get("list", [])

    # totalRecords: Broadcom puts it inside each row's field on page 0
    total_records: int = payload_data.get("totalRecords", 0) or 0
    if not total_records:
        for item in items:
            tr = item.get("totalRecords")
            if tr:
                try:
                    total_records = int(tr)
                    break
                except (ValueError, TypeError):
                    pass

    return items, total_records


def fetch_advisory_notification_ids(
    page_size:    int  = 20,
    max_pages:    int  = 100,   # Safety cap — 100 pages × 20 = 2000 advisories max
    segment:      str  = SEGMENT,
    sort_by_date: bool = True,
) -> List[Dict[str, Any]]:
    """
    Fetches ALL Broadcom Security Advisory notification IDs for the given segment.

    Strategy:
      1. Establish a Selenium session (headless Chrome) to get cookies/CSRF.
      2. Fetch page 0 to discover `totalRecords` from the API.
      3. Calculate total pages = ceil(totalRecords / page_size), capped at max_pages.
      4. Fetch all remaining pages with a 0.5s polite delay between each request.
      5. De-duplicate by notificationId.
      6. Sort all results by `updated` / `published` date DESCENDING (newest first).

    Args:
        page_size:    Advisories per API page (Broadcom default = 20).
        max_pages:    Hard cap to prevent runaway pagination.
        segment:      Portal segment code — 'VC' = VMware Cloud Foundation.
        sort_by_date: If True (default), results are sorted newest-first.

    Returns:
        List of advisory metadata dicts, newest first:
        [
          {
            'notificationId': 36986,
            'notificationUrl': 'https://support.broadcom.com/.../36986',
            'documentId': 'VCDSA36986',
            'title': '...',
            'severity': 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW',
            'published': '26 February 2026',
            'updated':   '2026-02-26 10:12:12.766',
            'status':    'OPEN'|'CLOSED',
            'affectedCve': 'CVE-...',
            'workAround':  '...',
          },
          ...
        ]
    """
    driver = None
    try:
        driver, cookies_dict, csrf_token = _get_selenium_session()

        all_advisories: List[Dict[str, Any]] = []
        seen_ids: set = set()

        # ── Page 0: discover total records ───────────────────────────────────
        logger.info(f"[Page 1] Fetching page 1 (discovery) | segment={segment} | page_size={page_size}")
        first_items, total_records = _fetch_page(0, page_size, segment, cookies_dict, csrf_token)

        if not first_items:
            logger.warning("No advisories returned on page 1. Returning empty list.")
            return []

        for item in first_items:
            nid = item.get("notificationId")
            if nid and nid not in seen_ids:
                seen_ids.add(nid)
                all_advisories.append(item)

        # ── Compute total pages to fetch ──────────────────────────────────────
        if total_records and total_records > page_size:
            ideal_pages = math.ceil(total_records / page_size)
            total_pages = min(ideal_pages, max_pages)
            logger.info(
                f"API reports {total_records} total advisories → "
                f"{ideal_pages} pages needed → fetching {total_pages} "
                f"(page_size={page_size}, max_pages={max_pages})"
            )
        else:
            # If totalRecords not available, use a conservative default
            total_pages = max_pages
            logger.info(
                f"totalRecords not available from API. "
                f"Will fetch up to {max_pages} pages and stop when empty."
            )

        # ── Fetch remaining pages ─────────────────────────────────────────────
        for page_num in range(1, total_pages):
            time.sleep(0.5)  # Polite rate limit

            logger.info(f"[Page {page_num + 1}/{total_pages}] Offset {page_num * page_size}")
            items, _ = _fetch_page(page_num, page_size, segment, cookies_dict, csrf_token)

            if not items:
                logger.info(f"Page {page_num + 1} returned 0 items — end of listing reached.")
                break

            added = 0
            for item in items:
                nid = item.get("notificationId")
                if nid and nid not in seen_ids:
                    seen_ids.add(nid)
                    all_advisories.append(item)
                    added += 1

            dupes = len(items) - added
            logger.info(f"  → {len(items)} items: {added} new, {dupes} duplicates")

        logger.info(
            f"Pagination complete: {len(all_advisories)} unique advisories "
            f"across all pages (segment={segment})."
        )

        # ── Sort by date DESCENDING (newest first) ────────────────────────────
        if sort_by_date and all_advisories:
            def sort_key(adv: Dict) -> datetime:
                # 'updated' is more precise (includes time); fall back to 'published'
                return _parse_date(adv.get("updated") or adv.get("published"))

            all_advisories.sort(key=sort_key, reverse=True)

            newest = all_advisories[0]
            oldest = all_advisories[-1]
            logger.info(
                f"Sorted newest→oldest: "
                f"{newest.get('documentId')} ({newest.get('published', '?')}) → "
                f"{oldest.get('documentId')} ({oldest.get('published', '?')})"
            )

        return all_advisories

    except Exception as e:
        logger.error(f"Error during advisory listing fetch: {e}", exc_info=True)
        return []
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    advisories = fetch_advisory_notification_ids(sort_by_date=True)
    print(f"\n{'='*75}")
    print(f"  Total VMware advisories fetched: {len(advisories)}")
    print(f"{'='*75}")
    for adv in advisories:
        sev  = adv.get("severity", "?")
        did  = adv.get("documentId", "?")
        pub  = adv.get("published", "?")
        stat = adv.get("status", "?")
        title = adv.get("title", "")[:65]
        print(f"  [{sev:8s}] {did:15s} {pub:22s} [{stat}] {title}")
    print(f"{'='*75}\n")
