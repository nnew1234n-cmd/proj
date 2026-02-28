"""
pvvs/ingestion/broadcom_scraper.py

Broadcom Security Advisory ingestion pipeline.

Daily workflow:
  1. Fetch ALL advisory listing items (all pages, newest first) via Selenium.
  2. Load the local state file (processed_advisories.json) — a set of already-processed 
     notification IDs (numeric, e.g. 36986) to avoid re-processing.
  3. Filter the listing to NEW items only BEFORE fetching their detail pages.
  4. For each new item, fetch the advisory detail HTML page and parse it.
  5. Return only the newly parsed advisories. State is updated by main.py AFTER 
     successful correlation and reporting (not here).

Key design:
  - The state key is `notificationId` (integer from the listing API), NOT the VMSA ID.
    This avoids the VCDSA/VMSA dual-ID confusion where listing uses 'VCDSA36986' 
    but the HTML page shows 'VMSA-2026-0002'.
  - Detail page fetching is only done for NEW advisories (not all 337).
  - Parsing falls back to listing metadata if the detail page is unavailable.
"""

import csv
import json
import logging
import os
import time
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)

# State file — resolved relative to CWD (i.e. project root where main.py runs)
# Both broadcom_scraper.py and storage.py must use the same path.
STATE_FILE = "processed_advisories.json"



class BroadcomScraper:
    def __init__(self, url: str):
        self.url = url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        })

    # ── State Management ──────────────────────────────────────────────────────

    @staticmethod
    def load_processed_ids() -> Dict[str, Any]:
        """
        Loads the processed advisory state file.

        State format:
        {
          "processed_notification_ids": [36986, 36947, ...],   ← numeric IDs from listing
          "last_run": "2026-02-27T17:03:55",
          "total_processed": 20
        }

        Returns a dict with 'processed_notification_ids' as a set.
        Returns empty state on missing/corrupt file.
        """
        if not os.path.exists(STATE_FILE):
            return {"processed_notification_ids": set(), "last_run": None, "total_processed": 0}

        try:
            with open(STATE_FILE, "r") as f:
                raw = json.load(f)

            # Migrate old flat-list format (["VMSA-2026-0002",...]) to new dict format
            if isinstance(raw, list):
                logger.warning("Migrating state file from legacy list format to new dict format.")
                return {
                    "processed_notification_ids": set(),  # Can't recover old numeric IDs; start fresh
                    "last_run": None,
                    "total_processed": len(raw),
                }

            processed_ids = set(int(i) for i in raw.get("processed_notification_ids", []))
            return {
                "processed_notification_ids": processed_ids,
                "last_run": raw.get("last_run"),
                "total_processed": raw.get("total_processed", len(processed_ids)),
            }
        except Exception as e:
            logger.error(f"Failed to read state file {STATE_FILE}: {e}. Starting with empty state.")
            return {"processed_notification_ids": set(), "last_run": None, "total_processed": 0}

    @staticmethod
    def save_processed_ids(state: Dict[str, Any], newly_processed: List[int]) -> None:
        """
        Atomically updates the state file with newly processed notification IDs.
        Uses a temp file + rename to prevent corruption on crash.
        """
        from datetime import datetime, timezone
        existing_ids: Set[int] = state.get("processed_notification_ids", set())
        updated_ids = existing_ids | set(newly_processed)

        new_state = {
            "processed_notification_ids": sorted(updated_ids),
            "last_run": datetime.now(timezone.utc).isoformat(),
            "total_processed": len(updated_ids),
        }

        tmp_file = STATE_FILE + ".tmp"
        try:
            with open(tmp_file, "w") as f:
                json.dump(new_state, f, indent=4)
            os.replace(tmp_file, STATE_FILE)  # Atomic on Linux
            logger.info(
                f"State file updated: {len(updated_ids)} total processed "
                f"({len(newly_processed)} new this run)."
            )
        except Exception as e:
            logger.error(f"Failed to save state file: {e}")
            if os.path.exists(tmp_file):
                os.remove(tmp_file)

    # ── CVE / CVSS Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _clean_cves(raw_text: str) -> List[str]:
        """
        Extracts CVE IDs from any raw string, handling commas, 'and', 
        non-breaking spaces, <br/> tags, and newlines.
        """
        import re
        normalized = (
            raw_text
            .replace('\u00a0', ' ')
            .replace('\n', ',')
            .replace(' and ', ',')
        )
        cves = re.findall(r'CVE-\d{4}-\d+', normalized, re.IGNORECASE)
        return list(dict.fromkeys(cves))  # preserve order, deduplicate

    @staticmethod
    def _normalize_cvss(raw_cvss: str) -> float:
        """Converts CVSS strings like '7.8-9.8' or '4.4' → float max value."""
        import re
        nums = re.findall(r'[\d]+\.[\d]+|[\d]+', raw_cvss)
        if not nums:
            return 0.0
        return max(float(n) for n in nums)

    # ── HTML Parser ───────────────────────────────────────────────────────────

    def parse_advisory_html(self, html_content: str) -> Dict[str, Any]:
        """
        Parses the real Broadcom advisory page HTML.
        Extracts: advisory_id, title, severity, CVSS, CVEs, and the full
        Response Matrix (product/version/fixed/workaround per CVE group).
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        advisory: Dict[str, Any] = {}

        # 1. Title & Advisory ID (VMSA-YYYY-NNNN)
        title_el = soup.find('p', class_=lambda c: c and 'ecx-page-title-default' in c)
        if title_el:
            full_title = title_el.get_text(separator=' ', strip=True)
            advisory['advisory_id'] = full_title.split(':')[0].strip()
            advisory['title'] = full_title
        else:
            advisory['advisory_id'] = "UNKNOWN"
            advisory['title'] = "Unknown Title"

        # 2. Severity, CVSS, Status
        for label_el in soup.find_all('label', class_='edit-solution-labels'):
            label_text = label_el.get_text(strip=True)
            value_el = label_el.find_next_sibling('p')
            if not value_el:
                continue
            val = value_el.get_text(strip=True)
            if 'Severity' in label_text:
                advisory.setdefault('overall_severity', val.upper())
            elif 'CVSS' in label_text:
                advisory['max_cvss'] = val
                advisory['max_cvss_float'] = self._normalize_cvss(val)
            elif 'Status' in label_text:
                advisory['status'] = val

        # 3. Global CVE list
        advisory['cves'] = []
        cve_label = soup.find('label', string=lambda t: t and 'CVE' in t)
        if cve_label:
            sib = cve_label.find_next_sibling('p')
            if sib:
                advisory['cves'] = self._clean_cves(sib.get_text())

        # 4. Response Matrix — dynamic column detection
        affected_products = []
        for table in soup.find_all('table'):
            header_row = table.find('tr')
            if not header_row:
                continue
            headers = [th.get_text(strip=True).lower() for th in header_row.find_all(['th', 'td'])]
            if not (any('product' in h for h in headers) and any('version' in h for h in headers)):
                continue

            col_idx: Dict[str, int] = {}
            for i, h in enumerate(headers):
                if 'product'    in h: col_idx.setdefault('product',   i)
                elif 'version'  in h: col_idx.setdefault('version',   i)
                elif 'running'  in h: col_idx.setdefault('running_on',i)
                elif 'cve'      in h: col_idx.setdefault('cve',       i)
                elif 'cvss'     in h: col_idx.setdefault('cvss',      i)
                elif 'severity' in h: col_idx.setdefault('severity',  i)
                elif 'fixed'    in h: col_idx.setdefault('fixed',     i)
                elif 'workaround' in h: col_idx.setdefault('workaround', i)

            for row in table.find_all('tr')[1:]:
                cols = row.find_all('td')
                if not cols:
                    continue
                n = len(cols)

                def safe_get(key: str, default: str = '') -> str:
                    idx = col_idx.get(key)
                    return cols[idx].get_text(separator=',', strip=True) if (idx is not None and idx < n) else default

                product_name = safe_get('product')
                if not product_name:
                    continue

                cve_raw = safe_get('cve')
                cves_in_row = self._clean_cves(cve_raw) if cve_raw else []
                version_raw = safe_get('version')
                versions = [v.strip() for v in version_raw.split(',') if v.strip()] or ['N/A']

                for v in versions:
                    affected_products.append({
                        'product_name':      product_name,
                        'affected_versions':  [v],
                        'running_on':        safe_get('running_on') or 'Any',
                        'fixed_version':     safe_get('fixed') or 'See advisory',
                        'cves':              cves_in_row,
                        'cvss':              safe_get('cvss') or 'N/A',
                        'severity':          safe_get('severity') or advisory.get('overall_severity', 'N/A'),
                        'workaround':        safe_get('workaround') or 'None',
                    })
            break  # Only parse first matching table

        advisory['affected_products'] = affected_products

        # Backfill global CVEs from product rows if the label wasn't found
        if not advisory['cves'] and affected_products:
            all_cves: List[str] = []
            for ap in affected_products:
                all_cves.extend(ap.get('cves', []))
            advisory['cves'] = list(dict.fromkeys(all_cves))

        return advisory

    # ── Main Entry Point ──────────────────────────────────────────────────────

    def fetch_advisories(self) -> List[Dict]:
        """
        Fetches NEW Broadcom Security Advisories for daily processing.

        Pipeline:
          1. Fetch ALL listing pages (newest first) via Selenium.
          2. Load local state → identify which notificationIds are already processed.
          3. Filter to NEW items ONLY → avoid detail-page fetches for old advisories.
          4. For each new item, GET the advisory detail HTML page and parse it.
          5. Return list of fully-parsed advisory dicts for the correlation engine.
             (State update happens in main.py AFTER successful correlation.)

        Returns:
            List[Dict] — new advisories, each containing:
              advisory_id, title, overall_severity, max_cvss, max_cvss_float,
              cves, affected_products, notification_url, notification_id (int),
              published, updated, status
        """
        logger.info(f"Fetching advisories from: {self.url}")

        try:
            from broadcom_listing import fetch_advisory_notification_ids

            # ── Step 1: Fetch ALL listing pages (sorted newest first) ──────────
            logger.info("Fetching full advisory listing (all pages, newest first)...")
            listing_items = fetch_advisory_notification_ids(sort_by_date=True)

            if not listing_items:
                logger.warning("No advisory listing items returned. Using fallback static entry.")
                listing_items = [{
                    "notificationId":  36986,
                    "notificationUrl": "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/36986",
                    "documentId":      "VCDSA36986",
                    "title":           "VMSA-2026-0002: VMware Workstation and Fusion updates address multiple vulnerabilities",
                    "severity":        "MEDIUM",
                    "published":       "26 February 2026",
                    "affectedCve":     "CVE-2026-22715, CVE-2026-22716, CVE-2026-22717, CVE-2026-22722",
                    "workAround":      "None",
                }]

            logger.info(f"Total listing items fetched: {len(listing_items)}")

            # ── Step 2: Load state → set of already-processed notificationIds ──
            state = self.load_processed_ids()
            processed_ids: Set[int] = state["processed_notification_ids"]
            logger.info(
                f"State file: {len(processed_ids)} advisories already processed. "
                f"Last run: {state.get('last_run', 'never')}"
            )

            # ── Step 3: Filter to NEW items only ──────────────────────────────
            new_items = [
                item for item in listing_items
                if int(item.get("notificationId", 0)) not in processed_ids
            ]

            if not new_items:
                logger.info("All advisories are already processed. Nothing new to analyze.")
                return []

            logger.info(
                f"Found {len(new_items)} new advisories "
                f"(out of {len(listing_items)} total). "
                f"Fetching detail pages..."
            )

            # ── Step 4: Fetch detail pages for new items only ─────────────────
            advisories: List[Dict] = []
            for idx, item in enumerate(new_items, start=1):
                notification_url = item.get("notificationUrl", "")
                doc_id           = item.get("documentId", "UNKNOWN")
                notification_id  = int(item.get("notificationId", 0))

                logger.info(
                    f"  [{idx}/{len(new_items)}] Fetching detail: {doc_id} "
                    f"(published: {item.get('published', '?')})"
                )

                advisory_data: Dict[str, Any] = {}
                if notification_url:
                    try:
                        resp = self.session.get(notification_url, timeout=20)
                        if resp.status_code == 200:
                            advisory_data = self.parse_advisory_html(resp.text)
                        else:
                            logger.warning(
                                f"    HTTP {resp.status_code} for {doc_id}. "
                                f"Falling back to listing metadata."
                            )
                    except Exception as e:
                        logger.warning(f"    Could not fetch detail page for {doc_id}: {e}")

                # Fall back to listing metadata if detail parse failed
                if not advisory_data.get("advisory_id") or advisory_data.get("advisory_id") == "UNKNOWN":
                    raw_cves = [c.strip() for c in item.get("affectedCve", "").split(",") if c.strip()]
                    advisory_data = {
                        "advisory_id":      doc_id,
                        "title":            item.get("title", ""),
                        "overall_severity": item.get("severity", "UNKNOWN").upper(),
                        "max_cvss":         "N/A",
                        "max_cvss_float":   0.0,
                        "cves":             raw_cves,
                        "affected_products": [],
                        "status":           item.get("status", "UNKNOWN"),
                    }
                    logger.debug(f"    Using listing fallback metadata for {doc_id}.")

                # Enrich with listing metadata fields
                advisory_data["notification_id"]  = notification_id
                advisory_data["notification_url"] = notification_url
                advisory_data["published"]        = item.get("published", "")
                advisory_data["updated"]          = item.get("updated", "")
                advisory_data.setdefault("overall_severity", item.get("severity", "UNKNOWN").upper())
                advisory_data.setdefault("max_cvss", "N/A")
                advisory_data.setdefault("max_cvss_float", 0.0)
                advisory_data.setdefault("cves", [])
                advisory_data.setdefault("affected_products", [])

                advisories.append(advisory_data)

                # Polite delay between detail page fetches (avoid rate limiting)
                if idx < len(new_items):
                    time.sleep(0.3)

            logger.info(f"Fetched {len(advisories)} new advisory detail pages.")
            return advisories

        except Exception as e:
            logger.error(f"Failed to fetch advisories: {e}", exc_info=True)
            return []



def export_to_csv(advisories: List[Dict[str, Any]], filename: str = "broadcom_advisories.csv"):
    """Write a simple CSV summary of the advisory list.

    The columns mirror the keys that BroadcomScraper populates during
    fetch_advisories().  Lists such as ``cves`` are joined with commas.
    """
    if not advisories:
        logger.info("No advisories to export, skipping CSV.")
        return

    fieldnames = [
        "advisory_id",
        "title",
        "overall_severity",
        "max_cvss",
        "max_cvss_float",
        "cves",
        "notification_id",
        "published",
        "updated",
    ]

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for adv in advisories:
            row = {k: adv.get(k, "") for k in fieldnames}
            if isinstance(row.get("cves"), list):
                row["cves"] = ",".join(row["cves"])
            writer.writerow(row)
    logger.info(f"Saved CSV → {filename}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    scraper = BroadcomScraper("https://support.broadcom.com")
    advisories = scraper.fetch_advisories()
    print(f"\nNew advisories: {len(advisories)}")
    # export to CSV for workflow
    export_to_csv(advisories)
    for adv in advisories:
        print(f"  [{adv.get('overall_severity')}] {adv.get('advisory_id')} — {adv.get('title','')[:80]}")
        print(f"    CVEs: {', '.join(adv.get('cves',[])[:5])}")
        print(f"    Affected Products: {len(adv.get('affected_products', []))}")
