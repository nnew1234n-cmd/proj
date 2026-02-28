import os
import requests
import json
import csv
import time
import logging
#from datetime import datetime, timezone
from datetime import datetime, timezone, timedelta


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────

NVD_API_KEY = "cb6716d7-4126-4bb9-8928-a962fc5b79d6"
if not NVD_API_KEY:
    raise ValueError("NVD_API_KEY environment variable not set")

HEADERS = {"apiKey": NVD_API_KEY}

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RAW_JSON_OUT = "nvd_raw.json"
CSV_OUT = "nvd_summary.csv"
TIMESTAMP_FILE = "last_sync.txt"

# 120-day window maximum allowed by NVD for date range
MAX_DAYS_WINDOW = 120

# ─────────────────────────────────────────────────────────────
# UTIL: Read/Write Last Sync Time
# ─────────────────────────────────────────────────────────────

def get_last_sync_time() -> str:
    """Return ISO timestamp of last run or default of 30 days ago if none."""
    if os.path.exists(TIMESTAMP_FILE):
        with open(TIMESTAMP_FILE) as f:
            ts = f.read().strip()
            return ts
    # default: 30 days ago
    return (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

def save_last_sync_time(ts: str):
    with open(TIMESTAMP_FILE, "w") as f:
        f.write(ts)

# ─────────────────────────────────────────────────────────────
# FETCH FULL JSON DATA
# ─────────────────────────────────────────────────────────────

def fetch_full_nvd(last_mod_start: str):

    end_dt = datetime.now(timezone.utc)
    last_mod_end = end_dt.isoformat()

    logger.info(f"Fetching modified CVEs from: {last_mod_start} → {last_mod_end}")

    start_index = 0
    all_vulns = []

    while True:

        params = {
            "lastModStartDate": last_mod_start,
            "lastModEndDate": last_mod_end,
            "startIndex": start_index,
            "resultsPerPage": 2000
        }

        try:
            resp = requests.get(BASE_URL, headers=HEADERS, params=params, timeout=60)

            if resp.status_code == 429:
                logger.warning("Rate limited — sleeping 30s")
                time.sleep(30)
                continue

            resp.raise_for_status()
            data = resp.json()

        except Exception as e:
            logger.error(f"API failed: {e}")
            break

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        all_vulns.extend(vulns)

        total = data.get("totalResults", 0)
        start_index += len(vulns)

        logger.info(f"Fetched {start_index}/{total}")

        if start_index >= total:
            break

        time.sleep(0.3)

    # Save raw JSON
    with open(RAW_JSON_OUT, "w", encoding="utf-8") as f:
        json.dump({"vulnerabilities": all_vulns}, f, indent=2)

    logger.info(f"Saved RAW JSON → {RAW_JSON_OUT}")

    return all_vulns, last_mod_end

# ─────────────────────────────────────────────────────────────
# PARSE FOR CSV SUMMARY
# ─────────────────────────────────────────────────────────────

def export_summary_csv(vulns: list):

    rows = []
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        published = cve.get("published", "")[:10]
        modified = cve.get("lastModified", "")[:10]

        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        cvss_score = float(cvss_v3[0]["cvssData"].get("baseScore", 0)) if cvss_v3 else 0

        # Extract CPE strings (vendor:product:version)
        cpes = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    crit = match.get("criteria")
                    if crit:
                        parts = crit.split(":")
                        if len(parts) >= 5:
                            cpes.append(f"{parts[3]}:{parts[4]}:{parts[5]}")

        rows.append({
            "cve_id": cve_id,
            "published": published,
            "modified": modified,
            "cvss_score": cvss_score,
            "description": desc_en,
            "cpes": ",".join(cpes)
        })

    # Write CSV
    with open(CSV_OUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"Saved summary CSV → {CSV_OUT}")

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":

    last_sync = get_last_sync_time()
    vulns, new_sync_ts = fetch_full_nvd(last_sync)

    if vulns:
        export_summary_csv(vulns)

    save_last_sync_time(new_sync_ts)

    logger.info("SYNC COMPLETE")
