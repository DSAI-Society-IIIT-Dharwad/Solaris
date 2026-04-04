# cve_scorer.py
import re
import time
import os
import requests
from dotenv import load_dotenv

load_dotenv()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# Simple in-memory cache so we don't re-query the same image twice in one run
_cache = {}

# Known vendor names that signal a false positive when the keyword
# appears only once and one of these dominates the description
KNOWN_VENDORS = [
    "honeywell", "jantek", "siemens", "cisco", "juniper", "microsoft",
    "oracle", "vmware", "fortinet", "palo alto", "checkpoint", "dell",
    "hp ", "ibm ", "samsung", "lg electronics", "hikvision", "dahua",
    # Telecom / ISP hardware vendors (common source of busybox false positives)
    "at&t", "arris", "nvg589", "nvg599", "u-verse", "netgear", "d-link",
    "zyxel", "huawei", "asus", "linksys", "belkin", "technicolor",
    "sagemcom", "motorola", "ubiquiti", "mikrotik", "tp-link", "tenda",
    # Industrial / embedded
    "schneider", "rockwell", "abb ", "emerson", "ge ", "bosch",
    "advantech", "moxa", "wago", "phoenix contact",
]


def parse_image_tag(image_string):
    """
    Extracts a clean (name, version) tuple from an image string.

    Examples:
      "nginx:1.25.3"           -> ("nginx", "1.25.3")
      "redis:7.2-alpine"       -> ("redis", "7.2")
      "gcr.io/project/app:v2"  -> ("app", "2")
      "busybox"                -> ("busybox", None)
    """
    # Strip registry prefix (anything before the last '/')
    base = image_string.split("/")[-1]

    # Split on ':' to get name and tag
    if ":" in base:
        name, tag = base.split(":", 1)
    else:
        name, tag = base, None

    # Extract numeric version from tag (e.g. "v1.25.3-alpine" -> "1.25.3")
    version = None
    if tag:
        match = re.search(r'[\d]+\.[\d.]+', tag)
        version = match.group(0) if match else None

    return name.lower(), version


def _is_false_positive(keyword_lower, desc_lower):
    """
    Returns True if the CVE is likely a false positive for this keyword.

    Two checks:
      1. Keyword must appear as a whole word (not a substring of another word).
      2. If it appears only once AND a known unrelated vendor dominates
         the description, it is a passing mention — not the vulnerable product.
    """
    # Check 1: whole-word match
    if not re.search(rf'\b{re.escape(keyword_lower)}\b', desc_lower):
        return True

    # Check 2: keyword mentioned only once alongside a dominant vendor name
    if desc_lower.count(keyword_lower) == 1:
        if any(vendor in desc_lower for vendor in KNOWN_VENDORS):
            return True

    return False


def query_nvd_api(keyword, version=None):
    """
    Calls the NIST NVD API and returns a list of CVE dicts.
    Each dict has: cve (str), cvss (float), desc (str).

    Strategy:
      - Tries versioned query first (e.g. "nginx 1.25.3").
      - Falls back to keyword-only (e.g. "nginx") if no results.
      - Filters false positives before returning.
    """
    cache_key = f"{keyword}:{version}"
    if cache_key in _cache:
        return _cache[cache_key]

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # Build query list: versioned first, then plain keyword as fallback
    queries_to_try = []
    if version:
        queries_to_try.append(f"{keyword} {version}")
    queries_to_try.append(keyword)

    raw_results = []
    for query in queries_to_try:
        params = {"keywordSearch": query, "resultsPerPage": 15}
        try:
            response = requests.get(
                NVD_API_URL, params=params, headers=headers, timeout=10
            )
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            print(f"  [!] NVD API error for '{query}': {e}")
            break

        # Respect NVD rate limit: 50 req/30s with key (~0.6s), 5/30s without (6s)
        sleep_time = 0.6 if NVD_API_KEY else 6.0
        time.sleep(sleep_time)

        raw_results = data.get("vulnerabilities", [])
        if raw_results:
            break  # got results, skip fallback query

    results = []
    for item in raw_results:
        cve_obj = item.get("cve", {})
        cve_id = cve_obj.get("id", "UNKNOWN")

        # Extract English description
        descriptions = cve_obj.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "No description"
        )

        # --- False positive filter ---
        if _is_false_positive(keyword.lower(), desc.lower()):
            continue

        desc = desc[:120]  # truncate for display

        # Extract CVSS score — prefer v3.1 > v3.0 > v2
        cvss_score = 0.0
        metrics = cve_obj.get("metrics", {})
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                break

        if cvss_score > 0:
            results.append({
                "cve": cve_id,
                "cvss": cvss_score,
                "desc": desc
            })

    # Worst CVE first
    results.sort(key=lambda x: x["cvss"], reverse=True)
    _cache[cache_key] = results
    return results


def fetch_live_cves(image_string):
    """
    Main entry point — drop-in replacement for detect_mock_cves().

    Returns: (list_of_cve_dicts, max_cvss_score)
    Identical return shape to the original so no other file needs to change.
    """
    name, version = parse_image_tag(image_string)

    # Skip non-queryable base images
    if not name or name in ("scratch", "distroless", "pause"):
        return [], 1.0

    cves = query_nvd_api(name, version)
    max_cvss = max((c["cvss"] for c in cves), default=1.0)

    return cves, max_cvss
