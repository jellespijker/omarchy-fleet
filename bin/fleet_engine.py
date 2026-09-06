#!/usr/bin/env python3
"""
fleet_engine.py
Unified telemetry, triage, and vulnerability management engine for FleetDM & osquery.
Shared by fleet-monitor (Quickshell QML widget) and fleet-triage (CLI Terminal).
Features:
  - CISA KEV active exploit cross-referencing
  - NIST NVD vulnerability link generation
  - Persistent ignore / mute management (~/.config/omarchy/fleet_ignored.json)
  - Full demo mode telemetry generation
  - Online/offline host classification
"""

import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.request
from typing import Dict, List, Any, Optional, Tuple

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.expanduser("~/.cache/omarchy-fleet")
os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._+@:/-]+$")

FLEET_CACHE_FILE = os.path.join(CACHE_DIR, "status.json")
KEV_CACHE_FILE = os.path.join(CACHE_DIR, "cisa_kev.json")
IGNORED_FILE = os.path.expanduser("~/.config/omarchy/fleet_ignored.json")
DEMO_FLAG_FILE = os.path.expanduser("~/.config/omarchy/fleet_demo_active")
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

NETWORK_TARGETS = [
    "aiohttp", "undici", "hono", "urllib3", "requests", "openssl",
    "nginx", "docker", "curl", "node", "python", "httpd", "apache"
]
LOCAL_PARSER_TARGETS = ["pypdf", "pillow", "mistune", "tldr"]


# ==========================================
# 1. Ignored / Muted Vulnerability Manager
# ==========================================

def load_ignored() -> Dict[str, Any]:
    """Loads ignored/muted packages and CVEs."""
    candidates = [
        IGNORED_FILE,
        os.path.join(PLUGIN_DIR, "ignored.json")
    ]
    for p in candidates:
        if os.path.isfile(p):
            try:
                with open(p, "r") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        if "packages" not in data:
                            data["packages"] = {}
                        if "cves" not in data:
                            data["cves"] = {}
                        return data
            except Exception:
                pass
    return {"packages": {}, "cves": {}}


def save_ignored(data: Dict[str, Any]) -> bool:
    """Saves ignored/muted packages and CVEs to persistent storage."""
    try:
        os.makedirs(os.path.dirname(IGNORED_FILE), mode=0o700, exist_ok=True)
        with open(IGNORED_FILE, "w") as f:
            json.dump(data, f, indent=2)
        try:
            os.chmod(IGNORED_FILE, 0o600)
        except Exception:
            pass
        # Invalidate status cache so mutations take effect immediately
        if os.path.exists(FLEET_CACHE_FILE):
            try:
                os.remove(FLEET_CACHE_FILE)
            except Exception:
                pass
        return True
    except Exception as e:
        print(f"Warning: Failed to save ignored file: {e}", file=sys.stderr)
        return False


def mute_package(pkg_name: str, reason: str = "") -> bool:
    """Mutes/ignores a package from urgent alerts and counters."""
    data = load_ignored()
    data["packages"][pkg_name] = {
        "reason": reason or "Muted by user",
        "muted_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    return save_ignored(data)


def unmute_package(pkg_name: str) -> bool:
    """Restores a previously muted package to active alerts."""
    data = load_ignored()
    if pkg_name in data.get("packages", {}):
        del data["packages"][pkg_name]
        return save_ignored(data)
    return False


def mute_cve(cve_id: str, reason: str = "") -> bool:
    """Mutes/ignores a specific CVE ID."""
    data = load_ignored()
    data["cves"][cve_id] = {
        "reason": reason or "Muted by user",
        "muted_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    return save_ignored(data)


def unmute_cve(cve_id: str) -> bool:
    """Unmutes a previously muted CVE."""
    data = load_ignored()
    if cve_id in data.get("cves", {}):
        del data["cves"][cve_id]
        return save_ignored(data)
    return False


def is_package_muted(pkg_name: str) -> bool:
    """Checks if a software package is currently muted."""
    data = load_ignored()
    return pkg_name.strip() in data.get("packages", {})


def is_cve_muted(cve_id: str) -> bool:
    """Checks if a CVE identifier is currently muted."""
    data = load_ignored()
    return cve_id.strip() in data.get("cves", {})


# ==========================================
# 2. Server & Telemetry Discovery
# ==========================================

def get_configured_fleet_url() -> str:
    """Discovers Fleet DM server base URL."""
    if os.environ.get("FLEET_URL"):
        return os.environ.get("FLEET_URL").strip()

    candidates = [
        os.path.join(PLUGIN_DIR, "config.json"),
        os.path.expanduser("~/.config/omarchy/fleet.json")
    ]
    for p in candidates:
        if os.path.isfile(p):
            try:
                with open(p, "r") as f:
                    cfg = json.load(f)
                    if cfg.get("fleet_url"):
                        return cfg["fleet_url"].strip()
            except Exception:
                pass

    fleet_cfg = os.path.expanduser("~/.fleet/config")
    if os.path.isfile(fleet_cfg):
        try:
            with open(fleet_cfg, "r") as f:
                for line in f:
                    if "address:" in line:
                        addr = line.split("address:", 1)[1].strip()
                        if addr:
                            return addr
        except Exception:
            pass

    return "https://localhost:8080"


def get_cisa_kev(force_refresh: bool = False) -> Dict[str, Any]:
    """Fetches and parses the CISA Known Exploited Vulnerabilities (KEV) catalog."""
    if not force_refresh and os.path.exists(KEV_CACHE_FILE):
        try:
            mtime = os.path.getmtime(KEV_CACHE_FILE)
            if (time.time() - mtime) < 43200:  # 12 hours
                with open(KEV_CACHE_FILE, "r") as f:
                    cached = json.load(f)
                    if isinstance(cached, dict) and "vulnerabilities" in cached:
                        v_list = cached["vulnerabilities"]
                        if isinstance(v_list, list):
                            return {item["cveID"]: item for item in v_list if "cveID" in item}
                        elif isinstance(v_list, dict):
                            return v_list
                    elif isinstance(cached, dict) and cached:
                        return cached
        except Exception:
            pass

    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={"User-Agent": "Fleet-Omarchy/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
            vulns_list = data.get("vulnerabilities", [])
            cves = {item["cveID"]: item for item in vulns_list if "cveID" in item}
            with open(KEV_CACHE_FILE, "w") as f:
                json.dump(cves, f)
            return cves
    except Exception:
        if os.path.exists(KEV_CACHE_FILE):
            try:
                with open(KEV_CACHE_FILE, "r") as f:
                    cached = json.load(f)
                    if isinstance(cached, dict) and "vulnerabilities" in cached:
                        return {item["cveID"]: item for item in cached["vulnerabilities"] if "cveID" in item}
                    elif isinstance(cached, dict):
                        return cached
            except Exception:
                pass
    return {}


def check_fleet_connection() -> tuple[str, str]:
    """
    Checks if fleetctl is installed and configured with valid credentials.
    Returns (state, error_message), where state is one of:
      - 'ok': connection verified and hosts query succeeded
      - 'missing_cli': fleetctl binary not in PATH
      - 'unconfigured': server address not configured
      - 'unauthenticated': login token missing or expired
      - 'unreachable': server down, connection refused, or timed out
      - 'error': generic daemon / subprocess error
    """
    import shutil
    if not shutil.which("fleetctl"):
        return "missing_cli", "The 'fleetctl' CLI is not installed or not found in PATH."
    try:
        proc = subprocess.run(
            ["fleetctl", "get", "hosts", "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8
        )
        if proc.returncode == 0:
            return "ok", ""
        err = proc.stderr.decode().strip()
        if "set the Fleet API address" in err or "not configured" in err:
            return "unconfigured", "Fleet server address not set. Run Setup Wizard or fleetctl config set --address <url>."
        elif "token config value missing" in err or "Please log in" in err or "unauthorized" in err.lower() or "401" in err:
            return "unauthenticated", "Fleet session expired or token missing. Log in or update API token."
        elif "connection refused" in err.lower() or "no such host" in err.lower() or "context deadline" in err.lower():
            return "unreachable", f"Fleet server unreachable at {get_configured_fleet_url()}."
        return "error", err or f"fleetctl exited with code {proc.returncode}"
    except subprocess.TimeoutExpired:
        return "unreachable", f"Fleet server connection timed out at {get_configured_fleet_url()}."
    except Exception as e:
        return "error", str(e)


def fetch_hosts() -> Dict[int, Dict[str, Any]]:
    """Fetches host status and metadata from fleetctl."""
    host_map = {}
    try:
        proc = subprocess.run(
            ["fleetctl", "get", "hosts", "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=True
        )
        for line in proc.stdout.decode().strip().splitlines():
            line = line.strip()
            if not line:
                continue
            h_obj = json.loads(line)
            spec = h_obj.get("spec", h_obj)
            hid = spec.get("id")
            if not hid:
                continue
            raw_name = spec.get("hostname") or spec.get("computer_name") or f"host-{hid}"
            display_name = raw_name.split(".")[0] if "." in raw_name and len(raw_name) > 14 else raw_name
            status = spec.get("status", "unknown").lower()
            host_map[hid] = {
                "id": hid,
                "name": display_name,
                "hostname": raw_name,
                "platform": spec.get("platform", "linux"),
                "status": status,
                "online": (status == "online"),
                "ip": spec.get("primary_ip", ""),
                "seen_time": spec.get("seen_time", "")
            }
    except Exception as e:
        print(f"Warning: Failed to fetch hosts: {e}", file=sys.stderr)
    return host_map


def fetch_vulnerable_software() -> List[Dict[str, Any]]:
    """Fetches vulnerable software from Fleet API."""
    try:
        proc = subprocess.run(
            ["fleetctl", "api", "-F", "vulnerable=true", "/api/v1/fleet/software"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=True
        )
        data = json.loads(proc.stdout.decode())
        return data.get("software", [])
    except Exception as e:
        print(f"Warning: Failed to fetch software: {e}", file=sys.stderr)
        return []


def get_software_hosts(software_id: int, host_map: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Retrieves hosts affected by a specific software ID."""
    try:
        proc = subprocess.run(
            ["fleetctl", "api", "-F", f"software_id={software_id}", "/api/v1/fleet/hosts"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=4
        )
        if proc.returncode != 0:
            return []
        data = json.loads(proc.stdout.decode())
        results = []
        for h in data.get("hosts", []):
            hid = h.get("id")
            hinfo = host_map.get(hid, {})
            hname = hinfo.get("name") or h.get("hostname", f"host-{hid}")
            raw_hname = hinfo.get("hostname") or h.get("hostname", f"host-{hid}")
            hplat = hinfo.get("platform") or h.get("platform", "linux")
            hstatus = hinfo.get("status", "unknown")
            is_online = hinfo.get("online", hstatus == "online")
            results.append({
                "id": hid,
                "name": hname,
                "hostname": raw_hname,
                "platform": hplat,
                "status": hstatus,
                "online": is_online
            })
        return results
    except Exception:
        return []


def make_remediation_command(name: str, source: str) -> str:
    """Generates package update command based on package source."""
    if not name or not SAFE_NAME_RE.match(name):
        return ""
    qname = shlex.quote(name)
    if source == "pacman_packages":
        return f"sudo pacman -Syu {qname}"
    elif source == "deb_packages":
        return f"sudo apt update && sudo apt install --only-upgrade {qname}"
    elif source == "rpm_packages":
        return f"sudo dnf upgrade {qname}"
    elif source == "python_packages":
        return f"pip install --upgrade {qname}"
    elif source == "npm_packages":
        return f"npm update {qname}"
    elif source == "programs":
        return f"winget upgrade --id {qname}"
    return f"sudo update {qname}"


def make_host_remediation(host_name: str, host_platform: str, base_cmd: str) -> str:
    """Wraps remediation command for local execution or remote SSH."""
    if not base_cmd:
        return ""
    if host_name.lower() in ["omarchy", "localhost"]:
        return base_cmd
    if not SAFE_NAME_RE.match(host_name):
        return ""
    qhost = shlex.quote(host_name)
    qcmd = shlex.quote(base_cmd)
    if "winget" in base_cmd:
        return f"ssh {qhost} {qcmd}"
    return f"ssh -t {qhost} {qcmd}"


# ==========================================
# 3. Software Triage & Classification
# ==========================================

def classify_software(s: Dict[str, Any], kev_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classifies a software entry into triage tiers:
      Tier 1: Actively exploited zero-days (CISA KEV)
      Tier 4: Historic epoch mismatch / likely false positives (Arch Linux)
      Tier 2: Exposed network runtimes, core frameworks, or packages with >=5 CVEs
      Tier 3: Local utilities, parsers, or low-exposure backlog
    Enriches with NIST NVD URLs for deep-dive research.
    """
    sid = s.get("id")
    name = s.get("name", "")
    name_lower = name.lower()
    ver = s.get("version", "")
    source = s.get("source", "")
    hosts_count = s.get("hosts_count", 1)
    vulns = s.get("vulnerabilities", [])
    cve_ids = [v.get("cve", "") for v in vulns if v.get("cve")]

    matched_kev = [c for c in cve_ids if c in kev_dict]
    primary_cve = matched_kev[0] if matched_kev else (cve_ids[0] if cve_ids else "")
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{primary_cve}" if primary_cve else ""
    cves_meta = [{"cve": c, "url": f"https://nvd.nist.gov/vuln/detail/{c}"} for c in cve_ids[:6]]

    remediation = make_remediation_command(name, source)

    base_record = {
        "id": sid,
        "name": name,
        "version": ver,
        "source": source,
        "hosts": hosts_count,
        "primary_cve": primary_cve,
        "nvd_url": nvd_url,
        "cves_meta": cves_meta,
        "cves": cve_ids[:4],
        "cve_count": len(cve_ids),
        "action": remediation,
        "host_chips": [],
        "is_muted": False
    }

    # 1. Tier 1: CISA KEV
    if matched_kev:
        kev_cve = matched_kev[0]
        base_record.update({
            "tier": 1,
            "tier_label": "CRITICAL: CISA KEV",
            "reason": f"Actively exploited in the wild ({kev_cve})",
            "matched_kev": matched_kev
        })
        return base_record

    # 2. Tier 4: Arch Linux epoch / rolling false positives
    if source == "pacman_packages" and name in ["ffmpeg", "wpa_supplicant"]:
        old_cves = [c for c in cve_ids if any(y in c for y in ["2011", "2012", "2013", "2014", "2015", "2016", "2017"])]
        if len(old_cves) > 5:
            base_record.update({
                "tier": 4,
                "tier_label": "Likely False Positive",
                "reason": "Arch rolling version epoch mismatch against historic CVEs"
            })
            return base_record

    # 3. Tier 2: Action Recommended
    is_network = any(t in name_lower for t in NETWORK_TARGETS)
    has_many_cves = len(cve_ids) >= 5
    if is_network or has_many_cves:
        reason = "Exposed network runtime / high vulnerability surface" if is_network else f"Multiple CVEs ({len(cve_ids)}) detected"
        base_record.update({
            "tier": 2,
            "tier_label": "Action Recommended",
            "reason": reason
        })
        return base_record

    # 4. Tier 3: Low Risk / Local / Backlog
    is_local_parser = any(t in name_lower for t in LOCAL_PARSER_TARGETS)
    reason = "File parser or local tool; requires local untrusted input" if is_local_parser else "Low-exposure library or backlog"
    base_record.update({
        "tier": 3,
        "tier_label": "Low Risk",
        "reason": reason
    })
    return base_record


def classify_aggregated_package(pkg_name: str, source: str, instances: List[Dict[str, Any]], kev_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classifies a software group (which may span multiple versions and hosts)
    into triage tiers, aggregating CVEs and host instances.
    """
    name_lower = pkg_name.lower()
    all_vulns_dict = {}
    for s in instances:
        for v in s.get("vulnerabilities", []):
            c = v.get("cve")
            if c and c not in all_vulns_dict:
                all_vulns_dict[c] = v

    cve_ids = list(all_vulns_dict.keys())
    matched_kev = [c for c in cve_ids if c in kev_dict]
    primary_cve = matched_kev[0] if matched_kev else (cve_ids[0] if cve_ids else "")
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{primary_cve}" if primary_cve else ""
    cves_meta = [{"cve": c, "url": f"https://nvd.nist.gov/vuln/detail/{c}"} for c in cve_ids[:6]]

    versions = list(dict.fromkeys(s.get("version", "") for s in instances if s.get("version")))
    if not versions:
        ver_display = ""
    elif len(versions) == 1:
        ver_display = versions[0]
    elif len(versions) == 2:
        ver_display = f"{versions[0]}, {versions[1]}"
    else:
        ver_display = f"{versions[0]} (+{len(versions)-1} versions)"

    hosts_count = sum(s.get("hosts_count", 1) for s in instances)
    remediation = make_remediation_command(pkg_name, source)
    primary_id = instances[0].get("id")

    base_record = {
        "id": primary_id,
        "name": pkg_name,
        "version": ver_display,
        "versions": versions,
        "source": source,
        "hosts": hosts_count,
        "primary_cve": primary_cve,
        "nvd_url": nvd_url,
        "cves_meta": cves_meta,
        "cves": cve_ids[:4],
        "cve_count": len(cve_ids),
        "action": remediation,
        "host_chips": [],
        "is_muted": False,
        "software_instances": [(s.get("id"), s.get("version", "")) for s in instances if s.get("id")]
    }

    # 1. Tier 1: CISA KEV
    if matched_kev:
        kev_cve = matched_kev[0]
        base_record.update({
            "tier": 1,
            "tier_label": "CRITICAL: CISA KEV",
            "reason": f"Actively exploited in the wild ({kev_cve})",
            "matched_kev": matched_kev
        })
        return base_record

    # 2. Tier 4: Arch Linux epoch / rolling false positives
    if source == "pacman_packages" and pkg_name in ["ffmpeg", "wpa_supplicant"]:
        old_cves = [c for c in cve_ids if any(y in c for y in ["2011", "2012", "2013", "2014", "2015", "2016", "2017"])]
        if len(old_cves) > 5:
            base_record.update({
                "tier": 4,
                "tier_label": "Likely False Positive",
                "reason": "Arch rolling version epoch mismatch against historic CVEs"
            })
            return base_record

    # 3. Tier 2: Action Recommended
    is_network = any(t in name_lower for t in NETWORK_TARGETS)
    has_many_cves = len(cve_ids) >= 5
    if is_network or has_many_cves:
        reason = "Exposed network runtime / high vulnerability surface" if is_network else f"Multiple CVEs ({len(cve_ids)}) detected"
        base_record.update({
            "tier": 2,
            "tier_label": "Action Recommended",
            "reason": reason
        })
        return base_record

    # 4. Tier 3: Low Risk / Local / Backlog
    is_local_parser = any(t in name_lower for t in LOCAL_PARSER_TARGETS)
    reason = "File parser or local tool; requires local untrusted input" if is_local_parser else "Low-exposure library or backlog"
    base_record.update({
        "tier": 3,
        "tier_label": "Low Risk",
        "reason": reason
    })
    return base_record


# ==========================================
# 4. Full Triage Pipeline
# ==========================================

def triage_all(force_refresh: bool = False, cache_ttl: int = 60, use_demo: Optional[bool] = None) -> Dict[str, Any]:
    """
    Executes full vulnerability scan, cross-referencing, host enrichment,
    aggregates packages across hosts, filters out muted packages, and caches results.
    """
    if use_demo is True or (use_demo is None and os.path.exists(DEMO_FLAG_FILE)):
        data = get_demo_data()
        try:
            os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
            with open(FLEET_CACHE_FILE, "w") as f:
                json.dump(data, f, indent=2)
            try:
                os.chmod(FLEET_CACHE_FILE, 0o600)
            except Exception:
                pass
        except Exception:
            pass
        return data

    if not force_refresh and os.path.exists(FLEET_CACHE_FILE):
        try:
            mtime = os.path.getmtime(FLEET_CACHE_FILE)
            if (time.time() - mtime) < cache_ttl:
                with open(FLEET_CACHE_FILE, "r") as f:
                    cached = json.load(f)
                    if cached.get("status") == "ok":
                        return cached
        except Exception:
            pass

    ignored = load_ignored()
    ignored_pkgs = ignored.get("packages", {})
    ignored_cves = ignored.get("cves", {})

    conn_state, conn_err = check_fleet_connection()
    if conn_state != "ok":
        return {
            "status": conn_state,
            "error_message": conn_err,
            "is_demo": False,
            "hosts_total": 0,
            "hosts_online": 0,
            "hosts_offline": 0,
            "vulnerable_software_count": 0,
            "total_cves": 0,
            "cisa_kev_active": 0,
            "tier1_count": 0,
            "tier2_count": 0,
            "tier3_count": 0,
            "tier4_count": 0,
            "muted_count": 0,
            "muted_packages": [],
            "muted_items": [],
            "actionable_count": 0,
            "last_scan_time": time.strftime("%H:%M:%S"),
            "fleet_url": get_configured_fleet_url(),
            "tier1_packages": [],
            "tier2_packages": [],
            "actionable_packages": []
        }

    host_map = fetch_hosts()
    hosts_total = len(host_map)
    hosts_online = sum(1 for h in host_map.values() if h.get("online"))
    hosts_offline = hosts_total - hosts_online

    software = fetch_vulnerable_software()
    kev_dict = get_cisa_kev(force_refresh=force_refresh)

    tier1_items = []
    tier2_items = []
    tier3_items = []
    tier4_items = []
    muted_items = []
    total_cve_instances = 0

    grouped_software: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for s in software:
        vulns = s.get("vulnerabilities", [])
        total_cve_instances += len(vulns)
        name = s.get("name", "")
        source = s.get("source", "")
        key = (name.lower(), source)
        grouped_software.setdefault(key, []).append(s)

    for (pkg_name_lower, source), instances in grouped_software.items():
        primary_name = instances[0].get("name", pkg_name_lower)
        classified = classify_aggregated_package(primary_name, source, instances, kev_dict)
        pkg_name = classified.get("name", "")
        primary_cve = classified.get("primary_cve", "")

        is_pkg_muted = pkg_name in ignored_pkgs
        is_cve_muted = bool(primary_cve and (primary_cve in ignored_cves))

        if is_pkg_muted or is_cve_muted:
            classified["is_muted"] = True
            reason = ignored_pkgs.get(pkg_name, {}).get("reason") or ignored_cves.get(primary_cve, {}).get("reason") or "Muted by user"
            muted_at = ignored_pkgs.get(pkg_name, {}).get("muted_at") or ignored_cves.get(primary_cve, {}).get("muted_at") or ""
            classified["muted_reason"] = reason
            classified["muted_at"] = muted_at
            muted_items.append(classified)
            continue

        t = classified.get("tier")
        if t == 1:
            tier1_items.append(classified)
        elif t == 2:
            tier2_items.append(classified)
        elif t == 4:
            tier4_items.append(classified)
        else:
            tier3_items.append(classified)

    # Sort items
    tier1_items.sort(key=lambda x: (x["hosts"], x["cve_count"]), reverse=True)
    tier2_items.sort(key=lambda x: (x["hosts"], x["cve_count"]), reverse=True)
    muted_items.sort(key=lambda x: (x["hosts"], x["cve_count"]), reverse=True)

    # Enrich top priority items with host chips
    candidate_items = tier1_items + tier2_items[:15] + muted_items[:10]
    for item in candidate_items:
        chips = []
        seen_hosts = set()
        for sid, s_ver in item.get("software_instances", []):
            hosts = get_software_hosts(sid, host_map)
            for h in hosts:
                hname = h["name"]
                if hname in seen_hosts:
                    continue
                seen_hosts.add(hname)
                hplat = h["platform"]
                chips.append({
                    "name": hname,
                    "platform": hplat,
                    "online": h.get("online", True),
                    "status": h.get("status", "online"),
                    "version": s_ver,
                    "action": make_host_remediation(hname, hplat, item["action"])
                })
        item["host_chips"] = chips
        if chips:
            item["hosts"] = len(chips)
            has_local = any(c["name"].lower() in ["omarchy", "localhost"] for c in chips)
            if not has_local:
                online_chips = [c for c in chips if c.get("online")]
                if online_chips:
                    item["action"] = online_chips[0]["action"]
                else:
                    item["action"] = chips[0]["action"]

    actionable_packages = tier1_items + tier2_items[:15]

    result = {
        "status": "ok",
        "error_message": "",
        "is_demo": False,
        "hosts_total": hosts_total,
        "hosts_online": hosts_online,
        "hosts_offline": hosts_offline,
        "vulnerable_software_count": len(software),
        "total_cves": total_cve_instances,
        "cisa_kev_active": len(tier1_items),
        "tier1_count": len(tier1_items),
        "tier2_count": len(tier2_items),
        "tier3_count": len(tier3_items),
        "tier4_count": len(tier4_items),
        "muted_count": len(muted_items),
        "muted_packages": [m["name"] for m in muted_items],
        "muted_items": muted_items,
        "actionable_count": len(tier1_items) + len(tier2_items),
        "last_scan_time": time.strftime("%H:%M:%S"),
        "fleet_url": f"{get_configured_fleet_url().rstrip('/')}/software?vulnerable=true",
        "tier1_packages": tier1_items,
        "tier2_packages": tier2_items[:15],
        "actionable_packages": actionable_packages
    }

    try:
        os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
        with open(FLEET_CACHE_FILE, "w") as f:
            json.dump(result, f)
        try:
            os.chmod(FLEET_CACHE_FILE, 0o600)
        except Exception:
            pass
    except Exception:
        pass

    return result


# ==========================================
# 5. Rich Demonstration Dataset
# ==========================================

def get_demo_data() -> Dict[str, Any]:
    """Generates realistic demonstration telemetry with mixed platforms and tiers."""
    demo_t1 = [
        {
            "id": 8001,
            "name": "samba",
            "version": "2:4.24.4-1",
            "source": "pacman_packages",
            "hosts": 2,
            "tier": 1,
            "tier_label": "CRITICAL: CISA KEV",
            "reason": "Actively exploited in the wild (CVE-2020-1472)",
            "primary_cve": "CVE-2020-1472",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472",
            "cves_meta": [
                {"cve": "CVE-2020-1472", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"},
                {"cve": "CVE-2021-44142", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44142"},
                {"cve": "CVE-2022-38023", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-38023"}
            ],
            "cves": ["CVE-2020-1472", "CVE-2021-44142", "CVE-2022-38023"],
            "cve_count": 39,
            "matched_kev": ["CVE-2020-1472"],
            "action": "ssh -t arch-prod \"sudo pacman -Syu samba\"",
            "is_muted": False,
            "host_chips": [
                {"name": "arch-prod", "platform": "linux", "online": True, "status": "online", "version": "2:4.24.4-1", "action": "ssh -t arch-prod \"sudo pacman -Syu samba\""},
                {"name": "dev-workstation", "platform": "linux", "online": False, "status": "offline", "version": "2:4.24.4-1", "action": "ssh -t dev-workstation \"sudo pacman -Syu samba\""}
            ]
        },
        {
            "id": 8002,
            "name": "google-chrome",
            "version": "151.0.7922.71-1",
            "source": "deb_packages",
            "hosts": 1,
            "tier": 1,
            "tier_label": "CRITICAL: CISA KEV",
            "reason": "Actively exploited in the wild (CVE-2026-85046)",
            "primary_cve": "CVE-2026-85046",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-85046",
            "cves_meta": [
                {"cve": "CVE-2026-85046", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-85046"},
                {"cve": "CVE-2026-85047", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-85047"}
            ],
            "cve_count": 582,
            "matched_kev": ["CVE-2026-85046"],
            "action": "ssh -t arch-prod \"sudo apt update && sudo apt install --only-upgrade google-chrome-stable\"",
            "is_muted": False,
            "host_chips": [
                {"name": "arch-prod", "platform": "linux", "online": True, "status": "online", "version": "151.0.7922.71-1", "action": "ssh -t arch-prod \"sudo apt update && sudo apt install --only-upgrade google-chrome-stable\""}
            ]
        }
    ]

    demo_t2 = [
        {
            "id": 8003,
            "name": "curl",
            "version": "8.5.0-2",
            "source": "pacman_packages",
            "hosts": 3,
            "tier": 2,
            "tier_label": "Action Recommended",
            "reason": "Exposed network runtime / SOCKS5 heap overflow (CVE-2023-38545)",
            "primary_cve": "CVE-2023-38545",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38545",
            "cves_meta": [
                {"cve": "CVE-2023-38545", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38545"},
                {"cve": "CVE-2023-38546", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38546"}
            ],
            "cves": ["CVE-2023-38545", "CVE-2023-38546"],
            "cve_count": 12,
            "action": "sudo pacman -Syu curl",
            "is_muted": False,
            "host_chips": [
                {"name": "omarchy", "platform": "linux", "online": True, "status": "online", "version": "8.5.0-2", "action": "sudo pacman -Syu curl"},
                {"name": "arch-prod", "platform": "linux", "online": True, "status": "online", "version": "8.5.0-2", "action": "ssh -t arch-prod \"sudo pacman -Syu curl\""},
                {"name": "fedora-srv", "platform": "linux", "online": True, "status": "online", "version": "8.5.0-2", "action": "ssh -t fedora-srv \"sudo dnf upgrade curl\""}
            ]
        },
        {
            "id": 8004,
            "name": "aiohttp",
            "version": "3.9.1",
            "source": "python_packages",
            "hosts": 2,
            "tier": 2,
            "tier_label": "Action Recommended",
            "reason": "Exposed network runtime / HTTP request smuggling",
            "primary_cve": "CVE-2024-23334",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23334",
            "cves_meta": [
                {"cve": "CVE-2024-23334", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23334"},
                {"cve": "CVE-2024-27306", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-27306"}
            ],
            "cves": ["CVE-2024-23334", "CVE-2024-27306"],
            "cve_count": 7,
            "action": "pip install --upgrade aiohttp",
            "is_muted": False,
            "host_chips": [
                {"name": "omarchy", "platform": "linux", "online": True, "status": "online", "version": "3.9.1", "action": "pip install --upgrade aiohttp"},
                {"name": "windows-runner", "platform": "windows", "online": True, "status": "online", "version": "3.9.1", "action": "ssh windows-runner \"pip install --upgrade aiohttp\""}
            ]
        },
        {
            "id": 8005,
            "name": "openssl",
            "version": "3.0.13",
            "source": "deb_packages",
            "hosts": 1,
            "tier": 2,
            "tier_label": "Action Recommended",
            "reason": "Exposed network runtime / cryptographic validation surface",
            "primary_cve": "CVE-2024-0727",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0727",
            "cves_meta": [
                {"cve": "CVE-2024-0727", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0727"},
                {"cve": "CVE-2023-5678", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-5678"}
            ],
            "cves": ["CVE-2024-0727", "CVE-2023-5678"],
            "cve_count": 8,
            "action": "ssh -t arch-prod \"sudo apt update && sudo apt install --only-upgrade openssl\"",
            "is_muted": False,
            "host_chips": [
                {"name": "arch-prod", "platform": "linux", "online": True, "status": "online", "version": "3.0.13", "action": "ssh -t arch-prod \"sudo apt update && sudo apt install --only-upgrade openssl\""}
            ]
        }
    ]

    demo_muted = [
        {
            "id": 8009,
            "name": "ffmpeg",
            "version": "2:7.1-1",
            "source": "pacman_packages",
            "hosts": 2,
            "tier": 4,
            "tier_label": "Muted",
            "reason": "Arch rolling version epoch mismatch against historic CVEs",
            "primary_cve": "CVE-2016-10195",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2016-10195",
            "cves_meta": [
                {"cve": "CVE-2016-10195", "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-10195"},
                {"cve": "CVE-2016-10196", "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-10196"}
            ],
            "cves": ["CVE-2016-10195", "CVE-2016-10196"],
            "cve_count": 14,
            "action": "sudo pacman -Syu ffmpeg",
            "is_muted": True,
            "muted_reason": "Historic Arch Linux epoch mismatch (false positive)",
            "muted_at": "2026-09-06 12:00:00",
            "host_chips": [
                {"name": "omarchy", "platform": "linux", "online": True, "status": "online", "version": "2:7.1-1", "action": "sudo pacman -Syu ffmpeg"},
                {"name": "dev-workstation", "platform": "linux", "online": False, "status": "offline", "version": "2:7.1-1", "action": "ssh -t dev-workstation \"sudo pacman -Syu ffmpeg\""}
            ]
        }
    ]

    ignored = load_ignored()
    ignored_pkgs = ignored.get("packages", {})
    
    active_t1 = []
    active_t2 = []
    muted_list = list(demo_muted)

    for item in demo_t1:
        if item["name"] in ignored_pkgs:
            info = ignored_pkgs[item["name"]]
            c = dict(item)
            c["is_muted"] = True
            c["muted_reason"] = info.get("reason", "Muted by user")
            c["muted_at"] = info.get("muted_at", "")
            muted_list.append(c)
        else:
            active_t1.append(item)

    for item in demo_t2:
        if item["name"] in ignored_pkgs:
            info = ignored_pkgs[item["name"]]
            c = dict(item)
            c["is_muted"] = True
            c["muted_reason"] = info.get("reason", "Muted by user")
            c["muted_at"] = info.get("muted_at", "")
            muted_list.append(c)
        else:
            active_t2.append(item)

    return {
        "status": "ok",
        "error_message": "",
        "is_demo": True,
        "hosts_total": 6,
        "hosts_online": 5,
        "hosts_offline": 1,
        "vulnerable_software_count": 42,
        "total_cves": 1420,
        "cisa_kev_active": len(active_t1),
        "tier1_count": len(active_t1),
        "tier2_count": len(active_t2),
        "tier3_count": 28,
        "tier4_count": 9,
        "muted_count": len(muted_list),
        "muted_packages": [m["name"] for m in muted_list],
        "muted_items": muted_list,
        "actionable_count": len(active_t1) + len(active_t2),
        "last_scan_time": time.strftime("%H:%M:%S"),
        "fleet_url": "https://fleet.demo.internal:8080/software?vulnerable=true",
        "tier1_packages": active_t1,
        "tier2_packages": active_t2,
        "actionable_packages": active_t1 + active_t2
    }
