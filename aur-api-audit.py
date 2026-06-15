#!/usr/bin/env python3

import os
import re
import sys
import subprocess
import urllib.request
from pathlib import Path

RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
BOLD = "\033[1m"
NC = "\033[0m"

INTEL_FEED_URL = "https://md.archlinux.org/s/SxbqukK6IA/download"

HEURISTIC_SIGS = [
    r"atomic-lockfile",
    r"js-digest",
    r"lockfile-js",
    r"nextfile-js",
    r"npm\s+(install|i)\s+",
    r"bun\s+add\s+",
    r"yarn\s+add\s+"
]

def banner():
    print(f"{CYAN}{BOLD}===================================================={NC}")
    print(f"{CYAN}{BOLD}        AUR THREAT MITIGATOR: ATOMIC ARCH           {NC}")
    print(f"{CYAN}        Real-time Live Feed & Behavioral Auditor     {NC}")
    print(f"{CYAN}{BOLD}===================================================={NC}\n")

def fetch_live_compromised_list():
    print(f"{BOLD}[*] Connecting to Arch Linux Live Incident Server...{NC}")
    req = urllib.request.Request(
        INTEL_FEED_URL, 
        headers={'User-Agent': 'Mozilla/5.0 (X11; Arch Linux; Linux x86_64)'}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw_data = response.read().decode('utf-8')
            
        compromised = set()
        for line in raw_data.splitlines():
            line = line.strip()
            match = re.search(r"-\s*([a-zA-Z0-9\-_+\.]+)", line)
            if match and not line.startswith("#"):
                compromised.add(match.group(1).lower())
                
        if len(compromised) > 0:
            print(f"    {GREEN}[✓] Successfully synced live feed. Tracking {len(compromised)} blacklisted packages.{NC}")
            return compromised
    except Exception as e:
        print(f"    {YELLOW}[!] Feed Sync Failed ({e}). Falling back to advanced heuristics.{NC}")
        
    return set()

def get_local_aur_packages():
    try:
        res = subprocess.run(["pacman", "-Qmq"], capture_output=True, text=True, check=True)
        packages = [pkg.strip().lower() for pkg in res.stdout.splitlines() if pkg.strip()]
        print(f"    - Found {len(packages)} local AUR packages installed.")
        return packages
    except Exception as e:
        print(f"    {RED}[-] Failed to query local pacman database: {e}{NC}")
        sys.exit(1)

def scan_pacman_local_db():
    print(f"\n{BOLD}[*] Auditing local ALPM metadata for malicious post-install hooks...{NC}")
    pacman_db = Path("/var/lib/pacman/local")
    if not pacman_db.exists():
        print(f"    {YELLOW}[!] Pacman local DB structure missing or inaccessible. Skipping heuristics.{NC}")
        return 0

    compiled_sigs = [re.compile(sig, re.IGNORECASE) for sig in HEURISTIC_SIGS]
    flagged_hooks = 0

    for path in pacman_db.glob("*/desc"):
        try:
            content = path.read_text(errors="ignore")
            for sig in compiled_sigs:
                if sig.search(content):
                    parent_pkg = path.parent.name
                    print(f"    {RED}[CRITICAL] Heuristic Hit inside ALPM metadata for: {parent_pkg}{NC}")
                    flagged_hooks += 1
                    break
        except Exception:
            continue
            
    return flagged_hooks

def scan_build_caches():
    print(f"{BOLD}[*] Inspecting local AUR build cache directories...{NC}")
    cache_targets = [
        Path.home() / ".cache/yay",
        Path.home() / ".cache/paru",
        Path("/var/cache/aur")
    ]
    
    flagged_caches = 0
    compiled_sigs = [re.compile(sig, re.IGNORECASE) for sig in HEURISTIC_SIGS]
    
    for cache_dir in cache_targets:
        if not cache_dir.exists():
            continue
        for path in cache_dir.glob("**/PKGBUILD"):
            try:
                content = path.read_text(errors="ignore")
                for sig in compiled_sigs:
                    if sig.search(content):
                        print(f"    {RED}[CRITICAL] Suspicious instruction sequence found in: {path}{NC}")
                        flagged_caches += 1
                        break
            except Exception:
                continue
                
    return flagged_caches

def main():
    banner()
    
    if os.getuid() != 0:
        print(f"{YELLOW}[!] Running without root privileges. Heuristic depth on /var/lib/pacman may be partial.{NC}\n")

    threat_intel = fetch_live_compromised_list()
    
    print(f"\n{BOLD}[*] Enumerating installed system artifacts...{NC}")
    local_aur = get_local_aur_packages()
    
    cross_match = set(local_aur).intersection(threat_intel)
    
    meta_flags = scan_pacman_local_db()
    cache_flags = scan_build_caches()
    
    print(f"\n{BOLD}==================== Summary Report ===================={NC}")
    if cross_match:
        print(f"{RED}[CRITICAL] MATCH DETECTED Against Live Threat Feed!{NC}")
        for matched_pkg in cross_match:
            print(f"    - {matched_pkg}")
            
    if meta_flags > 0 or cache_flags > 0:
        print(f"{RED}[!] WARNING: Heuristic evaluation flagged structural malicious footprints.{NC}")
        
    if not cross_match and meta_flags == 0 and cache_flags == 0:
        print(f"{GREEN}[✓] System Clean. No active indicators of the Atomic Arch campaign found.{NC}")
    else:
        print(f"\n{YELLOW}[i] Security Action Required:{NC}")
        print("    1. Freeze software modifications.")
        print("    2. Audit the flagged files manually via git history/PKGBUILD diff paths.")
        print("    3. If infected, rotate all active keys, sessions, and credentials immediately.")
    print(f"{BOLD}========================================================{NC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[-] Diagnostic sweep interrupted by user.{NC}")
        sys.exit(0)
