#!/usr/bin/env python3
import os
import re
import sys
import subprocess
from pathlib import Path

RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"
BOLD = "\033[1m"
NC = "\033[0m"

MANIFEST_FILE = "packages.txt"

MALICIOUS_SIGNATURES = {
    "lockfile-js": "Known Node payload implant component",
    "atomic-lockfile": "Known hostile footprint component",
    r"npm\s+(install|i)\s+": "Suspicious native Node Package Manager execution in build",
    r"curl\s+.*-s\s+.*\|\s*(bash|sh|node)": "Arbitrary remote code execution shell pipe",
    r"wget\s+.*-qO-\s+.*\|\s*(bash|sh)": "Arbitrary remote code execution pipe via wget",
    r"base64\s+-d\s*\|\s*(bash|sh)": "Obfuscated Base64 decode-and-execute stream",
    r"eval\s*\(\s*curl": "Dynamic execution injection via web stream request",
    r"exec\s+3<>/dev/tcp/": "Direct interactive bash reverse shell socket deployment",
    r"\\x[0-9a-fA-F]{2}": "Hex-encoded obfuscated string layout detected"
}

def print_banner():
    print(f"{CYAN}{BOLD}===================================================================={NC}")
    print(f"{CYAN}{BOLD}         AUR FORENSIC AUDITOR: MULTI-LAYER COMPLIANCE ENGINE        {NC}")
    print(f"{CYAN}         Zero Network Footprint — Static Content & Identity Sweep   {NC}")
    print(f"{CYAN}{BOLD}===================================================================={NC}\n")

def load_local_manifest():
    manifest_path = Path(MANIFEST_FILE)
    compromised_packages = set()
    
    if not manifest_path.exists():
        print(f"{RED}[!] FATAL: '{MANIFEST_FILE}' not found in current directory.{NC}")
        print(f"{YELLOW}Please ensure your threat list is saved right next to this script.{NC}")
        sys.exit(1)
        
    print(f"{BOLD}[*] Loading offline signature manifest database '{manifest_path}'...{NC}")
    try:
        content = manifest_path.read_text(errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and re.match(r"^[a-z0-9\-_\+\.]+$", line):
                compromised_packages.add(line.lower())
        print(f"    [SUCCESS] Loaded {len(compromised_packages)} database signatures into tracking space.")
        return compromised_packages
    except Exception as e:
        print(f"{RED}[!] Error parsing target manifest tracking structures: {e}{NC}")
        sys.exit(1)

def parse_local_aur_registry():
    local_registry = {}
    print(f"{BOLD}[*] Interrogating local ALPM database records via pacman...{NC}")
    try:
        res = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            fragments = line.strip().split()
            if len(fragments) == 2:
                local_registry[fragments[0].lower()] = fragments[1]
        print(f"    [SUCCESS] Mapped {len(local_registry)} foreign/AUR packages currently installed.")
        return local_registry
    except FileNotFoundError:
        print(f"{YELLOW}[!] pacman binary not detected. This script requires an Arch Linux host environment.{NC}")
        sys.exit(1)
    except Exception as e:
        print(f"    [ERROR] Failed to map local system package registries: {e}")
        return {}

def analyze_file_content(file_path):
    findings = []
    try:
        content = file_path.read_text(errors="ignore")
        for signature, description in MALICIOUS_SIGNATURES.items():
            if re.search(signature, content, re.IGNORECASE):
                findings.append((signature, description))
    except Exception:
        pass
    return findings

def deep_scan_all_caches(user_home):
    print(f"\n{CYAN}{BOLD}[*] Launching Deep Build Cache Code-Level Sweep...{NC}")
    cache_bases = [
        user_home / ".cache/yay",
        user_home / ".cache/paru",
        user_home / ".cache/aurutils/sync",
        Path("/var/cache/aur")
    ]
    
    total_scanned = 0
    total_hits = 0
    cache_compromised = False
    active_caches = 0
    
    for base in cache_bases:
        if not base.exists():
            continue
        active_caches += 1
        print(f"    [*] Scanning directory tree root: {base}")
        for pkgbuild_file in base.glob("**/PKGBUILD"):
            total_scanned += 1
            structural_anomalies = analyze_file_content(pkgbuild_file)
            if structural_anomalies:
                total_hits += 1
                cache_compromised = True
                print(f"\n      {RED}{BOLD}[CRITICAL CONTENT ALERT] Malicious code structure caught in build cache!{NC}")
                print(f"      Filepath: {pkgbuild_file}")
                for sig, desc in structural_anomalies:
                    print(f"        [-] Heuristic Trigger: '{sig}' -> ({desc})")
                    
    if active_caches == 0:
        print(f"    {YELLOW}[!] WARNING: No local helper build caches found. Caches may have been cleared via clean commands.{NC}")
        print(f"        Heuristic discovery is relying strictly on persistent ALPM system metadata structures.{NC}")
    else:
        print(f"\n    [COMPLETE] Content scan done. Inspected {total_scanned} scripts. Detected {total_hits} behavior anomalies.")
        
    return cache_compromised

def audit_target_locations(package, version, user_home):
    print(f"\n{RED}{BOLD}[CRITICAL OVERLAP] Match identified with signature target: '{package}' (Version: {version}){NC}")
    threat_isolated = False
    
    alpm_meta_base = Path(f"/var/lib/pacman/local/{package}-{version}")
    if alpm_meta_base.exists():
        threat_isolated = True
        print(f"    [*] Persistent ALPM Metadata Footprint Verified: {alpm_meta_base}")
        for critical_file in ["desc", "install"]:
            target_file = alpm_meta_base / critical_file
            if target_file.exists():
                structural_anomalies = analyze_file_content(target_file)
                for sig, desc in structural_anomalies:
                    print(f"        [BEHAVIORAL HIT] Operational anomaly in system install hooks: '{sig}' -> ({desc})")

    cache_clusters = [
        user_home / f".cache/yay/{package}",
        user_home / f".cache/paru/{package}",
        user_home / f".cache/aurutils/sync/{package}",
        Path(f"/var/cache/aur/{package}")
    ]
    
    for cache_directory in cache_clusters:
        if cache_directory.exists():
            threat_isolated = True
            print(f"    [*] Found Local Cached Layout: {cache_directory}")
            pkgbuild_file = cache_directory / "PKGBUILD"
            if pkgbuild_file.exists():
                structural_anomalies = analyze_file_content(pkgbuild_file)
                for sig, desc in structural_anomalies:
                    print(f"        [CRITICAL CODE ALERT] Exploit string verified inside PKGBUILD: '{sig}' -> ({desc})")
                    
    return threat_isolated

def main():
    print_banner()
    user_home = Path.home()
    
    threat_feed = load_local_manifest()
    local_packages = parse_local_aur_registry()
    system_compromised = False

    if local_packages:
        print(f"\n{BOLD}[*] Cross-referencing database name matches against manifest rules...{NC}")
        compromised_intersections = set(local_packages.keys()).intersection(threat_feed)
        
        if compromised_intersections:
            for package_match in compromised_intersections:
                if audit_target_locations(package_match, local_packages[package_match], user_home):
                    system_compromised = True
        else:
            print(f"    {GREEN}[CLEAN] No installed package names match database entries.{NC}")

    if deep_scan_all_caches(user_home):
        system_compromised = True
    
    print(f"\n{BOLD}============================== Diagnostic Verdict =============================={NC}")
    
    if system_compromised:
        print(f"\n{RED}{BOLD}[!] HOST ENVIRONMENT VERDICT: COMPROMISED OR SUSPICIOUS COMPONENT FOUND [!]{NC}")
        print(f"{RED}Trace threat indicators matching designated risk vectors were verified locally.{NC}")
        print(f"\n{YELLOW}{BOLD}Incident Response Remediation Playbook:{NC}")
        print(f"  1. Isolate this machine from your local production network immediately.")
        print(f"  2. Do NOT rely entirely on 'pacman -R'. Malicious installers execute logic out-of-band.")
        print(f"  3. Audit '~/.config/systemd/user/' and '/etc/systemd/system/' configurations for rogue timers.")
        print(f"  4. Check environment profile definitions ('~/.bashrc', '~/.zshrc') for persistent network loops.")
        print(f"  5. Inspect volatile system paths like '/tmp/' and '/dev/shm/' for unverified binaries.")
        print(f"  6. Revoke access tokens, drop authorization cookies, and rotate SSH credentials via an independent machine.")
        sys.exit(1)
    else:
        print(f"{GREEN}[CLEAN] Environment scan complete. System matching secure configuration thresholds.{NC}")
        print(f"{BOLD}================================================================================{NC}")
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] User aborted inspection workflow.{NC}")
        sys.exit(0)
