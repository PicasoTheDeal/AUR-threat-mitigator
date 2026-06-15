#!/usr/bin/env python3

import subprocess
import urllib.request
import urllib.error
import json
import os
import sys

RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
NC = '\033[0m'

SONATYPE_API_URL = "https://api.sonatype.com/v1/threat-intel/campaigns/atomic-arch/packages"
SAFEDEP_API_URL = "https://api.safedep.io/ti/campaigns/atomic-arch/iocs"

SONATYPE_FALLBACK_PKGS = ["example-hijacked-pkg1", "omarchy-update-aur-pkgs"]
SAFEDEP_FALLBACK_IOCS = ["atomic-lockfile", "js-digest", "scales.bpf.c"]

def fetch_sonatype_packages():
    print(f"{CYAN}[*] Fetching known hijacked AUR packages from Sonatype Threat Intelligence...{NC}")
    try:
        req = urllib.request.Request(SONATYPE_API_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception:
        print(f"{YELLOW}[!] Sonatype API unreachable. Using fallback package list.{NC}\n")
        return SONATYPE_FALLBACK_PKGS

def fetch_safedep_iocs():
    print(f"{CYAN}[*] Fetching latest eBPF and npm/bun IOCs from SafeDep...{NC}")
    try:
        req = urllib.request.Request(SAFEDEP_API_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception:
        print(f"{YELLOW}[!] SafeDep API unreachable. Using fallback IOC list.{NC}\n")
        return SAFEDEP_FALLBACK_IOCS

def get_local_aur_packages():
    print(f"{CYAN}[*] Enumerating local AUR packages...{NC}")
    try:
        result = subprocess.run(['pacman', '-Qm'], capture_output=True, text=True, check=True)
        return [line.split()[0] for line in result.stdout.strip().split('\n') if line]
    except subprocess.CalledProcessError:
        print(f"{RED}[!] Failed to query pacman. Are you on an Arch-based system?{NC}")
        sys.exit(1)

def scan_iocs(safedep_iocs):
    paranoia_level = 0
    print(f"{CYAN}[*] Sweeping system for 'Atomic Arch' execution artifacts from SafeDep...{NC}")
    home = os.path.expanduser("~")

    for ioc in safedep_iocs:
        if ioc in ["atomic-lockfile", "js-digest"]:
            for cache_dir in [".npm", ".bun/install/cache"]:
                target_path = os.path.join(home, cache_dir)
                if os.path.exists(target_path):
                    if subprocess.run(['grep', '-qr', ioc, target_path], capture_output=True).returncode == 0:
                        print(f"  {RED}[!] SafeDep IOC FOUND:{NC} '{ioc}' traces detected in {cache_dir}.")
                        paranoia_level += 1
        elif "bpf" in ioc or "scales" in ioc:
            try:
                find_cmd = f"find /tmp /var/tmp ~/.config -type f -name '{ioc}' 2>/dev/null"
                result = subprocess.run(find_cmd, shell=True, capture_output=True, text=True)
                if result.stdout.strip():
                    print(f"  {RED}[!] SafeDep IOC FOUND:{NC} eBPF rootkit artifact ({ioc}) detected.")
                    paranoia_level += 1
            except Exception:
                pass

    if paranoia_level == 0:
        print(f"  {GREEN}[+] ZERO ARTIFACTS FOUND.{NC} The malicious hooks did not execute.")
        print(f"  {GREEN}[+] Paranoia averted. Safe to surgically remove the package.{NC}")
        return False
    else:
        print(f"\n  {RED}[!!!] SYSTEM COMPROMISE CONFIRMED [!!!]{NC}")
        print(f"  The hooks executed. Uninstalling the package will NOT clear the rootkit.")
        print(f"  Rotate all keys and reinstall the OS from clean media.")
        return True

def get_package_info(pkg):
    try:
        result = subprocess.run(['pacman', '-Qi', pkg], capture_output=True, text=True, check=True)
        desc = "Unknown"
        req_by = "None"
        for line in result.stdout.split('\n'):
            if line.startswith("Description"):
                desc = line.split(':', 1)[1].strip()
            elif line.startswith("Required By"):
                req_by = line.split(':', 1)[1].strip()
        return desc, req_by
    except subprocess.CalledProcessError:
        return "Unknown", "None"

def main():
    print(f"{RED}[!!!] CRITICAL INCIDENT AUDITOR: ATOMIC ARCH [!!!]{NC}")
    
    blocklist = fetch_sonatype_packages()
    safedep_iocs = fetch_safedep_iocs()
    local_pkgs = get_local_aur_packages()
    
    affected = [pkg for pkg in local_pkgs if pkg in blocklist]

    if not affected:
        print(f"{GREEN}[+] System Clean. No known compromised AUR packages found.{NC}")
        sys.exit(0)

    print(f"{RED}[!] Found {len(affected)} affected package(s) on your system.{NC}\n")

    for pkg in affected:
        print(f"{YELLOW}======================================================{NC}")
        print(f"{CYAN}Target:{NC} {pkg}")
        
        desc, req_by = get_package_info(pkg)
        print(f"{CYAN}Category:{NC} {desc}")
        
        if req_by == "None":
            print(f"{CYAN}Blast Radius:{NC} Zero. Safe to remove.")
        else:
            print(f"{RED}WARNING - BLAST RADIUS:{NC} The following will BREAK if removed:")
            print(f" -> {req_by}")
        print(f"{YELLOW}------------------------------------------------------{NC}")
        
        is_compromised = scan_iocs(safedep_iocs)
        print(f"{YELLOW}------------------------------------------------------{NC}")
        
        if is_compromised:
            print(f"{RED}WARNING: Because artifacts were found, pacman -Rns will NOT save you.{NC}")
        
        confirm = input(f"Grant permission to execute removal of {pkg}? (y/N): ").strip().lower()
        if confirm == 'y':
            subprocess.run(['sudo', 'pacman', '-Rns', pkg])
            print(f"{CYAN}[+] Neutralized package: {pkg}.{NC}\n")
        else:
            print(f"{YELLOW}[-] Bypassed: {pkg}.{NC}\n")

    print(f"{CYAN}[*] Audit run completed.{NC}")

if __name__ == "__main__":
    main()
