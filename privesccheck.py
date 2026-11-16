#!/usr/bin/env python3
"""
PrivEscCheck - Linux Privilege Escalation Checker
Category: OS Specific Attack
Identifies common local privilege escalation vectors on Linux systems.
"""

import argparse
import json
import os
import signal
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path

KILL_SWITCH = False

def signal_handler(sig, frame):
    global KILL_SWITCH
    print("\n[!] Kill switch activated. Aborting cleanly...")
    KILL_SWITCH = True
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

DISCLAIMER = """
================================================================================
LEGAL DISCLAIMER - COMPUTER CRIMES ACT 1997 (MALAYSIA)
================================================================================
This tool is for educational and authorized ethical hacking purposes only.
Unauthorized access or privilege escalation attempts are criminal offences under
the Computer Crimes Act 1997 (Act 563).

This tool only inspects the local system. You must have explicit authorization
before running it. By continuing you confirm you have proper authorization.

The authors accept no liability for misuse.
================================================================================
"""

def display_disclaimer():
    print(DISCLAIMER)
    confirm = input("Do you have explicit authorization to check this system for privilege escalation vectors? (yes/no): ").strip().lower()
    if confirm not in ("yes", "y"):
        print("[!] Authorization not confirmed. Exiting.")
        sys.exit(1)
    print("[+] Authorization confirmed. Starting local privilege escalation checks only.\n")

def run_command(cmd, timeout=5):
    """Run a shell command safely and return output."""
    if KILL_SWITCH:
        return ""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except Exception:
        return ""

def check_suid_sgid():
    """Find SUID and SGID binaries."""
    print("[*] Checking for SUID/SGID binaries...")
    findings = []
    # Common interesting SUID binaries
    interesting = ["nmap", "vim", "find", "bash", "sh", "python", "perl", "ruby", "awk", "less", "more", "nano", "cp", "mv"]
    output = run_command("find / -perm -4000 -type f 2>/dev/null | head -50")
    for line in output.splitlines():
        if KILL_SWITCH:
            break
        binary = os.path.basename(line)
        severity = "High" if any(x in binary.lower() for x in interesting) else "Info"
        findings.append({
            "path": line,
            "type": "SUID",
            "severity": severity,
            "note": "Potential privilege escalation vector" if severity == "High" else "Standard SUID binary"
        })
        print(f"  [{severity}] SUID: {line}")
    return findings

def check_writable_path():
    """Check if any directories in PATH are writable by current user."""
    print("[*] Checking PATH for writable directories...")
    findings = []
    path_dirs = os.environ.get("PATH", "").split(":")
    for directory in path_dirs:
        if KILL_SWITCH or not directory or not os.path.isdir(directory):
            continue
        if os.access(directory, os.W_OK):
            findings.append({
                "path": directory,
                "issue": "Writable directory in PATH",
                "severity": "High",
                "note": "Can be used for PATH hijacking privilege escalation"
            })
            print(f"  [High] Writable PATH directory: {directory}")
    return findings

def check_cron_jobs():
    """Check cron jobs for potential issues."""
    print("[*] Checking cron jobs...")
    findings = []
    cron_paths = ["/etc/crontab", "/etc/cron.d/", "/var/spool/cron/crontabs/"]
    for path in cron_paths:
        if KILL_SWITCH:
            break
        if os.path.isfile(path):
            try:
                with open(path, "r") as f:
                    content = f.read()
                if content.strip():
                    findings.append({
                        "path": path,
                        "type": "cron",
                        "severity": "Info",
                        "note": "Cron file exists - review for writable scripts or wildcards"
                    })
                    print(f"  [Info] Cron file: {path}")
            except PermissionError:
                pass
    return findings

def check_capabilities():
    """Check for binaries with capabilities."""
    print("[*] Checking for Linux capabilities...")
    findings = []
    output = run_command("getcap -r / 2>/dev/null | head -30")
    for line in output.splitlines():
        if KILL_SWITCH:
            break
        if line.strip():
            findings.append({
                "entry": line,
                "type": "capability",
                "severity": "Medium",
                "note": "Binary with special capabilities"
            })
            print(f"  [Medium] {line}")
    return findings

def check_sudo_permissions():
    """Check sudo -l if possible."""
    print("[*] Checking sudo permissions...")
    output = run_command("sudo -n -l 2>/dev/null")
    findings = []
    if output and "not allowed" not in output.lower():
        findings.append({
            "type": "sudo",
            "output": output[:500],
            "severity": "High",
            "note": "User has sudo privileges - review allowed commands"
        })
        print("  [High] Sudo privileges detected")
    else:
        print("  [Info] No passwordless sudo or sudo not available")
    return findings

def check_kernel_info():
    """Get kernel version (informational)."""
    kernel = run_command("uname -r")
    return {"kernel": kernel, "note": "Check for known kernel exploits matching this version"}

def run_checks():
    findings = {
        "suid_sgid": check_suid_sgid(),
        "writable_path": check_writable_path(),
        "cron": check_cron_jobs(),
        "capabilities": check_capabilities(),
        "sudo": check_sudo_permissions(),
        "kernel": check_kernel_info()
    }
    return findings

def save_results(findings, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"privesc_report_{timestamp}.json")
    report = {
        "timestamp": datetime.now().isoformat(),
        "hostname": os.uname().nodename,
        "findings": findings
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Results saved to {filename}")
    return filename

def main():
    parser = argparse.ArgumentParser(
        description="PrivEscCheck - Linux Privilege Escalation Checker (OS Specific Attack)",
        epilog="Local checks only. Educational and authorized use only."
    )
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    args = parser.parse_args()

    display_disclaimer()
    print("[*] Starting privilege escalation checks (local system only)...")
    findings = run_checks()

    high_count = 0
    for category in findings.values():
        if isinstance(category, list):
            high_count += sum(1 for item in category if isinstance(item, dict) and item.get("severity") == "High")

    print(f"\n[*] Checks complete. High severity findings: {high_count}")
    save_results(findings, args.output)
    print("[!] Review results carefully. Only use on systems you are authorized to test.")

if __name__ == "__main__":
    main()
