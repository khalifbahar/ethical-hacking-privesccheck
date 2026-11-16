# PrivEscCheck

**Linux Privilege Escalation Checker**

## Description
PrivEscCheck is an original ethical hacking tool for the OS Specific Attack category. It identifies common local privilege escalation vectors on Linux systems, including SUID/SGID binaries, writable directories in PATH, cron jobs, Linux capabilities, and sudo permissions. All checks are local-only.

## Attack Category
OS Specific Attack

## Attack Lifecycle Mapping
- **Reconnaissance / Privilege Escalation Discovery**: Primary phase. Identifies potential local privilege escalation paths.
- **Exploitation**: None (discovery only).
- **Reporting**: Local JSON output.

## Installation
```bash
git clone <your-repo-url>
cd privesccheck
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
chmod +x privesccheck.py
```

## Usage
```bash
python3 privesccheck.py
python3 privesccheck.py -o ./results
python3 privesccheck.py --help
```

## Ethical Considerations
Local-only checks, mandatory authorization confirmation, legal disclaimer, kill switch (Ctrl+C), and local-only data storage.

## Rules of Engagement (RoE)
- **Authorized Scope**: Local system only, or systems with explicit written authorization.
- **Time Windows**: During authorized testing periods only.
- **Permitted Techniques**: Read-only discovery of SUID binaries, PATH, cron, capabilities, and sudo rights.
- **Prohibited Actions**: No actual exploitation, no remote scanning, no unauthorized use.
- **Emergency Stop**: Ctrl+C for immediate clean abort.

## Responsible Disclosure
Report any real findings privately to the system owner. Do not exploit or publicly disclose without permission.

## Legal Disclaimer
References Computer Crimes Act 1997 (Malaysia). Unauthorized use is illegal.

## Limitation Notes
- Some checks require the corresponding system tools to be installed.
- Results are informational; manual verification is recommended.
- Not exhaustive.
- Educational use only.

## License
MIT

## Output
JSON report saved in the output directory.
