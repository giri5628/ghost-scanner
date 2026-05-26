GHOST - Vulnerability Scanner & OSINT Tool

Cross-platform vulnerability scanner for Kali Linux, Termux & Windows

## Features
* IP + Geo Intelligence - Location, ISP, ASN via ip-api.com
* WHOIS Lookup - Domain registration data with expiry check
* Subdomain Discovery - Using hackertarget.com API
* Port Scan - Color-coded severity (CRITICAL/HIGH/MEDIUM/LOW)
* SSL/TLS Analysis - Certificate expiry, cipher strength
* HTTP Security Headers - HSTS, CSP, X-Frame-Options audit
* DNS Security - SPF, DKIM, DMARC, CAA records
* Wayback Machine - Historical snapshots via archive.org
* Sensitive File Exposure - .env, .git, phpinfo, backups
* HTML Report - Auto-generated with auto-open in browser

## Installation & Usage

### Kali Linux / Termux
```bash
# 1. Clone the repository
   git clone https://github.com/gireeshsec/ghost-scanner.git

# 2. Go to folder
  cd ghost-scanner

# 3. Install dependencies
  python3 -m venv ghost-env
  source ghost-env/bin/activate
  pip install requests python-whois dnspython

# 4. Run the tool
     python3 ghost.py 
```
# ⚠️ Legal Disclaimer
   For authorized security testing and educational purposes only.  
   Unauthorized scanning of systems you don't own is illegal.
   
# Author
  Gireesh G
  
# License
MIT License - Open Source
