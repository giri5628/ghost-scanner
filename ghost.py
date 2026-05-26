#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════╗
# ║   GHOST.py — Vulnerability Scanner & OSINT Tool          ║
# ║   For authorized security testing only                   ║
# ║   Usage: python3 ghost.py example.com                    ║
# ╚══════════════════════════════════════════════════════════╝


import sys, os, ssl, socket, datetime, time, subprocess, warnings
from datetime import timezone
warnings.filterwarnings("ignore", category=DeprecationWarning)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def install(pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

try: import requests
except: install("requests"); import requests
try: import whois
except: install("python-whois"); import whois
try: import dns.resolver
except: install("dnspython"); import dns.resolver

dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
dns.resolver.default_resolver.timeout = 3
dns.resolver.default_resolver.lifetime = 3

R='\033[38;5;196m'; G='\033[38;5;46m'; Y='\033[38;5;226m'; B='\033[38;5;21m'; C='\033[38;5;51m'
W='\033[97m'; DIM='\033[2m'; BOLD='\033[1m'; RST='\033[0m'


if os.name == 'nt':
    R=G=Y=B=C=W=DIM=BOLD=RST=''
 
def red(s): return R+str(s)+RST
def green(s): return G+str(s)+RST
def yellow(s): return Y+str(s)+RST
def blue(s): return B+str(s)+RST
def cyan(s): return C+str(s)+RST
def bold(s): return BOLD+str(s)+RST
def dim(s): return DIM+str(s)+RST


__version__ = "1.0.0"

def banner():
    os.system('clear' if os.name!= 'nt' else 'cls')
    print(cyan(bold(r"""
  ██████  ██╗  ██╗ ██████╗ ███████╗████████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ██║  ███╗███████║██║   ██║███████╗   ██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
""")))
    print(f"{'':>28}{red('Version : ' + __version__)}\n")
    print(f" {green('[+] Tool Created by Gireesh G')}\n")
    print(f" {bold('GHOST -  Vulnerability & OSINT Tool')}")
    print(f" {dim('For authorized security testing only')}\n")

results = {"target":"","ip":"","findings":[],"ports":[],"ssl":{}}
SEV = {"CRITICAL":red,"HIGH":yellow,"MEDIUM":yellow,"LOW":blue,"PASS":green,"INFO":cyan,"CLEAN":green}

def print_finding(sev, title, detail=""):
    fn = SEV.get(sev, cyan)
    tag = fn(f"[{sev}]".ljust(10))
    print(f" {tag} {title}")
    if detail:
        for line in detail.strip().split('\n'): print(dim(f" {line}"))

def add_finding(sev, title, desc): results["findings"].append({"sev":sev,"title":title,"desc":desc})

def section(title):
    print(f"\n{cyan('═'*55)}")
    print(bold(cyan(f" ◈ {title}")))
    print(cyan('═'*55))

def format_date(date_obj):
    if not date_obj: return "N/A"
    if isinstance(date_obj, list):
        date_obj = date_obj[0] if date_obj else None
    if not date_obj: return "N/A"
    if isinstance(date_obj, datetime.datetime):
        if date_obj.tzinfo: date_obj = date_obj.replace(tzinfo=None)
        return date_obj.strftime("%Y-%m-%d %H:%M:%S")
    return str(date_obj)

def run_geo(target):
    section("IP RESOLUTION + GEO INTELLIGENCE")
    try:
        ip = socket.gethostbyname(target)
        results["ip"] = ip
        print_finding("INFO", f"Resolved IP: {ip}")
        print_finding("INFO", f"Target: {target}")
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=8).json()
        if r.get("status") == "success":
            results["geo"] = r 
            print_finding("INFO", f"Country: {r.get('country')} ({r.get('countryCode')})")
            print_finding("INFO", f"City: {r.get('city')}, {r.get('regionName')}")
            print_finding("INFO", f"ISP: {r.get('isp')}")
            print_finding("INFO", f"ASN: {r.get('as')}")
            print_finding("INFO", f"Org: {r.get('org')}")
            print_finding("INFO", f"Timezone: {r.get('timezone')}")
            print_finding("INFO", f"Lat/Lon: {r.get('lat')}, {r.get('lon')}")
    except socket.gaierror:
        print_finding("CRITICAL", f"DNS Resolution Failed: {target}")
        add_finding("CRITICAL", "DNS Resolution Failed", "Target domain does not exist")
    except: print_finding("INFO", "Geo lookup failed")

def run_whois(target):
    section("WHOIS REGISTRATION DATA")
    try: socket.inet_aton(target); return
    except: pass
    try:
        w = whois.whois(target)
        print_finding("INFO", f"Registrar: {w.registrar or 'N/A'}")
        print_finding("INFO", f"Created: {format_date(w.creation_date)}")
        print_finding("INFO", f"Updated: {format_date(w.updated_date)}")
        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0] if exp else None
        if exp and isinstance(exp, datetime.datetime):
            if exp.tzinfo: exp = exp.replace(tzinfo=None)
            days = (exp - datetime.datetime.now()).days
            if days < 0:
                print_finding("CRITICAL", f"Domain EXPIRED {abs(days)} days ago!")
                add_finding("CRITICAL", "Domain Expired", "")
            elif days < 30:
                print_finding("CRITICAL", f"Expires in {days} days — URGENT")
                add_finding("CRITICAL", f"Domain Expiring in {days} days", "")
            else: print_finding("PASS", f"Expiry OK — {days} days remaining")
    except:
        print_finding("INFO", "WHOIS lookup failed - Data unavailable")

def run_subdomains(target):
    section("SUBDOMAIN DISCOVERY")
    try: socket.inet_aton(target); return
    except: pass

    subs_found = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={target}", timeout=10, headers=headers)
        if r.status_code == 200 and "error" not in r.text.lower():
            lines = r.text.strip().split('\n')
            subs = [line.split(',')[0] for line in lines if line and ',' in line]
            subs_found.extend(subs)
            if subs: print_finding("PASS", f"Hackertarget: Found {len(subs)} subdomains")
    except:
        pass

    if not subs_found:
        print_finding("INFO", "Trying DNS bruteforce on common subdomains...")
        common = ['www','mail','ftp','admin','test','dev','api','blog','shop','cpanel','webmail','smtp','ns1','ns2','staging','vpn']
        for sub in common:
            try:
                full_domain = f"{sub}.{target}"
                socket.gethostbyname(full_domain)
                subs_found.append(full_domain)
                print(f" {green('•')} {full_domain}")
            except:
                pass

    if subs_found:
        unique_subs = sorted(list(set(subs_found)))
        results["subdomains"] = [{"name": s} for s in unique_subs] 
        print(f"\n {green('✓')} Total Found: {bold(str(len(unique_subs)))} subdomains\n")
        for s in unique_subs[:40]:
            print(f" {green('•')} {s}")
        if len(unique_subs) > 40:
            print(f" {dim('... and')} {len(unique_subs)-40} {dim('more')}")
        sensitive = ['admin','phpmyadmin','test','dev','staging','api','cpanel','webmail','mail','ftp','vpn','git','jenkins']
        if any(k in s for s in unique_subs for k in sensitive):
            print_finding("HIGH", "Sensitive subdomains discovered!")
            add_finding("HIGH", "Sensitive Subdomains", "Admin/dev panels found")
    else:
        print(f"\n {blue('✓')} Found {bold('0')} subdomains")
        print_finding("INFO", "No subdomains found from available sources")

def run_ports(target):
    section("PORT SCAN")
    PORTS = {
        21: ("FTP", "HIGH", "FTP — plaintext credentials, check anonymous login"),
        22: ("SSH", "INFO", "SSH — verify strong keys, no password auth"),
        23: ("Telnet", "CRITICAL","Telnet — PLAINTEXT protocol, replace with SSH immediately"),
        25: ("SMTP", "INFO", "SMTP mail server"),
        53: ("DNS", "INFO", "DNS server — check for zone transfer"),
        80: ("HTTP", "INFO", "HTTP web server"),
        443: ("HTTPS", "PASS", "HTTPS — good"),
        445: ("SMB", "HIGH", "SMB — EternalBlue/WannaCry risk, block from internet"),
        3306:("MySQL", "CRITICAL","MySQL exposed to internet — critical misconfiguration"),
        3389:("RDP", "HIGH", "RDP — BlueKeep CVE-2019-0708 risk, brute force target"),
        5432:("PostgreSQL","HIGH", "PostgreSQL exposed — should not be internet-facing"),
        5900:("VNC", "HIGH", "VNC — remote desktop, often weak/no auth"),
        6379:("Redis", "CRITICAL","Redis exposed — often no auth, full data access"),
        8080:("HTTP-Alt","INFO", "Alternative HTTP port"),
        8443:("HTTPS-Alt","INFO", "Alternative HTTPS port"),
        9200:("Elasticsearch","CRITICAL","Elasticsearch — often no auth, massive data breach risk"),
        27017:("MongoDB","CRITICAL","MongoDB — often no auth by default")
    }
    ip = results.get("ip","")
    if not ip:
        try: ip = socket.gethostbyname(target)
        except: print_finding("HIGH", "Cannot resolve IP for port scan"); return
    open_ports = []
    print(f" {dim('Scanning common ports...')}\n")
    for port, (svc, sev, desc) in PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append({"port": port, "svc": svc, "sev": sev, "desc": desc})
                color = red if sev in ["CRITICAL","HIGH"] else (yellow if sev=="MEDIUM" else green)
                print(f" {color('OPEN')} {str(port).ljust(6)} {svc.ljust(15)} {dim(desc)}")
                if sev not in ["PASS","INFO"]:
                    add_finding(sev, f"Port {port}/{svc} Open", desc)
            else:
                print(f" {dim('CLSD')} {str(port).ljust(6)} {dim(svc)}")
        except Exception:
            print(f" {dim('ERR ')} {str(port).ljust(6)} {dim(svc)}")
    results["ports"] = open_ports
    if not open_ports:
        print_finding("INFO", "No common ports open (firewall may be blocking)")

def run_ssl(target):
    section("SSL / TLS ANALYSIS")
    ssl_worked = False

    for tls_name, tls_ver in [("TLSv1.2", ssl.TLSVersion.TLSv1_2),
                               ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                               ("TLSv1.0", ssl.TLSVersion.TLSv1)]:
        try:
            addr_info = socket.getaddrinfo(target, 443, socket.AF_INET, socket.SOCK_STREAM)
            ip = addr_info[0][4][0]
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = tls_ver
            context.maximum_version = tls_ver

            with socket.create_connection((ip, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    print_finding("INFO", f"TLS Version: {version}")
                    print_finding("INFO", f"Cipher: {cipher[0] if cipher else 'N/A'} ({cipher[2] if cipher else '?'} bits)")
                    exp_str = cert.get("notAfter","")
                    if exp_str:
                        exp_dt = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                        days = (exp_dt.replace(tzinfo=None) - datetime.datetime.now()).days
                        if days < 0:
                            add_finding("CRITICAL", "SSL Certificate Expired", f"Expired {abs(days)} days ago")
                            print_finding("CRITICAL", f"Certificate EXPIRED {abs(days)} days ago!")
                        elif days < 30:
                            add_finding("HIGH", f"SSL Certificate Expiring in {days} days", "Renew soon")
                            print_finding("HIGH", f"Certificate expires in {days} days")
                        else:
                            print_finding("PASS", f"Certificate valid — {days} days remaining")
                    subj = dict(x[0] for x in cert.get("subject",[]))
                    issuer = dict(x[0] for x in cert.get("issuer",[]))
                    print_finding("INFO", f"Subject: {subj.get('commonName','N/A')}")
                    print_finding("INFO", f"Issuer: {issuer.get('organizationName','N/A')}")
                    if version in ["TLSv1", "TLSv1.1"]:
                        add_finding("HIGH", f"Deprecated TLS Version: {version}", "TLS 1.0/1.1 are deprecated. Use TLS 1.2+")
                        print_finding("HIGH", f"Deprecated TLS version: {version} - Security Risk!")
                    else:
                        print_finding("PASS", f"TLS Version OK: {version}")
                    ssl_worked = True
                    break
        except ssl.SSLError as e:
            if "SSLV3_ALERT_HANDSHAKE_FAILURE" in str(e):
                continue
            else:
                continue
        except:
            continue

    if not ssl_worked:
        print_finding("HIGH", "SSL/TLS Handshake Failed with all versions")
        print_finding("INFO", "Reason: Server uses SSLv3/deprecated TLS or port filtered")
        add_finding("HIGH", "Obsolete SSL/TLS", "Server does not support TLS 1.0+. Critical security risk.")
        try:
            r = requests.get(f"https://{target}", timeout=10, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            print_finding("PASS", f"HTTPS accessible via requests - Status {r.status_code}")
            print_finding("MEDIUM", "HTTPS works but raw socket SSL failed - Possible SNI/ALPN issue")
        except requests.exceptions.SSLError:
            print_finding("HIGH", "Port 443 open but SSL handshake fails - Server misconfigured")
            add_finding("HIGH", "SSL Misconfiguration", "Port 443 responds but no valid TLS version")
        except requests.exceptions.ConnectionError:
            print_finding("INFO", "Port 443 not accessible - HTTP only site or firewall blocking")
        except requests.exceptions.Timeout:
            print_finding("INFO", "Port 443 timeout - Firewall may be dropping packets")
        except:
            print_finding("INFO", "HTTPS check failed - Unable to determine reason")

def run_headers(target):
    section("HTTP SECURITY HEADERS")
    HEADERS = {"Strict-Transport-Security":"HIGH","Content-Security-Policy":"HIGH","X-Frame-Options":"MEDIUM","X-Content-Type-Options":"LOW"}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    }
    url = None
    for scheme in ["https", "http"]:
        try:
            test_url = f"{scheme}://{target}"
            r = requests.get(test_url, timeout=15, verify=False, headers=headers, allow_redirects=True)
            url = test_url
            print_finding("INFO", f"Connected via {scheme.upper()}")
            break
        except:
            continue
    if not url:
        print_finding("INFO", "Header check skipped - Site not reachable (ISP may be blocking)")
        print_finding("INFO", "Try: Run with VPN or Mobile Hotspot")
        return
    try:
        r = requests.get(url, timeout=15, verify=False, headers=headers)
        print_finding("INFO", f"HTTP Status: {r.status_code} ({url.split('://')[0].upper()})")
        if "https" not in url:
            print_finding("HIGH", "Site uses HTTP only - No encryption")
            add_finding("HIGH", "HTTP Only - No HTTPS", "Data transmitted in plaintext")
        if r.headers.get("Server"):
            print_finding("INFO", f"Server header: {r.headers['Server']}")
        for h,sev in HEADERS.items():
            if h in r.headers:
                print_finding("PASS", f"{h} ✓")
            else:
                print_finding(sev, f"{h} MISSING")
                add_finding(sev, f"Missing Header: {h}", f"{h} not set")
    except Exception as e:
        print_finding("INFO", f"Header check failed: {str(e)[:50]}")

def run_dns(target):
    section("DNS SECURITY (SPF / DKIM / DMARC / CAA)")
    try: socket.inet_aton(target); return
    except: pass
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        resolver.timeout = 3
        resolver.lifetime = 3
        try:
            for r in resolver.resolve(target, "TXT"):
                if r.to_text().strip('"').startswith("v=spf1"):
                    print_finding("PASS", f"SPF Record Found: {r.to_text()[:60]}...")
                    break
            else: print_finding("HIGH", "SPF Record MISSING"); add_finding("HIGH", "No SPF Record", "Email spoofing possible")
        except: pass
        try:
            for r in resolver.resolve(f"_dmarc.{target}", "TXT"):
                txt = r.to_text().strip('"')
                if "DMARC1" in txt:
                    policy = "reject" if "p=reject" in txt else "quarantine" if "p=quarantine" in txt else "none"
                    print_finding("PASS", f"DMARC Found - Policy: {policy}")
                    if policy == "none": add_finding("MEDIUM", "DMARC Policy is 'none'", "Not enforcing")
                    break
        except: print_finding("MEDIUM", "DMARC Record MISSING"); add_finding("MEDIUM", "No DMARC Record", "No email fraud protection")
        try:
            for r in resolver.resolve(f"google._domainkey.{target}", "TXT"):
                if "DKIM1" in r.to_text(): print_finding("PASS", "DKIM Found (selector: google) ✓"); break
        except: pass
        try: resolver.resolve(target, "CAA"); print_finding("PASS", "CAA Record Found")
        except: print_finding("LOW", "CAA Record MISSING - Any CA can issue certificates")
        try: resolver.resolve(target, "AXFR"); print_finding("CRITICAL", "Zone Transfer OPEN!"); add_finding("CRITICAL", "Zone Transfer Enabled", "DNS records exposed")
        except: print_finding("PASS", "Zone Transfer blocked ✓")
        try:
            mx = resolver.resolve(target, "MX")
            for r in mx: print_finding("INFO", f"MX Record: {r.exchange} (priority {r.preference})")
        except: pass
    except: pass

def run_wayback(target):
    section("WAYBACK MACHINE / HISTORY")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json',
            'Referer': 'https://web.archive.org/'
        }
        endpoints = [
            f"http://web.archive.org/cdx/search/cdx?url={target}*&output=json&limit=10&fl=timestamp,original",
            f"https://web.archive.org/cdx/search/cdx?url={target}*&output=json&limit=10",
            f"http://web.archive.org/cdx/search/cdx?url=*.{target}&output=json&limit=10"
        ]
        data = None
        for url in endpoints:
            try:
                r = requests.get(url, timeout=25, headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    if len(data) > 1: break
            except: continue
        if data and len(data) > 1:
            print_finding("INFO", f"Wayback Machine has snapshots!")
            print("")
            for row in data[1:]:
                ts = row[0]
                date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                url_found = row[1] if len(row) > 1 else target
                print(f" • {date} {dim(url_found)}")
            print(f"\n Total snapshots: {len(data)-1} pages")
            print(f" Browse all: https://web.archive.org/web/*/{target}")
        else:
            print_finding("INFO", "No Wayback snapshots found for this domain")
            print_finding("INFO", "Reason: Domain may be new or never crawled")
            print(f" {dim('Try manually: https://web.archive.org/web/*/' + target)}")
    except requests.exceptions.Timeout:
        print_finding("INFO", "Wayback Machine timeout - Server overloaded")
        print_finding("INFO", f"Try: python3 ghost.py {target} (run again)")
    except requests.exceptions.ConnectionError:
        print_finding("INFO", "Wayback blocked this network - Use VPN")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            print_finding("INFO", "Wayback blocked this IP - Use VPN or Mobile Hotspot")
        elif e.response.status_code == 429:
            print_finding("INFO", "Wayback rate limited - Wait 1 minute and retry")
        else:
            print_finding("INFO", f"Wayback HTTP {e.response.status_code}")
    except Exception as e:
        print_finding("INFO", f"Wayback unavailable: {str(e)[:60]}")

def run_content(target):
    section("WEB CONTENT ANALYSIS")
    checks = [
        ("/.env", "CRITICAL", "Environment file exposed — may contain DB passwords, API keys"),
        ("/.git/config", "CRITICAL", "Git repository exposed — source code accessible"),
        ("/phpinfo.php", "HIGH", "PHP info page exposed — reveals server config"),
        ("/wp-login.php", "MEDIUM", "WordPress login detected"),
        ("/wp-admin/", "MEDIUM", "WordPress admin panel accessible"),
        ("/admin/", "MEDIUM", "Admin panel accessible"),
        ("/phpmyadmin/", "HIGH", "phpMyAdmin exposed — database admin interface"),
        ("/backup.sql", "CRITICAL", "SQL backup file exposed"),
        ("/backup.zip", "CRITICAL", "Backup archive exposed"),
        ("/.htpasswd", "HIGH", ".htpasswd file exposed — contains password hashes"),
        ("/config.php.bak", "HIGH", "PHP config backup exposed"),
        ("/robots.txt", "INFO", "robots.txt found — check for hidden paths"),
        ("/sitemap.xml", "INFO", "Sitemap found"),
        ("/crossdomain.xml", "LOW", "Crossdomain policy found"),
        ("/xmlrpc.php", "MEDIUM", "WordPress XML-RPC enabled — brute force / DDoS vector"),
        ("/server-status", "HIGH", "Apache server-status exposed — reveals active connections"),
        ("/server-info", "HIGH", "Apache server-info exposed — reveals config"),
        ("/.DS_Store", "MEDIUM", ".DS_Store file exposed — reveals directory structure"),
        ("/api/v1/", "INFO", "API endpoint found"),
        ("/swagger.json", "MEDIUM", "Swagger API docs exposed — full API enumeration possible"),
        ("/openapi.json", "MEDIUM", "OpenAPI docs exposed"),
        ("/.well-known/security.txt","INFO","Security.txt found"),
    ]
    print(f" {dim('Checking common sensitive paths...')}\n")
    found_critical = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    for path, sev, desc in checks:
        path_found = False
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{target}{path}"
                r = requests.get(url, timeout=4, allow_redirects=False, headers=headers, verify=False)
                if r.status_code in [200, 301, 302, 403]:
                    path_found = True
                    if r.status_code == 200:
                        color_fn = red if sev in ["CRITICAL","HIGH"] else (yellow if sev=="MEDIUM" else cyan)
                        print(f" {color_fn('FOUND')} [{r.status_code}] {path} {dim(desc)}")
                        if sev not in ["INFO"]:
                            add_finding(sev, f"Exposed: {path}", f"{desc}\nURL: {url}\nStatus: {r.status_code}")
                            if sev == "CRITICAL":
                                found_critical.append(path)
                    elif r.status_code == 403:
                        print(f" {yellow('BLOCK')} [{r.status_code}] {path} {dim('(exists but blocked)')}")
                    break
            except:
                continue
        if not path_found:
            print(f" {dim('MISS ')} [404] {dim(path)}")
    if found_critical:
        print(f"\n {red('⚠ CRITICAL files found:')} {', '.join(found_critical)}")
def print_summary():
    section("SCAN SUMMARY")
    
    sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0,"PASS":0}
    for f in results["findings"]:
        sev_counts[f["sev"]] = sev_counts.get(f["sev"],0) + 1
    
    total_vulns = sev_counts["CRITICAL"] + sev_counts["HIGH"] + sev_counts["MEDIUM"] + sev_counts["LOW"]
    overall = "CRITICAL" if sev_counts["CRITICAL"]>0 else "HIGH" if sev_counts["HIGH"]>2 else "MEDIUM" if sev_counts["MEDIUM"]>2 else "LOW" if total_vulns>0 else "CLEAN"
    
    print(f" {bold('Overall Risk:')} {SEV[overall](overall)}")
    print(f" {bold('Total Findings:')} {len(results['findings'])}")
    print(f" {bold('Target:')} {cyan(results['target'])}")
    print(f" {bold('IP:')} {results.get('ip','N/A')}")
    print()
    print(f" {red('●')} CRITICAL: {sev_counts['CRITICAL']}")
    print(f" {yellow('●')} HIGH:     {sev_counts['HIGH']}")
    print(f" {yellow('●')} MEDIUM:   {sev_counts['MEDIUM']}")
    print(f" {blue('●')} LOW:      {sev_counts['LOW']}")
    print(f" {cyan('●')} INFO:     {sev_counts['INFO']}")
    print(f" {green('●')} PASS:     {sev_counts['PASS']}")
    print()
def generate_report(target):
    section("GENERATING HTML REPORT")

    sev_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0,"PASS":0}
    for f in results["findings"]:
        sev_counts[f["sev"]] = sev_counts.get(f["sev"],0) + 1

    total_vulns = sev_counts["CRITICAL"] + sev_counts["HIGH"] + sev_counts["MEDIUM"] + sev_counts["LOW"]
    overall = "CRITICAL" if sev_counts["CRITICAL"]>0 else "HIGH" if sev_counts["HIGH"]>2 else "MEDIUM" if sev_counts["MEDIUM"]>2 else "LOW" if total_vulns>0 else "CLEAN"

    sev_colors = {
        "CRITICAL":"#ff2255","HIGH":"#ff7700","MEDIUM":"#ffd000",
        "LOW":"#00ff9d","PASS":"#00cc7d","INFO":"#00aaff"
    }

    findings_html = ""
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","PASS"]:
        group = [f for f in results["findings"] if f["sev"]==sev]
        if not group: continue
        for f in group:
            col = sev_colors.get(sev,"#aaa")
            findings_html += f"""
            <div class="finding" style="border-left:3px solid {col}">
                <div class="finding-hdr">
                    <span class="sev-tag" style="background:{col}22;color:{col};border:1px solid {col}44">{sev}</span>
                    <span class="finding-title">{f['title']}</span>
                </div>
                <div class="finding-desc">{f['desc']}</div>
                {"<div class='finding-detail'>"+f['detail']+"</div>" if f.get('detail') else ""}
            </div>"""

    subdomains_html = ""
    for s in results.get("subdomains",[])[:50]:
        subdomains_html += f"<div class='sub-item'><span class='dot'></span>{s['name']}</div>"
    if not subdomains_html:
        subdomains_html = "<div style='color:#5a8aaa'>No subdomains found or scan not completed</div>"

    ports_html = ""
    for p in results.get("ports",[]):
        col = "#ff2255" if p["sev"] in ["CRITICAL","HIGH"] else "#ffd000" if p["sev"]=="MEDIUM" else "#00ff9d"
        ports_html += f"<div class='port-item'><span style='color:{col}'>{p['port']}/tcp</span> <span>{p['svc']}</span></div>"
    if not ports_html:
        ports_html = "<div style='color:#5a8aaa'>No open ports found</div>"

    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    geo = results.get("geo",{})

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GHOST Scan — {target}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Space+Grotesk:wght@400;500;600;700&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#03070d;color:#8ab4d4;font-family:'Space Grotesk',sans-serif;padding:0}}
body::before{{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,157,.007) 2px,rgba(0,255,157,.007) 4px);pointer-events:none;z-index:9999}}
.mono{{font-family:'Share Tech Mono',monospace}}
#hdr{{background:linear-gradient(135deg,#040c18,#060d16);border-bottom:1px solid #0d2035;padding:18px 24px;position:relative;overflow:hidden}}
#hdr::after{{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,#00ff9d,transparent);opacity:.5}}
.logo{{font-family:'Share Tech Mono',monospace;font-size:28px;color:#00ff9d;letter-spacing:.2em;text-shadow:0 0 20px rgba(0,255,157,.5)}}
.logo-s{{font-size:11px;color:#00ff9d;opacity:.5;letter-spacing:.3em;margin-top:2px}}
#content{{max-width:900px;margin:0 auto;padding:20px}}
.hero{{background:linear-gradient(135deg,rgba(0,255,157,.06),rgba(0,170,255,.04));border:1px solid rgba(0,255,157,.2);border-radius:8px;padding:20px;margin-bottom:20px;position:relative;overflow:hidden}}
.hero::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#00ff9d,#00aaff,#cc44ff);opacity:.6}}
.target{{font-family:'Share Tech Mono',monospace;font-size:26px;color:#00ff9d;text-shadow:0 0 12px rgba(0,255,157,.3);margin-bottom:8px}}
.meta{{font-size:12px;color:#5a8aaa;letter-spacing:.08em}}
.risk-overall{{display:inline-block;padding:6px 16px;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:14px;font-weight:700;letter-spacing:.1em;margin-top:10px;border:1px solid}}
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:20px}}
.stat{{background:#060d16;border:1px solid #0d2035;border-radius:6px;padding:14px 10px;text-align:center}}
.stat-n{{font-family:'Share Tech Mono',monospace;font-size:28px;font-weight:700;line-height:1}}
.stat-l{{font-size:9px;color:#1a3550;letter-spacing:.12em;margin-top:4px;text-transform:uppercase}}
.section{{margin-bottom:24px}}
.sec-title{{font-family:'Share Tech Mono',monospace;font-size:13px;color:#00ff9d;letter-spacing:.2em;opacity:.6;text-transform:uppercase;margin-bottom:12px;display:flex;align-items:center;gap:8px}}
.sec-title::after{{content:'';flex:1;height:1px;background:#0d2035}}
.finding{{background:#060d16;border:1px solid #0d2035;border-radius:5px;padding:12px 14px;margin-bottom:8px;overflow:hidden}}
.finding-hdr{{display:flex;align-items:center;gap:10px;margin-bottom:6px}}
.sev-tag{{font-family:'Share Tech Mono',monospace;font-size:9px;font-weight:700;letter-spacing:.08em;padding:2px 8px;border-radius:2px;flex-shrink:0;text-align:center;min-width:65px}}
.finding-title{{font-size:13px;color:#b8d4e8;font-weight:600}}
.finding-desc{{font-size:11px;color:#5a8aaa;margin-bottom:6px;line-height:1.6}}
.finding-detail{{background:#030709;border-radius:3px;padding:8px 10px;font-family:'Share Tech Mono',monospace;font-size:11px;color:#8ab4d4;line-height:1.7;border:1px solid #0d2035;white-space:pre-wrap;word-break:break-all}}
.sub-item{{display:flex;align-items:center;gap:8px;padding:6px 10px;border-bottom:1px solid #0d2035;font-family:'Share Tech Mono',monospace;font-size:12px;color:#9bbdd4}}
.dot{{width:6px;height:6px;border-radius:50%;background:#00ff9d;flex-shrink:0}}
.port-item{{display:flex;gap:14px;padding:6px 10px;border-bottom:1px solid #0d2035;font-family:'Share Tech Mono',monospace;font-size:12px}}
.info-grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
.info-card{{background:#060d16;border:1px solid #0d2035;border-radius:5px;overflow:hidden}}
.info-card-title{{padding:8px 12px;background:rgba(0,255,157,.04);border-bottom:1px solid #0d2035;font-size:9px;color:#00ff9d;letter-spacing:.18em;text-transform:uppercase}}
.info-row{{display:flex;padding:6px 12px;border-bottom:1px solid #0d2035;gap:10px}}
.info-row:last-child{{border-bottom:none}}
.info-key{{font-size:10px;color:#1a3550;min-width:80px;flex-shrink:0}}
.info-val{{font-size:11px;color:#9bbdd4;word-break:break-all;font-family:'Share Tech Mono',monospace}}
footer{{text-align:center;padding:20px;font-size:11px;color:#1a3550;letter-spacing:.1em;border-top:1px solid #0d2035;margin-top:30px}}
@media(max-width:600px){{.stats{{grid-template-columns:repeat(3,1fr)}}.info-grid{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div id="hdr">
  <div class="logo">GHOST</div>
  <div class="logo-s">Vulnerability Scanner  &amp; OSINT Tool Report</div>
</div>
<div id="content">
  <div class="hero">
    <div class="target">{target}</div>
    <div class="meta">IP: {results.get('ip','N/A')} &nbsp;·&nbsp; {geo.get('country','N/A')} &nbsp;·&nbsp; {geo.get('isp','N/A')}</div>
    <div class="meta">Scan: {scan_time} &nbsp;·&nbsp; {len(results['findings'])} findings</div>
    <div class="risk-overall" style="background:rgba({'255,34,85' if overall=='CRITICAL' else '255,119,0' if overall=='HIGH' else '255,208,0' if overall=='MEDIUM' else '0,255,157'},.12);color:{'#ff2255' if overall=='CRITICAL' else '#ff7700' if overall=='HIGH' else '#ffd000' if overall=='MEDIUM' else '#00ff9d'};border-color:{'#ff2255' if overall=='CRITICAL' else '#ff7700' if overall=='HIGH' else '#ffd000' if overall=='MEDIUM' else '#00ff9d'}44">{overall} RISK</div>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-n" style="color:#ff2255">{sev_counts['CRITICAL']}</div><div class="stat-l">Critical</div></div>
    <div class="stat"><div class="stat-n" style="color:#ff7700">{sev_counts['HIGH']}</div><div class="stat-l">High</div></div>
    <div class="stat"><div class="stat-n" style="color:#ffd000">{sev_counts['MEDIUM']}</div><div class="stat-l">Medium</div></div>
    <div class="stat"><div class="stat-n" style="color:#00ff9d">{sev_counts['LOW']}</div><div class="stat-l">Low</div></div>
    <div class="stat"><div class="stat-n" style="color:#00aaff">{len(results['findings'])}</div><div class="stat-l">Total</div></div>
  </div>

  <div class="info-grid" style="margin-bottom:20px">
    <div class="info-card">
      <div class="info-card-title">IP &amp; Geo</div>
      <div class="info-row"><div class="info-key">IP</div><div class="info-val">{results.get('ip','N/A')}</div></div>
      <div class="info-row"><div class="info-key">Country</div><div class="info-val">{geo.get('country','N/A')} ({geo.get('countryCode','?')})</div></div>
      <div class="info-row"><div class="info-key">City</div><div class="info-val">{geo.get('city','N/A')}</div></div>
      <div class="info-row"><div class="info-key">ISP</div><div class="info-val">{geo.get('isp','N/A')}</div></div>
      <div class="info-row"><div class="info-key">ASN</div><div class="info-val">{geo.get('as','N/A')}</div></div>
      <div class="info-row"><div class="info-key">Timezone</div><div class="info-val">{geo.get('timezone','N/A')}</div></div>
    </div>
    <div class="info-card">
      <div class="info-card-title">Open Ports</div>
      {ports_html if ports_html else '<div style="padding:10px 12px;color:#1a3550">No open ports detected</div>'}
    </div>
  </div>

  <div class="section">
    <div class="sec-title">Vulnerability Findings ({len(results['findings'])})</div>
    {findings_html}
  </div>

  <div class="section">
    <div class="sec-title">Subdomains ({len(results.get('subdomains',[]))})</div>
    <div class="info-card">
      {subdomains_html}
    </div>
  </div>

  <footer>GHOST v{__version__} | Generated: {scan_time} | Educational Use Only </footer>
</div>
</body>
</html>"""

    fname = f"ghost_report_{target.replace('.','_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  {green('✓')} Report saved: {bold(fname)}")
    return fname

def is_ip(addr):
    try:
        socket.inet_aton(addr)
        return True
    except:
        return False

def main():
    global os 
    import argparse

    parser = argparse.ArgumentParser(description="GHOST - Vulnerability Scanner & OSINT Tool")
    parser.add_argument('target', nargs='?', help='Domain or IP to scan')
    parser.add_argument('--version', '-v', action='store_true', help='Show version info')
    args = parser.parse_args()


    if args.version:
        banner()

        # Cross-Platform Detection
        if os.name == 'nt':
            platform_text = f"{yellow('Windows')} - Cross-Platform Support"
        else:
            platform_text = f"{cyan('Linux/macOS')} - Cross-Platform Support"

        print(f" {bold('GHOST Scanner')} {cyan(f'v{__version__}')} - Initial Release")
        print(f" {dim('Features:')} IP+Geo, WHOIS, Subdomains, Port Scan, SSL/TLS, Headers, DNS Security, Wayback, File Exposure, HTML Report")
        print(f" {dim('Python:')} {sys.version.split()[0]}")
        print(f" {dim('Platform:')} {platform_text}")
        print(f" {dim('Developer:')} {bold('Gireesh G')}")
        print(f" {dim('GitHub:')} https://github.com/gireeshsec/ghost-scanner")
        print(f" {dim('License:')} MIT - Educational Use Only\n")
        sys.exit(0)

    if not args.target:
        banner()
        print(f"{BOLD} Usage: python3 ghost.py <domain.com>")
        print(f"{BOLD} Example: {cyan('python3 ghost.py example.com')}")
        print(f"{BOLD} Example: {cyan('python3 ghost.py 8.8.8.8')}\n")
        sys.exit(1)

    target = args.target.strip().replace("https://","").replace("http://","").split("/")[0]

    if target.startswith('-') or ('.' not in target and not is_ip(target)):
        print(red(f"Error: '{target}' is not a valid domain name or IP address"))
        print(f"Usage: {bold('python3 ghost.py <domain.com>')}")
        sys.exit(1)

    results["target"] = target
    banner()
    print(f" {bold('Target:')} {cyan(target)}")
    print(f" {bold('Started:')} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" {dim('⚠ For authorized security testing only')}\n")

    start = time.time()
    run_geo(target)
    run_whois(target)
    run_subdomains(target)
    run_ports(target)
    run_ssl(target)
    run_headers(target)
    run_dns(target)
    run_wayback(target)
    run_content(target)
    print_summary()
    report_file = generate_report(target)
    print(f"\n {green('✓')} Scan complete in {time.time()-start:.1f}s") 
    print(f" {green('✓')} Report: {bold(report_file)}")

    try:
        import webbrowser, os
        file_path = os.path.abspath(report_file)
        webbrowser.open(f'file://{file_path}')
        print(f" {green('✓')} Opening report in browser...")
    except:
        print(f" {yellow('!')} Open manually: firefox {report_file}")
    print(f"\n {dim('Open the HTML report in browser for full details')}\n")


if __name__ == "__main__":
    main()

