import asyncio
import socket
import ssl
import httpx
import dns.resolver
from urllib.parse import urlparse

COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 143, 443,
    8080, 8443
]

RISKY_PORTS = [21, 22, 25, 3306, 5432, 6379, 27017]

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

COMMON_SUBDOMAINS = [
    "www", "api", "admin", "dev", "staging", "test",
    "mail", "portal", "app", "dashboard", "cdn", "blog"
]

SECURITY_HEADERS = {
    "Content-Security-Policy": {"severity": "MEDIUM", "fix": "Add a strong Content-Security-Policy header."},
    "X-Frame-Options": {"severity": "MEDIUM", "fix": "Add X-Frame-Options: DENY or SAMEORIGIN."},
    "X-Content-Type-Options": {"severity": "LOW", "fix": "Add X-Content-Type-Options: nosniff."},
    "Strict-Transport-Security": {"severity": "MEDIUM", "fix": "Add Strict-Transport-Security header."},
    "Referrer-Policy": {"severity": "LOW", "fix": "Add Referrer-Policy header."},
    "Permissions-Policy": {"severity": "LOW", "fix": "Add Permissions-Policy header."}
}

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/backup.zip", "/database.sql",
    "/phpinfo.php", "/admin", "/login", "/wp-admin"
]

SENSITIVE_ROBOTS_KEYWORDS = [
    "admin", "backup", "private", "secret", "config", "database", "login"
]

NIKTO_PATHS = [
    {
        "path": "/phpmyadmin/",
        "name": "phpMyAdmin Exposed",
        "severity": "HIGH",
        "keywords": ["phpmyadmin", "pma_username"],
        "fix": "Restrict phpMyAdmin access by IP, VPN, or remove it from public internet."
    },
    {
        "path": "/wp-login.php",
        "name": "WordPress Login Exposed",
        "severity": "MEDIUM",
        "keywords": ["wordpress", "wp-submit", "wp-login"],
        "fix": "Protect WordPress login with rate limiting, MFA, and WAF rules."
    },
    {
        "path": "/wp-admin/",
        "name": "WordPress Admin Exposed",
        "severity": "MEDIUM",
        "keywords": ["wordpress", "wp-admin", "login"],
        "fix": "Restrict admin access and enable strong authentication."
    },
    {
        "path": "/server-status",
        "name": "Apache Server Status Exposed",
        "severity": "HIGH",
        "keywords": ["apache server status", "server uptime", "total accesses"],
        "fix": "Disable server-status or restrict it to localhost/admin IPs."
    },
    {
        "path": "/.env",
        "name": ".env File Exposed",
        "severity": "HIGH",
        "keywords": ["app_key", "db_password", "secret", "password", "database_url"],
        "fix": "Remove .env from public web root immediately."
    },
    {
        "path": "/.git/config",
        "name": "Git Config Exposed",
        "severity": "HIGH",
        "keywords": ["[core]", "repositoryformatversion"],
        "fix": "Block access to .git directory and remove it from public web root."
    },
    {
        "path": "/backup.zip",
        "name": "Backup File Exposed",
        "severity": "HIGH",
        "keywords": [],
        "fix": "Remove public backup files from the server."
    },
    {
        "path": "/backup.sql",
        "name": "Database Backup Exposed",
        "severity": "HIGH",
        "keywords": [],
        "fix": "Remove public database backups from the server."
    },
    {
        "path": "/database.sql",
        "name": "Database Dump Exposed",
        "severity": "HIGH",
        "keywords": [],
        "fix": "Remove public SQL dumps from the server."
    },
    {
        "path": "/debug",
        "name": "Debug Page Exposed",
        "severity": "MEDIUM",
        "keywords": ["debug", "traceback", "exception", "stack trace"],
        "fix": "Disable debug mode in production."
    },
    {
        "path": "/phpinfo.php",
        "name": "PHP Info Page Exposed",
        "severity": "HIGH",
        "keywords": ["php version", "phpinfo"],
        "fix": "Remove phpinfo.php from production."
    },
    {
        "path": "/config.php",
        "name": "Config File Exposed",
        "severity": "HIGH",
        "keywords": ["db_password", "database", "password", "secret"],
        "fix": "Move configuration files outside the web root."
    },
    {
        "path": "/admin/",
        "name": "Admin Panel Exposed",
        "severity": "MEDIUM",
        "keywords": ["admin", "login", "password"],
        "fix": "Protect admin panels with authentication, MFA, and IP restrictions."
    }
]


def add_finding(findings, title, severity, description, fix):
    findings.append({
        "title": title,
        "severity": severity,
        "description": description,
        "fix": fix
    })


def add_vuln(vulns, name, severity, evidence, impact, fix):
    vulns.append({
        "name": name,
        "severity": severity,
        "evidence": evidence,
        "impact": impact,
        "fix": fix
    })


def normalize_target(target):
    if not target.startswith("http://") and not target.startswith("https://"):
        return "https://" + target
    return target


def get_hostname(target):
    return urlparse(normalize_target(target)).hostname


async def safe_get(client, url):
    try:
        return await client.get(url)
    except:
        return None


async def safe_options(client, url):
    try:
        return await client.options(url)
    except:
        return None


async def check_port(host, port):
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=1.5)

        banner = None

        try:
            data = await asyncio.wait_for(reader.read(128), timeout=1)
            if data:
                banner = data.decode(errors="ignore").strip()
        except:
            banner = None

        writer.close()
        await writer.wait_closed()

        return {
            "port": port,
            "service": PORT_SERVICES.get(port, "Unknown"),
            "banner": banner[:120] if banner else None,
            "risk": "RISKY" if port in RISKY_PORTS else "NORMAL"
        }

    except:
        return None


async def check_ssl(host):
    def ssl_job():
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    return True, cert.get("notAfter"), ssock.version()
        except Exception as e:
            return False, str(e), None

    return await asyncio.to_thread(ssl_job)


async def check_dns_security(host):
    result = {
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "spf": False,
        "dmarc": False,
        "issues": []
    }

    def dns_job():
        try:
            try:
                result["a_records"] = [r.to_text() for r in dns.resolver.resolve(host, "A")]
            except:
                result["issues"].append("No A record found")

            try:
                result["mx_records"] = [r.to_text() for r in dns.resolver.resolve(host, "MX")]
            except:
                result["issues"].append("No MX record found")

            try:
                result["ns_records"] = [r.to_text() for r in dns.resolver.resolve(host, "NS")]
            except:
                result["issues"].append("No NS record found")

            try:
                txts = [r.to_text() for r in dns.resolver.resolve(host, "TXT")]
                result["txt_records"] = txts

                for txt in txts:
                    if "v=spf1" in txt.lower():
                        result["spf"] = True

                if not result["spf"]:
                    result["issues"].append("SPF record not found")
            except:
                result["issues"].append("No TXT record found")

            try:
                dmarc_host = "_dmarc." + host
                dmarc_txts = [r.to_text() for r in dns.resolver.resolve(dmarc_host, "TXT")]

                for txt in dmarc_txts:
                    if "v=dmarc1" in txt.lower():
                        result["dmarc"] = True

                if not result["dmarc"]:
                    result["issues"].append("DMARC record not found")
            except:
                result["issues"].append("DMARC record not found")

        except Exception as e:
            result["issues"].append(str(e))

        return result

    return await asyncio.to_thread(dns_job)


async def resolve_subdomain(subdomain):
    def dns_job():
        try:
            return [r.to_text() for r in dns.resolver.resolve(subdomain, "A")]
        except:
            return []

    return await asyncio.to_thread(dns_job)


async def check_subdomain_http(client, subdomain):
    result = {
        "subdomain": subdomain,
        "ips": [],
        "http": False,
        "https": False,
        "status_code": None,
        "final_url": None
    }

    ips = await resolve_subdomain(subdomain)

    if not ips:
        return None

    result["ips"] = ips

    https_res = await safe_get(client, "https://" + subdomain)
    if https_res:
        result["https"] = True
        result["status_code"] = https_res.status_code
        result["final_url"] = str(https_res.url)
        return result

    http_res = await safe_get(client, "http://" + subdomain)
    if http_res:
        result["http"] = True
        result["status_code"] = http_res.status_code
        result["final_url"] = str(http_res.url)

    return result


async def check_subdomains(client, host):
    found = []
    base_domain = host.replace("www.", "", 1) if host.startswith("www.") else host

    tasks = [
        check_subdomain_http(client, f"{name}.{base_domain}")
        for name in COMMON_SUBDOMAINS
    ]

    results = await asyncio.gather(*tasks)

    for item in results:
        if item:
            found.append(item)

    return found


def detect_technologies(response):
    tech = []

    if not response:
        return tech

    headers = response.headers
    html = response.text.lower()

    server = headers.get("Server", "").lower()
    powered = headers.get("X-Powered-By", "").lower()

    if "cloudflare" in server:
        tech.append("Cloudflare")
    if "nginx" in server:
        tech.append("Nginx")
    if "apache" in server:
        tech.append("Apache")
    if "gws" in server:
        tech.append("Google Web Server")
    if "express" in powered:
        tech.append("Express.js")
    if "php" in powered:
        tech.append("PHP")
    if "asp.net" in powered:
        tech.append("ASP.NET")
    if "wordpress" in html or "wp-content" in html:
        tech.append("WordPress")
    if "_next" in html:
        tech.append("Next.js")
    if "react" in html:
        tech.append("React")
    if "vue" in html:
        tech.append("Vue.js")

    return list(set(tech))


def detect_waf(response):
    if not response:
        return "Unknown"

    headers = response.headers
    server = headers.get("Server", "").lower()

    if "cloudflare" in server or headers.get("CF-Ray"):
        return "Cloudflare"
    if headers.get("Akamai-Request-ID"):
        return "Akamai"
    if headers.get("X-Sucuri-ID"):
        return "Sucuri"
    if "x-waf" in str(headers).lower():
        return "Possible WAF"

    return "Not detected"


def check_cors(response):
    issues = []

    if not response:
        return issues

    origin = response.headers.get("Access-Control-Allow-Origin")
    credentials = response.headers.get("Access-Control-Allow-Credentials")

    if origin == "*":
        issues.append("CORS allows all origins (*)")

    if origin == "*" and credentials and credentials.lower() == "true":
        issues.append("Dangerous CORS configuration: wildcard origin with credentials")

    return issues


def check_http_methods(options_response):
    if not options_response:
        return []

    allow = (
        options_response.headers.get("Allow")
        or options_response.headers.get("Access-Control-Allow-Methods")
    )

    if not allow:
        return []

    return [m.strip() for m in allow.split(",")]


async def check_sensitive_path(client, base_url, path):
    url = base_url.rstrip("/") + path
    res = await safe_get(client, url)

    if not res or res.status_code != 200:
        return None

    text = res.text.lower()

    if path == "/.env" and ("password" in text or "secret" in text or "db_" in text):
        return path

    if path == "/.git/config" and "[core]" in text:
        return path

    if path in ["/backup.zip", "/database.sql"]:
        return path

    if path == "/phpinfo.php" and "php version" in text:
        return path

    if path in ["/admin", "/login", "/wp-admin"]:
        return path

    return None


async def check_nikto_paths(client, base_url):
    results = []
    tasks = []

    for item in NIKTO_PATHS:
        url = base_url.rstrip("/") + item["path"]
        tasks.append((item, safe_get(client, url)))

    responses = await asyncio.gather(*[task for _, task in tasks])

    for (item, _), res in zip(tasks, responses):
        if not res:
            continue

        text = res.text.lower()
        detected = False

        if res.status_code == 200:
            if item["keywords"]:
                for keyword in item["keywords"]:
                    if keyword.lower() in text:
                        detected = True
                        break
            else:
                detected = True

        if detected:
            results.append({
                "name": item["name"],
                "severity": item["severity"],
                "path": item["path"],
                "status": res.status_code,
                "url": str(res.url),
                "evidence": f"Matched {item['path']} with HTTP {res.status_code}",
                "fix": item["fix"]
            })

    return results


async def check_robots_txt(client, base_url):
    result = {
        "exists": False,
        "url": base_url.rstrip("/") + "/robots.txt",
        "suspicious_entries": [],
        "summary": "robots.txt not found"
    }

    res = await safe_get(client, result["url"])

    if not res or res.status_code != 200:
        return result

    result["exists"] = True
    text = res.text.lower()

    for line in text.splitlines():
        line_clean = line.strip()
        if line_clean.startswith("disallow:"):
            for keyword in SENSITIVE_ROBOTS_KEYWORDS:
                if keyword in line_clean:
                    result["suspicious_entries"].append(line_clean)

    if result["suspicious_entries"]:
        result["summary"] = "robots.txt contains potentially sensitive disallow entries"
    else:
        result["summary"] = "robots.txt found with no obvious sensitive entries"

    return result


async def check_security_txt(client, base_url):
    result = {
        "exists": False,
        "url": None,
        "contacts": [],
        "policy": None,
        "summary": "security.txt not found"
    }

    for path in ["/.well-known/security.txt", "/security.txt"]:
        url = base_url.rstrip("/") + path
        res = await safe_get(client, url)

        if not res or res.status_code != 200:
            continue

        result["exists"] = True
        result["url"] = url

        for line in res.text.splitlines():
            clean = line.strip()

            if clean.lower().startswith("contact:"):
                result["contacts"].append(clean)

            if clean.lower().startswith("policy:"):
                result["policy"] = clean

        result["summary"] = "security.txt found"
        return result

    return result


async def fetch_cves_for_keyword(client, keyword):
    cves = []

    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 3
        }

        res = await client.get(url, params=params, timeout=8)

        if res.status_code != 200:
            return cves

        data = res.json()

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            published = cve.get("published")
            descriptions = cve.get("descriptions", [])

            description = "No description"
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value")
                    break

            metrics = cve.get("metrics", {})
            severity = "UNKNOWN"
            cvss_score = None

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                cvss_score = cvss.get("baseScore")

            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                cvss_score = cvss.get("baseScore")

            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
                cvss_score = cvss.get("baseScore")

            cves.append({
                "id": cve_id,
                "published": published,
                "severity": severity,
                "score": cvss_score,
                "description": description[:300] + "..." if len(description) > 300 else description,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })

    except:
        return cves

    return cves


async def check_cves(client, technologies):
    results = []

    if not technologies:
        return results

    keywords = []

    for tech in technologies:
        t = tech.lower()

        if "apache" in t:
            keywords.append("Apache HTTP Server")
        elif "nginx" in t:
            keywords.append("nginx")
        elif "wordpress" in t:
            keywords.append("WordPress")
        elif "php" in t:
            keywords.append("PHP")
        elif "express" in t:
            keywords.append("Express.js")
        elif "asp.net" in t:
            keywords.append("ASP.NET")
        elif "google web server" in t:
            continue
        else:
            keywords.append(tech)

    keywords = list(set(keywords))[:3]

    if not keywords:
        return results

    tasks = [fetch_cves_for_keyword(client, keyword) for keyword in keywords]
    responses = await asyncio.gather(*tasks)

    for keyword, cves in zip(keywords, responses):
        results.append({
            "technology": keyword,
            "cves": cves
        })

    return results


async def analyze(target, profile="full"):
    profile = profile.lower()

    if profile not in ["quick", "full", "deep"]:
        profile = "full"

    enable_subdomains = profile in ["full", "deep"]
    enable_nikto = profile in ["full", "deep"]
    enable_cve = profile in ["full", "deep"]

    url = normalize_target(target)
    host = get_hostname(target)

    score = 0
    alerts = []
    vulnerabilities = []
    vulnerability_checks = []
    findings = []
    found_headers = []
    missing_headers = []

    if not host:
        return {
            "risk": "HIGH",
            "score": 100,
            "profile": profile,
            "alerts": ["Invalid target"],
            "vulnerabilities": ["Invalid target format"],
            "vulnerability_checks": [],
            "findings": []
        }

    try:
        ip = socket.gethostbyname(host)
    except:
        return {
            "risk": "HIGH",
            "score": 90,
            "profile": profile,
            "alerts": ["DNS resolution failed"],
            "vulnerabilities": ["Domain does not resolve"],
            "vulnerability_checks": [{
                "name": "DNS Resolution Failed",
                "severity": "HIGH",
                "evidence": host,
                "impact": "The domain cannot be reached.",
                "fix": "Check DNS configuration and domain validity."
            }],
            "findings": [{
                "title": "DNS Resolution Failed",
                "severity": "HIGH",
                "description": "The domain could not be resolved to an IP address.",
                "fix": "Check that the domain is valid and DNS records are configured correctly."
            }]
        }

    async with httpx.AsyncClient(
        timeout=5,
        follow_redirects=True,
        headers={"User-Agent": "ThreatScanner-Profile/2.5"}
    ) as client:

        response_task = safe_get(client, url)
        options_task = safe_options(client, url)
        ssl_task = check_ssl(host)
        dns_task = check_dns_security(host)
        robots_task = check_robots_txt(client, url)
        security_txt_task = check_security_txt(client, url)
        subdomains_task = (
            check_subdomains(client, host)
            if enable_subdomains
            else asyncio.sleep(0, result=[])
        )

        nikto_task = (
            check_nikto_paths(client, url)
            if enable_nikto
            else asyncio.sleep(0, result=[])
        )

        ports_task = asyncio.gather(*[
            check_port(host, port)
            for port in COMMON_PORTS + RISKY_PORTS
        ])

        sensitive_task = asyncio.gather(*[
            check_sensitive_path(client, url, path)
            for path in SENSITIVE_PATHS
        ])

        (
            response,
            options_response,
            ssl_result,
            dns_security,
            robots_txt,
            security_txt,
            subdomains,
            nikto_checks,
            ports_result,
            sensitive_result
        ) = await asyncio.gather(
            response_task,
            options_task,
            ssl_task,
            dns_task,
            robots_task,
            security_txt_task,
            subdomains_task,
            nikto_task,
            ports_task,
            sensitive_task
        )

        ssl_ok, ssl_info, tls_version = ssl_result
        open_ports = [p for p in ports_result if p]
        exposed_paths = [p for p in sensitive_result if p]

        technologies = detect_technologies(response)
        waf = detect_waf(response)
        cors_issues = check_cors(response)
        http_methods = check_http_methods(options_response)
        cve_results = (
            await check_cves(client, technologies)
            if enable_cve
            else []
        )

    if not response:
        score += 25
        alerts.append("Website is not reachable")
        vulnerabilities.append("Website is not reachable")

        add_vuln(
            vulnerability_checks,
            "Website Not Reachable",
            "MEDIUM",
            url,
            "Scanner could not connect to the website.",
            "Check server, DNS, firewall, and hosting status."
        )

        add_finding(
            findings,
            "Website Not Reachable",
            "MEDIUM",
            "The scanner could not connect to the website.",
            "Check server availability, firewall rules, DNS, and hosting status."
        )

    else:
        if response.url.scheme == "http":
            score += 25
            vulnerabilities.append("Website uses HTTP instead of HTTPS")

            add_vuln(
                vulnerability_checks,
                "HTTP Without HTTPS",
                "MEDIUM",
                str(response.url),
                "Traffic may be intercepted or modified.",
                "Force HTTPS redirection and enable HSTS."
            )

            add_finding(
                findings,
                "HTTP Used Instead of HTTPS",
                "MEDIUM",
                "The website is accessible over insecure HTTP.",
                "Redirect all HTTP traffic to HTTPS and enable a valid SSL certificate."
            )

        if response.status_code >= 500:
            score += 20
            alerts.append(f"Server error detected: {response.status_code}")

            add_vuln(
                vulnerability_checks,
                "Server Error",
                "MEDIUM",
                f"HTTP {response.status_code}",
                "Server-side errors may reveal instability or misconfiguration.",
                "Review backend logs and server configuration."
            )

        elif response.status_code >= 400:
            score += 10
            alerts.append(f"Client error detected: {response.status_code}")

            add_vuln(
                vulnerability_checks,
                "Client Error",
                "LOW",
                f"HTTP {response.status_code}",
                "The requested page returns an error.",
                "Review URL routing and access controls."
            )

        for header, info in SECURITY_HEADERS.items():
            if header in response.headers:
                found_headers.append(header)
            else:
                missing_headers.append(header)
                score += 6
                vulnerabilities.append(f"Missing security header: {header}")

                severity = info["severity"]

                add_vuln(
                    vulnerability_checks,
                    f"Missing Security Header: {header}",
                    severity,
                    f"{header} not present",
                    "Missing browser security controls may increase attack surface.",
                    info["fix"]
                )

                add_finding(
                    findings,
                    f"Missing Security Header: {header}",
                    severity,
                    f"The response does not include the {header} security header.",
                    info["fix"]
                )

        server = response.headers.get("Server")
        powered = response.headers.get("X-Powered-By")

        if server:
            score += 5
            vulnerabilities.append(f"Server header exposed: {server}")

            add_vuln(
                vulnerability_checks,
                "Server Header Disclosure",
                "LOW",
                f"Server: {server}",
                "Attackers may identify server technology.",
                "Hide or reduce server version information."
            )

            add_finding(
                findings,
                "Server Header Exposed",
                "LOW",
                f"The server reveals technology information: {server}.",
                "Hide or minimize server version headers to reduce information disclosure."
            )

        if powered:
            score += 5
            vulnerabilities.append(f"Technology header exposed: {powered}")

            add_vuln(
                vulnerability_checks,
                "Technology Disclosure",
                "LOW",
                f"X-Powered-By: {powered}",
                "Application technology is exposed.",
                "Remove X-Powered-By header."
            )

            add_finding(
                findings,
                "Technology Header Exposed",
                "LOW",
                f"The application reveals technology information: {powered}.",
                "Remove X-Powered-By headers from the web server or framework."
            )

        cookies = response.headers.get("Set-Cookie", "")

        if cookies:
            if "HttpOnly" not in cookies:
                score += 8
                vulnerabilities.append("Cookie missing HttpOnly flag")

                add_vuln(
                    vulnerability_checks,
                    "Cookie Missing HttpOnly",
                    "MEDIUM",
                    cookies,
                    "JavaScript may access sensitive cookies.",
                    "Set HttpOnly flag on sensitive cookies."
                )

            if "Secure" not in cookies:
                score += 8
                vulnerabilities.append("Cookie missing Secure flag")

                add_vuln(
                    vulnerability_checks,
                    "Cookie Missing Secure",
                    "MEDIUM",
                    cookies,
                    "Cookies may be sent over insecure connections.",
                    "Set Secure flag on cookies."
                )

            if "SameSite" not in cookies:
                score += 6
                vulnerabilities.append("Cookie missing SameSite flag")

                add_vuln(
                    vulnerability_checks,
                    "Cookie Missing SameSite",
                    "LOW",
                    cookies,
                    "May increase CSRF risk.",
                    "Set SameSite=Lax or SameSite=Strict."
                )

        for issue in cors_issues:
            score += 12
            vulnerabilities.append(issue)

            add_vuln(
                vulnerability_checks,
                "CORS Misconfiguration",
                "MEDIUM",
                issue,
                "Overly permissive CORS may allow untrusted origins.",
                "Restrict CORS to trusted domains only."
            )

            add_finding(
                findings,
                "CORS Misconfiguration",
                "MEDIUM",
                issue,
                "Restrict Access-Control-Allow-Origin to trusted domains only."
            )

        dangerous_methods = [
            m for m in http_methods
            if m.upper() in ["PUT", "DELETE", "TRACE", "CONNECT"]
        ]

        if dangerous_methods:
            score += len(dangerous_methods) * 10
            methods_text = ", ".join(dangerous_methods)
            vulnerabilities.append(f"Potentially dangerous HTTP methods enabled: {methods_text}")

            for method in dangerous_methods:
                add_vuln(
                    vulnerability_checks,
                    "Dangerous HTTP Method Enabled",
                    "MEDIUM",
                    method,
                    "Unsafe HTTP methods may allow unintended actions.",
                    "Disable unused HTTP methods such as PUT, DELETE, TRACE, CONNECT."
                )

            add_finding(
                findings,
                "Dangerous HTTP Methods",
                "MEDIUM",
                "Some HTTP methods may allow unsafe operations if not protected.",
                "Disable unused HTTP methods at the web server or application layer."
            )

        page_text = response.text.lower()

        if "index of /" in page_text or "directory listing" in page_text:
            score += 30
            vulnerabilities.append("Directory listing appears to be enabled")

            add_vuln(
                vulnerability_checks,
                "Directory Listing Enabled",
                "HIGH",
                "Page contains directory listing indicators.",
                "Files and folders may be publicly exposed.",
                "Disable directory listing on the web server."
            )

            add_finding(
                findings,
                "Directory Listing Enabled",
                "HIGH",
                "The website appears to expose directory listings.",
                "Disable directory listing in the web server configuration."
            )

    if not ssl_ok:
        score += 25
        vulnerabilities.append("SSL certificate problem or HTTPS unavailable")

        add_vuln(
            vulnerability_checks,
            "SSL/TLS Problem",
            "MEDIUM",
            str(ssl_info),
            "Users may be exposed to insecure or broken HTTPS.",
            "Install a valid TLS certificate and ensure HTTPS is correctly configured."
        )

        add_finding(
            findings,
            "SSL Problem",
            "MEDIUM",
            "The website has an SSL/TLS issue or HTTPS is not available.",
            "Install a valid TLS certificate and ensure HTTPS is correctly configured."
        )

    for issue in dns_security["issues"]:
        if "SPF" in issue or "DMARC" in issue:
            score += 8
            vulnerabilities.append(issue)

            add_vuln(
                vulnerability_checks,
                "DNS Email Security Issue",
                "LOW",
                issue,
                "Missing email security records may increase spoofing risk.",
                "Configure SPF and DMARC records."
            )

            add_finding(
                findings,
                "DNS Email Security Issue",
                "LOW",
                issue,
                "Configure SPF and DMARC records to reduce email spoofing risk."
            )

    if robots_txt["suspicious_entries"]:
        score += 10
        vulnerabilities.append("robots.txt contains potentially sensitive entries")

        add_vuln(
            vulnerability_checks,
            "Suspicious robots.txt Entries",
            "LOW",
            ", ".join(robots_txt["suspicious_entries"]),
            "robots.txt may reveal sensitive paths.",
            "Avoid exposing sensitive path names and protect routes with authentication."
        )

        add_finding(
            findings,
            "Suspicious robots.txt Entries",
            "LOW",
            "robots.txt contains paths that may reveal sensitive areas.",
            "Avoid exposing sensitive path names in robots.txt and protect sensitive routes."
        )

    if not security_txt["exists"]:
        add_finding(
            findings,
            "security.txt Not Found",
            "INFO",
            "The website does not expose a security.txt file.",
            "Add /.well-known/security.txt with a security contact and disclosure policy."
        )

    for path in exposed_paths:
        score += 20
        vulnerabilities.append(f"Sensitive path exposed: {path}")

        add_vuln(
            vulnerability_checks,
            "Sensitive Path Exposed",
            "HIGH",
            path,
            "Sensitive files or admin paths may be publicly accessible.",
            "Remove exposed files or restrict access with authentication."
        )

    for item in nikto_checks:
        severity = item["severity"]

        if severity == "HIGH":
            score += 20
        elif severity == "MEDIUM":
            score += 10
        elif severity == "LOW":
            score += 5

        vulnerabilities.append(item["name"])

        add_vuln(
            vulnerability_checks,
            item["name"],
            item["severity"],
            item["evidence"],
            f"Potential exposure detected at {item['path']}",
            item["fix"]
        )

        add_finding(
            findings,
            item["name"],
            item["severity"],
            item["evidence"],
            item["fix"]
        )

    risky_open = [
        p for p in open_ports
        if p.get("port") in RISKY_PORTS
    ]

    if risky_open:
        score += len(risky_open) * 12
        ports_text = ", ".join([
            f"{p['port']} ({p['service']})"
            for p in risky_open
        ])
        vulnerabilities.append(f"Risky open ports detected: {ports_text}")

        add_vuln(
            vulnerability_checks,
            "Risky Open Ports",
            "MEDIUM",
            ports_text,
            "Potentially risky service ports are reachable from the internet.",
            "Close unused ports or restrict them with firewall rules."
        )

        add_finding(
            findings,
            "Risky Open Ports",
            "MEDIUM",
            "Potentially risky service ports are reachable from the internet.",
            "Close unused ports or restrict them with firewall rules and IP allowlists."
        )

    if subdomains:
        add_finding(
            findings,
            "Subdomains Discovered",
            "INFO",
            f"{len(subdomains)} common subdomains were discovered.",
            "Review discovered subdomains and ensure unused environments are removed or protected."
        )

    for item in cve_results:
        for cve in item.get("cves", []):
            severity = cve.get("severity", "UNKNOWN")

            if severity == "CRITICAL":
                score += 20
            elif severity == "HIGH":
                score += 15
            elif severity == "MEDIUM":
                score += 8
            elif severity == "LOW":
                score += 3

            add_vuln(
                vulnerability_checks,
                f"Possible CVE Match: {cve.get('id')}",
                severity,
                f"Technology: {item.get('technology')}",
                cve.get("description", "No description"),
                f"Review {cve.get('url')} and update or patch if applicable."
            )

            add_finding(
                findings,
                f"Possible CVE Match: {cve.get('id')}",
                severity,
                f"Technology: {item.get('technology')} | {cve.get('description')}",
                f"Review: {cve.get('url')} and update/patch the affected technology if applicable."
            )

    score = min(score, 100)

    if score >= 70:
        risk = "HIGH"
    elif score >= 35:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    alerts.extend(vulnerabilities)

    return {
        "target": target,
        "host": host,
        "ip": ip,
        "profile": profile,
        "risk": risk,
        "score": score,
        "status_code": response.status_code if response else None,
        "final_url": str(response.url) if response else None,
        "ssl": {
            "valid": ssl_ok,
            "info": ssl_info,
            "tls_version": tls_version
        },
        "dns_security": dns_security,
        "robots_txt": robots_txt,
        "security_txt": security_txt,
        "subdomains": subdomains,
        "nikto_checks": nikto_checks,
        "security_headers": {
            "found": found_headers,
            "missing": missing_headers
        },
        "open_ports": open_ports,
        "technologies": technologies,
        "cve_results": cve_results,
        "waf": waf,
        "http_methods": http_methods,
        "vulnerabilities": vulnerabilities,
        "vulnerability_checks": vulnerability_checks,
        "findings": findings,
        "alerts": alerts
    }