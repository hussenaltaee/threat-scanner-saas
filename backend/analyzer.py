import asyncio
import socket
import ssl
import httpx
import dns.resolver
import re
from urllib.parse import urlparse, urljoin


COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 8080, 8443]
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
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "fix": "Add a strong Content-Security-Policy header."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "fix": "Add X-Frame-Options: DENY or SAMEORIGIN."
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "fix": "Add X-Content-Type-Options: nosniff."
    },
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "fix": "Add Strict-Transport-Security header."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "fix": "Add Referrer-Policy header."
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "fix": "Add Permissions-Policy header."
    }
}

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/database.sql",
    "/phpinfo.php",
    "/admin",
    "/login",
    "/wp-admin"
]

SENSITIVE_ROBOTS_KEYWORDS = [
    "admin",
    "backup",
    "private",
    "secret",
    "config",
    "database",
    "login"
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


def add_finding(findings, title, severity, description, fix, category="General", evidence=None):
    findings.append({
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "evidence": evidence,
        "fix": fix
    })


def add_vuln(vulns, name, severity, evidence, impact, fix, category="General"):
    vulns.append({
        "name": name,
        "severity": severity,
        "category": category,
        "evidence": evidence,
        "impact": impact,
        "fix": fix
    })


def normalize_target(target):
    target = target.strip()

    if not target.startswith("http://") and not target.startswith("https://"):
        return "https://" + target

    return target


def get_hostname(target):
    return urlparse(normalize_target(target)).hostname


def severity_points(severity):
    return {
        "CRITICAL": 25,
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 5,
        "INFO": 0,
        "UNKNOWN": 3
    }.get(str(severity).upper(), 3)


def dedupe_list(items):
    seen = set()
    output = []

    for item in items:
        key = str(item)

        if key not in seen:
            seen.add(key)
            output.append(item)

    return output


def dedupe_dicts(items, key_fields):
    seen = set()
    output = []

    for item in items:
        key = tuple(item.get(k) for k in key_fields)

        if key not in seen:
            seen.add(key)
            output.append(item)

    return output


async def safe_get(client, url):
    try:
        return await client.get(url)
    except Exception:
        return None


async def safe_options(client, url):
    try:
        return await client.options(url)
    except Exception:
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

        except Exception:
            banner = None

        writer.close()
        await writer.wait_closed()

        return {
            "port": port,
            "service": PORT_SERVICES.get(port, "Unknown"),
            "banner": banner[:120] if banner else None,
            "risk": "RISKY" if port in RISKY_PORTS else "NORMAL"
        }

    except Exception:
        return None


async def check_ssl(host):
    def ssl_job():
        try:
            context = ssl.create_default_context()

            with socket.create_connection((host, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))

                    return {
                        "valid": True,
                        "expires": cert.get("notAfter"),
                        "tls_version": ssock.version(),
                        "cipher_name": cipher[0] if cipher else None,
                        "cipher_protocol": cipher[1] if cipher else None,
                        "cipher_bits": cipher[2] if cipher else None,
                        "subject": subject,
                        "issuer": issuer
                    }

        except Exception as e:
            return {
                "valid": False,
                "expires": str(e),
                "tls_version": None,
                "cipher_name": None,
                "cipher_protocol": None,
                "cipher_bits": None,
                "subject": {},
                "issuer": {}
            }

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
                result["a_records"] = [
                    r.to_text() for r in dns.resolver.resolve(host, "A")
                ]
            except Exception:
                result["issues"].append("No A record found")

            try:
                result["mx_records"] = [
                    r.to_text() for r in dns.resolver.resolve(host, "MX")
                ]
            except Exception:
                result["issues"].append("No MX record found")

            try:
                result["ns_records"] = [
                    r.to_text() for r in dns.resolver.resolve(host, "NS")
                ]
            except Exception:
                result["issues"].append("No NS record found")

            try:
                txts = [
                    r.to_text() for r in dns.resolver.resolve(host, "TXT")
                ]

                result["txt_records"] = txts

                for txt in txts:
                    if "v=spf1" in txt.lower():
                        result["spf"] = True

                if not result["spf"]:
                    result["issues"].append("SPF record not found")

            except Exception:
                result["issues"].append("No TXT record found")

            try:
                dmarc_host = "_dmarc." + host

                dmarc_txts = [
                    r.to_text() for r in dns.resolver.resolve(dmarc_host, "TXT")
                ]

                for txt in dmarc_txts:
                    if "v=dmarc1" in txt.lower():
                        result["dmarc"] = True

                if not result["dmarc"]:
                    result["issues"].append("DMARC record not found")

            except Exception:
                result["issues"].append("DMARC record not found")

        except Exception as e:
            result["issues"].append(str(e))

        result["issues"] = dedupe_list(result["issues"])

        return result

    return await asyncio.to_thread(dns_job)


async def resolve_subdomain(subdomain):
    def dns_job():
        try:
            return [
                r.to_text() for r in dns.resolver.resolve(subdomain, "A")
            ]
        except Exception:
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
        return {
            "name": "Unknown",
            "confidence": "0%",
            "evidence": []
        }

    headers = response.headers
    text_headers = str(headers).lower()
    server = headers.get("Server", "").lower()
    powered = headers.get("X-Powered-By", "").lower()

    combined = f"{text_headers} {server} {powered}".lower()

    waf_db = [
        {
            "name": "Cloudflare",
            "signatures": [
                "cf-ray",
                "cloudflare",
                "__cf_bm",
                "cf-cache-status",
                "cf-request-id"
            ]
        },
        {
            "name": "Akamai",
            "signatures": [
                "akamai",
                "akamaighost",
                "x-akamai",
                "akamai-request-id"
            ]
        },
        {
            "name": "AWS WAF",
            "signatures": [
                "awselb",
                "x-amzn",
                "x-amz-cf",
                "aws-waf",
                "aws"
            ]
        },
        {
            "name": "Imperva / Incapsula",
            "signatures": [
                "imperva",
                "incapsula",
                "visid_incap",
                "x-iinfo"
            ]
        },
        {
            "name": "Sucuri",
            "signatures": [
                "sucuri",
                "x-sucuri",
                "x-sucuri-id",
                "x-sucuri-cache"
            ]
        },
        {
            "name": "F5 BIG-IP",
            "signatures": [
                "bigip",
                "f5",
                "big-ip",
                "x-waf"
            ]
        },
        {
            "name": "Barracuda",
            "signatures": ["barra", "barracuda"]
        },
        {
            "name": "Fortinet",
            "signatures": ["fortigate", "fortiwaf", "fortinet"]
        },
        {
            "name": "ModSecurity",
            "signatures": ["mod_security", "modsecurity", "modsec"]
        },
        {
            "name": "Fastly",
            "signatures": ["fastly", "x-fastly", "x-served-by"]
        },
        {
            "name": "Azure Front Door",
            "signatures": ["azure", "x-azure", "afd", "azurefd"]
        },
        {
            "name": "StackPath",
            "signatures": ["stackpath"]
        },
        {
            "name": "CloudFront",
            "signatures": [
                "cloudfront",
                "x-amz-cf-id",
                "x-amz-cf-pop"
            ]
        }
    ]

    best_match = {
        "name": "Not detected",
        "confidence": "0%",
        "evidence": []
    }

    best_score = 0

    for waf in waf_db:
        matched = []

        for signature in waf["signatures"]:
            sig = signature.lower()

            if sig in combined:
                matched.append(signature)

        if matched:
            confidence_value = min(100, 40 + (len(matched) * 20))

            if confidence_value > best_score:
                best_score = confidence_value

                best_match = {
                    "name": waf["name"],
                    "confidence": f"{confidence_value}%",
                    "evidence": matched
                }

    return best_match


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
                detected = any(keyword.lower() in text for keyword in item["keywords"])
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

    result["suspicious_entries"] = dedupe_list(result["suspicious_entries"])

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

        result["contacts"] = dedupe_list(result["contacts"])
        result["summary"] = "security.txt found"

        return result

    return result


def mask_secret(value):
    value = str(value or "").strip()

    if len(value) <= 10:
        return "***"

    return value[:6] + "..." + value[-4:]


def extract_js_urls(base_url, html):
    js_urls = []
    html = html or ""

    patterns = [
        r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
        r'href=["\']([^"\']+\.js[^"\']*)["\']'
    ]

    for pattern in patterns:
        for match in re.findall(pattern, html, flags=re.IGNORECASE):
            try:
                full_url = urljoin(str(base_url), match)
                if full_url not in js_urls:
                    js_urls.append(full_url)
            except Exception:
                pass

    return js_urls[:12]


def detect_js_secrets(js_text, js_url):
    findings = []

    secret_patterns = [
        {
            "type": "AWS Access Key",
            "severity": "HIGH",
            "regex": r"AKIA[0-9A-Z]{16}",
            "fix": "Remove AWS keys from frontend JavaScript. Rotate the exposed key and move secrets to backend environment variables."
        },
        {
            "type": "Google API Key",
            "severity": "MEDIUM",
            "regex": r"AIza[0-9A-Za-z\-_]{35}",
            "fix": "Restrict the Google API key by domain/IP and move sensitive usage to the backend where possible."
        },
        {
            "type": "Firebase API Key",
            "severity": "MEDIUM",
            "regex": r"apiKey\s*[:=]\s*[\"']([^\"']{20,})[\"']",
            "fix": "Review Firebase rules. Public Firebase config is common, but database/storage rules must be locked down."
        },
        {
            "type": "Private Key Marker",
            "severity": "CRITICAL",
            "regex": r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
            "fix": "Immediately remove private keys from public files, rotate affected credentials, and redeploy."
        },
        {
            "type": "Bearer Token",
            "severity": "HIGH",
            "regex": r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",
            "fix": "Do not expose bearer tokens in frontend code. Rotate the token and store it server-side."
        },
        {
            "type": "GitHub Token",
            "severity": "HIGH",
            "regex": r"gh[pousr]_[A-Za-z0-9_]{20,}",
            "fix": "Revoke the GitHub token immediately and remove it from public JavaScript."
        },
        {
            "type": "Slack Token",
            "severity": "HIGH",
            "regex": r"xox[baprs]-[A-Za-z0-9\-]{20,}",
            "fix": "Revoke the Slack token and move it to backend-only configuration."
        },
        {
            "type": "Possible Secret Assignment",
            "severity": "MEDIUM",
            "regex": r"(?:secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\s*[:=]\s*[\"']([^\"']{12,})[\"']",
            "fix": "Review this value. If it is a real secret, rotate it and move it to backend environment variables."
        }
    ]

    for rule in secret_patterns:
        try:
            matches = re.findall(rule["regex"], js_text, flags=re.IGNORECASE)

            for match in matches[:5]:
                value = match[0] if isinstance(match, tuple) else match

                findings.append({
                    "type": rule["type"],
                    "severity": rule["severity"],
                    "url": js_url,
                    "evidence": mask_secret(value),
                    "fix": rule["fix"]
                })

        except Exception:
            continue

    return findings


async def check_js_secrets(client, response):
    results = []

    if not response:
        return results

    js_urls = extract_js_urls(response.url, response.text)

    if not js_urls:
        return results

    tasks = [
        safe_get(client, js_url)
        for js_url in js_urls
    ]

    responses = await asyncio.gather(*tasks)

    for js_url, js_res in zip(js_urls, responses):
        if not js_res or js_res.status_code != 200:
            continue

        content_type = js_res.headers.get("content-type", "").lower()

        if "javascript" not in content_type and not str(js_url).lower().split("?")[0].endswith(".js"):
            continue

        js_text = js_res.text[:250000]
        results.extend(detect_js_secrets(js_text, js_url))

    return dedupe_dicts(results, ["type", "url", "evidence"])




def extract_api_endpoints(text):
    endpoints = set()

    if not text:
        return []

    patterns = [
        r'["\'](\/api\/[^"\']+)["\']',
        r'["\'](\/graphql[^"\']*)["\']',
        r'["\'](\/v[0-9]+\/[^"\']+)["\']',
        r'["\'](\/admin[^"\']*)["\']',
        r'["\'](https?:\/\/[^"\']+\/api\/[^"\']+)["\']'
    ]

    for pattern in patterns:
        try:
            matches = re.findall(pattern, text, flags=re.IGNORECASE)

            for match in matches:
                endpoint = str(match).strip()

                if len(endpoint) > 3:
                    endpoints.add(endpoint)

        except Exception:
            continue

    dangerous_keywords = [
        "debug",
        "internal",
        "private",
        "test",
        "dev",
        "swagger",
        "graphql",
        "admin"
    ]

    results = []

    for endpoint in sorted(list(endpoints))[:40]:
        severity = "INFO"

        if any(k in endpoint.lower() for k in dangerous_keywords):
            severity = "MEDIUM"

        results.append({
            "endpoint": endpoint,
            "severity": severity
        })

    return results


async def discover_api_endpoints(client, response):
    if not response:
        return []

    endpoints = []

    try:
        html = response.text or ""

        endpoints.extend(extract_api_endpoints(html))

        js_urls = extract_js_urls(response.url, html)

        tasks = [
            safe_get(client, js_url)
            for js_url in js_urls
        ]

        responses = await asyncio.gather(*tasks)

        for js_res in responses:
            if not js_res or js_res.status_code != 200:
                continue

            try:
                js_text = js_res.text[:250000]
                endpoints.extend(extract_api_endpoints(js_text))
            except Exception:
                continue

    except Exception:
        return []

    return dedupe_dicts(endpoints, ["endpoint"])




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

    except Exception:
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

    tasks = [
        fetch_cves_for_keyword(client, keyword)
        for keyword in keywords
    ]

    responses = await asyncio.gather(*tasks)

    for keyword, cves in zip(keywords, responses):
        results.append({
            "technology": keyword,
            "cves": cves
        })

    return results


async def check_whois_asn(client, ip):
    result = {
        "ip": ip,
        "asn": None,
        "organization": None,
        "isp": None,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "timezone": None,
        "network_range": None,
        "reverse_dns": None,
        "source": "ip-api.com",
        "error": None
    }

    if not ip:
        result["error"] = "No IP address available"
        return result

    try:
        url = f"http://ip-api.com/json/{ip}"

        params = {
            "fields": "status,message,country,countryCode,regionName,city,timezone,isp,org,as,query,reverse"
        }

        res = await client.get(url, params=params, timeout=6)

        if res.status_code != 200:
            result["error"] = f"ASN lookup HTTP {res.status_code}"
            return result

        data = res.json()

        if data.get("status") != "success":
            result["error"] = data.get("message", "ASN lookup failed")
            return result

        as_text = data.get("as") or ""
        asn = None
        organization_from_as = None

        if as_text:
            parts = as_text.split(" ", 1)
            asn = parts[0]
            organization_from_as = parts[1] if len(parts) > 1 else None

        result.update({
            "ip": data.get("query", ip),
            "asn": asn,
            "organization": data.get("org") or organization_from_as,
            "isp": data.get("isp"),
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "timezone": data.get("timezone"),
            "network_range": as_text,
            "reverse_dns": data.get("reverse"),
            "error": None
        })

        return result

    except Exception as e:
        result["error"] = str(e)
        return result


def build_structured_storage(findings, vulnerability_checks, subdomains, cve_results, open_ports):
    scan_findings = []
    scan_cves = []
    scan_subdomains = []
    scan_ports = []

    for item in findings:
        scan_findings.append({
            "title": item.get("title"),
            "severity": item.get("severity"),
            "category": item.get("category", "General"),
            "description": item.get("description"),
            "evidence": item.get("evidence"),
            "fix": item.get("fix")
        })

    for item in vulnerability_checks:
        if not any(f["title"] == item.get("name") for f in scan_findings):
            scan_findings.append({
                "title": item.get("name"),
                "severity": item.get("severity"),
                "category": item.get("category", "General"),
                "description": item.get("impact"),
                "evidence": item.get("evidence"),
                "fix": item.get("fix")
            })

    for sub in subdomains:
        scan_subdomains.append({
            "subdomain": sub.get("subdomain"),
            "ips": sub.get("ips", []),
            "http": sub.get("http", False),
            "https": sub.get("https", False),
            "status_code": sub.get("status_code"),
            "final_url": sub.get("final_url")
        })

    for port in open_ports:
        scan_ports.append({
            "port": port.get("port"),
            "service": port.get("service"),
            "banner": port.get("banner"),
            "risk": port.get("risk")
        })

    for tech_item in cve_results:
        technology = tech_item.get("technology")

        for cve in tech_item.get("cves", []):
            scan_cves.append({
                "technology": technology,
                "cve_id": cve.get("id"),
                "severity": cve.get("severity"),
                "score": cve.get("score"),
                "published": cve.get("published"),
                "description": cve.get("description"),
                "url": cve.get("url")
            })

    return {
        "scan_findings": dedupe_dicts(scan_findings, ["title", "severity", "evidence"]),
        "scan_subdomains": dedupe_dicts(scan_subdomains, ["subdomain"]),
        "scan_ports": dedupe_dicts(scan_ports, ["port"]),
        "scan_cves": dedupe_dicts(scan_cves, ["technology", "cve_id"])
    }


def build_fix_plan(findings):
    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4
    }

    critical_actions = []
    quick_wins = []
    top_issues = []

    sorted_findings = sorted(
        findings,
        key=lambda x: severity_order.get(str(x.get("severity", "INFO")).upper(), 99)
    )

    for item in sorted_findings[:10]:
        entry = {
            "title": item.get("title"),
            "severity": item.get("severity"),
            "fix": item.get("fix"),
            "category": item.get("category")
        }

        top_issues.append(entry)

        sev = str(item.get("severity", "INFO")).upper()

        if sev in ["CRITICAL", "HIGH"]:
            critical_actions.append(entry)

        elif sev in ["LOW", "MEDIUM"]:
            quick_wins.append(entry)

    return {
        "top_issues": top_issues[:5],
        "critical_actions": critical_actions[:5],
        "quick_wins": quick_wins[:5]
    }


def explain_score(findings, vulnerabilities, score):
    factors = []

    severity_weights = {
        "CRITICAL": 25,
        "HIGH": 18,
        "MEDIUM": 10,
        "LOW": 5
    }

    for item in findings[:20]:
        sev = str(item.get("severity", "INFO")).upper()

        if sev not in severity_weights:
            continue

        factors.append({
            "reason": item.get("title"),
            "severity": sev,
            "score_impact": severity_weights.get(sev, 0)
        })

    factors = sorted(
        factors,
        key=lambda x: x["score_impact"],
        reverse=True
    )

    return {
        "final_score": score,
        "risk_drivers": factors[:8],
        "total_vulnerabilities": len(vulnerabilities)
    }




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
            "target": target,
            "host": None,
            "ip": None,
            "profile": profile,
            "risk": "HIGH",
            "score": 100,
            "alerts": ["Invalid target"],
            "vulnerabilities": ["Invalid target format"],
            "vulnerability_checks": [],
            "findings": [],
            "structured": {
                "scan_findings": [],
                "scan_subdomains": [],
                "scan_ports": [],
                "scan_cves": []
            },
            "scan_summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }

    try:
        ip = socket.gethostbyname(host)

    except Exception:
        return {
            "target": target,
            "host": host,
            "ip": None,
            "profile": profile,
            "risk": "HIGH",
            "score": 90,
            "alerts": ["DNS resolution failed"],
            "vulnerabilities": ["Domain does not resolve"],
            "vulnerability_checks": [
                {
                    "name": "DNS Resolution Failed",
                    "severity": "HIGH",
                    "category": "DNS",
                    "evidence": host,
                    "impact": "The domain cannot be reached.",
                    "fix": "Check DNS configuration and domain validity."
                }
            ],
            "findings": [
                {
                    "title": "DNS Resolution Failed",
                    "severity": "HIGH",
                    "category": "DNS",
                    "description": "The domain could not be resolved to an IP address.",
                    "evidence": host,
                    "fix": "Check that the domain is valid and DNS records are configured correctly."
                }
            ],
            "structured": {
                "scan_findings": [
                    {
                        "title": "DNS Resolution Failed",
                        "severity": "HIGH",
                        "category": "DNS",
                        "description": "The domain could not be resolved to an IP address.",
                        "evidence": host,
                        "fix": "Check that the domain is valid and DNS records are configured correctly."
                    }
                ],
                "scan_subdomains": [],
                "scan_ports": [],
                "scan_cves": []
            },
            "scan_summary": {
                "total_findings": 1,
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }

    async with httpx.AsyncClient(
        timeout=5,
        follow_redirects=True,
        headers={"User-Agent": "ThreatScanner-Profile/3.0"}
    ) as client:

        response_task = safe_get(client, url)
        options_task = safe_options(client, url)
        ssl_task = check_ssl(host)
        dns_task = check_dns_security(host)
        robots_task = check_robots_txt(client, url)
        security_txt_task = check_security_txt(client, url)
        whois_asn_task = check_whois_asn(client, ip)

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
            for port in list(set(COMMON_PORTS + RISKY_PORTS))
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
            whois_asn,
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
            whois_asn_task,
            subdomains_task,
            nikto_task,
            ports_task,
            sensitive_task
        )

        ssl_ok = ssl_result.get("valid")
        ssl_info = ssl_result.get("expires")
        tls_version = ssl_result.get("tls_version")
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

        js_secrets = (
            await check_js_secrets(client, response)
            if response and profile in ["full", "deep"]
            else []
        )

        api_endpoints = (
            await discover_api_endpoints(client, response)
            if response and profile in ["full", "deep"]
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
                "Check server, DNS, firewall, and hosting status.",
                "Availability"
            )

            add_finding(
                findings,
                "Website Not Reachable",
                "MEDIUM",
                "The scanner could not connect to the website.",
                "Check server availability, firewall rules, DNS, and hosting status.",
                "Availability",
                url
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
                    "Force HTTPS redirection and enable HSTS.",
                    "SSL/TLS"
                )

                add_finding(
                    findings,
                    "HTTP Used Instead of HTTPS",
                    "MEDIUM",
                    "The website is accessible over insecure HTTP.",
                    "Redirect all HTTP traffic to HTTPS and enable a valid SSL certificate.",
                    "SSL/TLS",
                    str(response.url)
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
                    "Review backend logs and server configuration.",
                    "HTTP"
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
                    "Review URL routing and access controls.",
                    "HTTP"
                )

            for header, info in SECURITY_HEADERS.items():
                if header in response.headers:
                    found_headers.append(header)

                else:
                    missing_headers.append(header)
                    score += 6
                    vulnerabilities.append(f"Missing security header: {header}")

                    add_vuln(
                        vulnerability_checks,
                        f"Missing Security Header: {header}",
                        info["severity"],
                        f"{header} not present",
                        "Missing browser security controls may increase attack surface.",
                        info["fix"],
                        "Headers"
                    )

                    add_finding(
                        findings,
                        f"Missing Security Header: {header}",
                        info["severity"],
                        f"The response does not include the {header} security header.",
                        info["fix"],
                        "Headers",
                        f"{header} not present"
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
                    "Hide or reduce server version information.",
                    "Headers"
                )

                add_finding(
                    findings,
                    "Server Header Exposed",
                    "LOW",
                    f"The server reveals technology information: {server}.",
                    "Hide or minimize server version headers to reduce information disclosure.",
                    "Headers",
                    f"Server: {server}"
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
                    "Remove X-Powered-By header.",
                    "Headers"
                )

                add_finding(
                    findings,
                    "Technology Header Exposed",
                    "LOW",
                    f"The application reveals technology information: {powered}.",
                    "Remove X-Powered-By headers from the web server or framework.",
                    "Headers",
                    f"X-Powered-By: {powered}"
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
                        "Set HttpOnly flag on sensitive cookies.",
                        "Cookies"
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
                        "Set Secure flag on cookies.",
                        "Cookies"
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
                        "Set SameSite=Lax or SameSite=Strict.",
                        "Cookies"
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
                    "Restrict CORS to trusted domains only.",
                    "CORS"
                )

                add_finding(
                    findings,
                    "CORS Misconfiguration",
                    "MEDIUM",
                    issue,
                    "Restrict Access-Control-Allow-Origin to trusted domains only.",
                    "CORS",
                    issue
                )

            dangerous_methods = [
                m for m in http_methods
                if m.upper() in ["PUT", "DELETE", "TRACE", "CONNECT"]
            ]

            if dangerous_methods:
                score += len(dangerous_methods) * 10
                methods_text = ", ".join(dangerous_methods)

                vulnerabilities.append(
                    f"Potentially dangerous HTTP methods enabled: {methods_text}"
                )

                for method in dangerous_methods:
                    add_vuln(
                        vulnerability_checks,
                        "Dangerous HTTP Method Enabled",
                        "MEDIUM",
                        method,
                        "Unsafe HTTP methods may allow unintended actions.",
                        "Disable unused HTTP methods such as PUT, DELETE, TRACE, CONNECT.",
                        "HTTP Methods"
                    )

                add_finding(
                    findings,
                    "Dangerous HTTP Methods",
                    "MEDIUM",
                    "Some HTTP methods may allow unsafe operations if not protected.",
                    "Disable unused HTTP methods at the web server or application layer.",
                    "HTTP Methods",
                    methods_text
                )

            page_text = response.text.lower()

            if js_secrets:
                score += min(30, len(js_secrets) * 8)
                vulnerabilities.append("Possible secrets exposed in JavaScript files")

                for secret in js_secrets[:8]:
                    add_vuln(
                        vulnerability_checks,
                        f"Possible JS Secret Exposure: {secret.get('type')}",
                        secret.get("severity", "MEDIUM"),
                        f"{secret.get('url')} | Evidence: {secret.get('evidence')}",
                        "Public JavaScript appears to contain a value that may be sensitive.",
                        secret.get("fix"),
                        "JavaScript Secrets"
                    )

                    add_finding(
                        findings,
                        f"Possible JS Secret Exposure: {secret.get('type')}",
                        secret.get("severity", "MEDIUM"),
                        "A public JavaScript file appears to contain a possible secret or credential-like value.",
                        secret.get("fix"),
                        "JavaScript Secrets",
                        f"{secret.get('url')} | Evidence: {secret.get('evidence')}"
                    )

            if api_endpoints:
                add_finding(
                    findings,
                    "API Endpoints Discovered",
                    "INFO",
                    f"{len(api_endpoints)} possible API endpoints were discovered.",
                    "Review exposed endpoints and ensure authentication, authorization, and rate limiting are enabled.",
                    "Attack Surface",
                    ", ".join([x.get("endpoint") for x in api_endpoints[:5]])
                )

                for endpoint in api_endpoints[:15]:

                    if endpoint.get("severity") == "MEDIUM":
                        score += 4

                        add_vuln(
                            vulnerability_checks,
                            "Sensitive API Endpoint Discovered",
                            "LOW",
                            endpoint.get("endpoint"),
                            "Potentially sensitive API or admin endpoint discovered in frontend content.",
                            "Protect internal/admin/debug endpoints and disable unused public APIs.",
                            "Attack Surface"
                        )

            test_payloads = [
                "' OR '1'='1",
                "<script>alert(1)</script>"
            ]

            for payload in test_payloads:
                try:
                    test_url = str(response.url)

                    if "?" in test_url:
                        test_url = test_url + "&scan_test=" + payload
                    else:
                        test_url = test_url + "?scan_test=" + payload

                    test_res = await safe_get(client, test_url)

                    if not test_res:
                        continue

                    body = test_res.text.lower()

                    sqli_patterns = [
                        "sql syntax",
                        "mysql_fetch",
                        "mysql error",
                        "syntax error",
                        "unclosed quotation",
                        "odbc sql",
                        "postgresql",
                        "sqlite error",
                        "sqlstate",
                        "you have an error in your sql syntax",
                        "warning: mysql",
                        "ora-",
                        "microsoft ole db"
                    ]

                    if any(pattern in body for pattern in sqli_patterns):
                        score += 25

                        vulnerabilities.append(
                            "Possible SQL Injection behavior detected"
                        )

                        add_vuln(
                            vulnerability_checks,
                            "Possible SQL Injection",
                            "HIGH",
                            payload,
                            "Database error patterns were detected after a safe test payload was sent.",
                            "Use parameterized queries, server-side validation, and avoid showing database errors to users.",
                            "Injection"
                        )

                        add_finding(
                            findings,
                            "Possible SQL Injection",
                            "HIGH",
                            "The application returned SQL-related error patterns after a safe test payload.",
                            "Use parameterized queries and sanitize user input. Disable detailed database errors in production.",
                            "Injection",
                            payload
                        )

                    if payload.lower() in body:
                        score += 15

                        vulnerabilities.append(
                            "Possible reflected XSS behavior detected"
                        )

                        add_vuln(
                            vulnerability_checks,
                            "Possible Reflected XSS",
                            "MEDIUM",
                            payload,
                            "The test payload was reflected in the HTTP response.",
                            "Escape output, sanitize user-controlled input, and apply a strong Content-Security-Policy.",
                            "XSS"
                        )

                        add_finding(
                            findings,
                            "Possible Reflected XSS",
                            "MEDIUM",
                            "User-controlled input appears to be reflected in the response.",
                            "Escape HTML output, validate input, and add a strong Content-Security-Policy header.",
                            "XSS",
                            payload
                        )

                except Exception:
                    pass

            if "index of /" in page_text or "directory listing" in page_text:
                score += 30
                vulnerabilities.append("Directory listing appears to be enabled")

                add_vuln(
                    vulnerability_checks,
                    "Directory Listing Enabled",
                    "HIGH",
                    "Page contains directory listing indicators.",
                    "Files and folders may be publicly exposed.",
                    "Disable directory listing on the web server.",
                    "Exposure"
                )

                add_finding(
                    findings,
                    "Directory Listing Enabled",
                    "HIGH",
                    "The website appears to expose directory listings.",
                    "Disable directory listing in the web server configuration.",
                    "Exposure",
                    "index of /"
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
            "Install a valid TLS certificate and ensure HTTPS is correctly configured.",
            "SSL/TLS"
        )

        add_finding(
            findings,
            "SSL Problem",
            "MEDIUM",
            "The website has an SSL/TLS issue or HTTPS is not available.",
            "Install a valid TLS certificate and ensure HTTPS is correctly configured.",
            "SSL/TLS",
            str(ssl_info)
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
                "Configure SPF and DMARC records.",
                "DNS"
            )

            add_finding(
                findings,
                "DNS Email Security Issue",
                "LOW",
                issue,
                "Configure SPF and DMARC records to reduce email spoofing risk.",
                "DNS",
                issue
            )

    if robots_txt["suspicious_entries"]:
        score += 10
        vulnerabilities.append("robots.txt contains potentially sensitive entries")
        evidence = ", ".join(robots_txt["suspicious_entries"])

        add_vuln(
            vulnerability_checks,
            "Suspicious robots.txt Entries",
            "LOW",
            evidence,
            "robots.txt may reveal sensitive paths.",
            "Avoid exposing sensitive path names and protect routes with authentication.",
            "Robots"
        )

        add_finding(
            findings,
            "Suspicious robots.txt Entries",
            "LOW",
            "robots.txt contains paths that may reveal sensitive areas.",
            "Avoid exposing sensitive path names in robots.txt and protect sensitive routes.",
            "Robots",
            evidence
        )

    if not security_txt["exists"]:
        add_finding(
            findings,
            "security.txt Not Found",
            "INFO",
            "The website does not expose a security.txt file.",
            "Add /.well-known/security.txt with a security contact and disclosure policy.",
            "Security Policy"
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
            "Remove exposed files or restrict access with authentication.",
            "Exposure"
        )

    for item in nikto_checks:
        score += severity_points(item["severity"])
        vulnerabilities.append(item["name"])

        add_vuln(
            vulnerability_checks,
            item["name"],
            item["severity"],
            item["evidence"],
            f"Potential exposure detected at {item['path']}",
            item["fix"],
            "Nikto-like"
        )

        add_finding(
            findings,
            item["name"],
            item["severity"],
            item["evidence"],
            item["fix"],
            "Nikto-like",
            item.get("url")
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
            "Close unused ports or restrict them with firewall rules.",
            "Ports"
        )

        add_finding(
            findings,
            "Risky Open Ports",
            "MEDIUM",
            "Potentially risky service ports are reachable from the internet.",
            "Close unused ports or restrict them with firewall rules and IP allowlists.",
            "Ports",
            ports_text
        )

    if subdomains:
        add_finding(
            findings,
            "Subdomains Discovered",
            "INFO",
            f"{len(subdomains)} common subdomains were discovered.",
            "Review discovered subdomains and ensure unused environments are removed or protected.",
            "Subdomains"
        )

    if whois_asn and not whois_asn.get("error"):
        whois_evidence = ", ".join([
            str(x)
            for x in [
                whois_asn.get("asn"),
                whois_asn.get("organization"),
                whois_asn.get("isp"),
                whois_asn.get("country")
            ]
            if x
        ])

        add_finding(
            findings,
            "Whois / ASN Information Collected",
            "INFO",
            "Public network ownership and ASN information was collected for the target IP.",
            "Review hosting provider, ASN, and geolocation information for asset inventory and exposure tracking.",
            "Whois/ASN",
            whois_evidence or whois_asn.get("ip")
        )

    for item in cve_results:
        for cve in item.get("cves", []):
            severity = cve.get("severity", "UNKNOWN")
            score += severity_points(severity)

            add_vuln(
                vulnerability_checks,
                f"Possible CVE Match: {cve.get('id')}",
                severity,
                f"Technology: {item.get('technology')}",
                cve.get("description", "No description"),
                f"Review {cve.get('url')} and update or patch if applicable.",
                "CVE"
            )

            add_finding(
                findings,
                f"Possible CVE Match: {cve.get('id')}",
                severity,
                f"Technology: {item.get('technology')} | {cve.get('description')}",
                f"Review: {cve.get('url')} and update/patch the affected technology if applicable.",
                "CVE",
                cve.get("url")
            )

    score = min(score, 100)

    if score >= 70:
        risk = "HIGH"
    elif score >= 35:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    vulnerabilities = dedupe_list(vulnerabilities)
    alerts = dedupe_list(alerts + vulnerabilities)
    findings = dedupe_dicts(findings, ["title", "severity", "evidence"])
    vulnerability_checks = dedupe_dicts(
        vulnerability_checks,
        ["name", "severity", "evidence"]
    )

    structured = build_structured_storage(
        findings=findings,
        vulnerability_checks=vulnerability_checks,
        subdomains=subdomains,
        cve_results=cve_results,
        open_ports=open_ports
    )

    summary_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for item in structured["scan_findings"]:
        sev = str(item.get("severity", "INFO")).lower()

        if sev in summary_counts:
            summary_counts[sev] += 1

    scan_summary = {
        "total_findings": len(structured["scan_findings"]),
        **summary_counts
    }

    remediation_plan = build_fix_plan(findings)

    score_explanation = explain_score(
        findings=findings,
        vulnerabilities=vulnerabilities,
        score=score
    )

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
            "tls_version": tls_version,
            "cipher_name": ssl_result.get("cipher_name"),
            "cipher_protocol": ssl_result.get("cipher_protocol"),
            "cipher_bits": ssl_result.get("cipher_bits"),
            "subject": ssl_result.get("subject"),
            "issuer": ssl_result.get("issuer")
        },
        "dns_security": dns_security,
        "robots_txt": robots_txt,
        "security_txt": security_txt,
        "whois_asn": whois_asn,
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
        "js_secrets": js_secrets,
        "api_endpoints": api_endpoints,
        "vulnerabilities": vulnerabilities,
        "vulnerability_checks": vulnerability_checks,
        "findings": findings,
        "alerts": alerts,
        "structured": structured,
        "scan_summary": scan_summary,
        "remediation_plan": remediation_plan,
        "score_explanation": score_explanation
    }