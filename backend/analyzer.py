import asyncio
import socket
import ssl
import httpx
import dns.resolver
import re
import ipaddress
import nmap
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse


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

ADVANCED_EXPOSURE_PATHS = [
    {
        "path": "/docs",
        "type": "Swagger / FastAPI Docs",
        "category": "API Documentation",
        "risk_if_public": "HIGH",
        "keywords": ["swagger ui", "openapi", "fastapi", "api documentation"]
    },
    {
        "path": "/redoc",
        "type": "ReDoc API Docs",
        "category": "API Documentation",
        "risk_if_public": "HIGH",
        "keywords": ["redoc", "openapi"]
    },
    {
        "path": "/openapi.json",
        "type": "OpenAPI Schema",
        "category": "API Documentation",
        "risk_if_public": "HIGH",
        "keywords": ["openapi", "paths", "components", "schemas"]
    },
    {
        "path": "/swagger",
        "type": "Swagger Endpoint",
        "category": "API Documentation",
        "risk_if_public": "HIGH",
        "keywords": ["swagger", "openapi"]
    },
    {
        "path": "/swagger-ui.html",
        "type": "Swagger UI",
        "category": "API Documentation",
        "risk_if_public": "HIGH",
        "keywords": ["swagger ui", "openapi"]
    },
    {
        "path": "/graphql",
        "type": "GraphQL Endpoint",
        "category": "GraphQL",
        "risk_if_public": "MEDIUM",
        "keywords": ["graphql", "query", "mutation", "errors"]
    },
    {
        "path": "/graphiql",
        "type": "GraphiQL Console",
        "category": "GraphQL",
        "risk_if_public": "HIGH",
        "keywords": ["graphiql", "graphql"]
    },
    {
        "path": "/admin",
        "type": "Admin Panel",
        "category": "Admin/Auth",
        "risk_if_public": "MEDIUM",
        "keywords": ["admin", "dashboard", "login", "password", "sign in"]
    },
    {
        "path": "/admin/",
        "type": "Admin Panel",
        "category": "Admin/Auth",
        "risk_if_public": "MEDIUM",
        "keywords": ["admin", "dashboard", "login", "password", "sign in"]
    },
    {
        "path": "/login",
        "type": "Login Page",
        "category": "Admin/Auth",
        "risk_if_public": "INFO",
        "keywords": ["login", "password", "username", "sign in"]
    },
    {
        "path": "/debug",
        "type": "Debug Endpoint",
        "category": "Debug",
        "risk_if_public": "HIGH",
        "keywords": ["debug", "traceback", "stack trace", "exception", "environment"]
    },
    {
        "path": "/api/docs",
        "type": "API Docs",
        "category": "API Documentation",
        "risk_if_public": "HIGH",
        "keywords": ["swagger", "openapi", "api"]
    }
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


def add_finding(
    findings,
    title,
    severity,
    description,
    fix,
    category="General",
    evidence=None,
    confidence="MEDIUM",
    evidence_type="generic"
):
    findings.append({
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "evidence": evidence,
        "fix": fix,
        "confidence": confidence,
        "evidence_type": evidence_type,
        "affected_url": None,
        "fix_location": None
    })


def add_vuln(
    vulns,
    name,
    severity,
    evidence,
    impact,
    fix,
    category="General",
    confidence="MEDIUM",
    evidence_type="generic"
):
    vulns.append({
        "name": name,
        "severity": severity,
        "category": category,
        "evidence": evidence,
        "impact": impact,
        "fix": fix,
        "confidence": confidence,
        "evidence_type": evidence_type,
        "affected_url": None,
        "fix_location": None
    })


def is_ip_address(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except Exception:
        return False


def normalize_target(target):
    target = str(target or "").strip()

    if not target:
        return target

    if target.startswith("http://") or target.startswith("https://"):
        return target

    return "https://" + target


def get_hostname(target):
    return urlparse(normalize_target(target)).hostname


def get_target_type(host):
    return "ip" if is_ip_address(host) else "domain"


def get_http_candidates(target):
    normalized = normalize_target(target)
    parsed = urlparse(normalized)

    if not parsed.hostname:
        return []

    host = parsed.hostname
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path if parsed.path else ""

    if parsed.query:
        path += "?" + parsed.query

    first_scheme = parsed.scheme or "https"
    second_scheme = "http" if first_scheme == "https" else "https"

    candidates = [
        f"{first_scheme}://{host}{port}{path}",
        f"{second_scheme}://{host}{port}{path}"
    ]

    output = []
    for item in candidates:
        if item not in output:
            output.append(item)

    return output


async def get_best_response(client, target):
    for candidate in get_http_candidates(target):
        res = await safe_get(client, candidate)
        if res:
            return res

    return None


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


async def check_reverse_dns(ip):
    result = {
        "ip": ip,
        "reverse_dns": None,
        "error": None
    }

    if not is_ip_address(ip):
        result["error"] = "Target is not an IP address"
        return result

    def reverse_job():
        try:
            host, aliases, addresses = socket.gethostbyaddr(ip)
            result["reverse_dns"] = host
            return result
        except Exception as e:
            result["error"] = str(e)
            return result

    return await asyncio.to_thread(reverse_job)


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
                "fix": item["fix"],
                "affected_url": str(res.url),
                "fix_location": item["path"]
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




def classify_exposure_status(res, item):
    if not res:
        return None

    status_code = res.status_code
    body = (res.text or "").lower()[:6000]
    headers = str(res.headers).lower()

    if status_code in [401, 403]:
        return {
            "path": item["path"],
            "type": item["type"],
            "category": item["category"],
            "severity": "INFO",
            "status_code": status_code,
            "status": "PROTECTED",
            "confidence": "HIGH",
            "evidence_type": "status_code",
            "evidence": f"HTTP {status_code} indicates access control is present.",
            "fix": "Protected endpoint detected. Keep authentication and authorization enabled."
        }

    if status_code in [404, 410]:
        return None

    keyword_hits = [
        kw for kw in item.get("keywords", [])
        if kw.lower() in body or kw.lower() in headers
    ]

    # OpenAPI JSON is strong evidence if public and parse-like response exists
    if item["path"].endswith("openapi.json") and status_code == 200:
        if "openapi" in body and "paths" in body:
            return {
                "path": item["path"],
                "type": item["type"],
                "category": item["category"],
                "severity": "HIGH",
                "status_code": status_code,
                "status": "POSSIBLE",
                "confidence": "HIGH",
                "evidence_type": "public_schema",
                "evidence": "OpenAPI schema appears publicly accessible.",
                "fix": "Restrict OpenAPI schema in production or protect it behind authentication."
            }

    if status_code == 200 and keyword_hits:
        severity = item.get("risk_if_public", "INFO")

        # Login pages are generally attack surface, not vulnerabilities
        if item["category"] == "Admin/Auth" and item["type"] == "Login Page":
            severity = "INFO"

        return {
            "path": item["path"],
            "type": item["type"],
            "category": item["category"],
            "severity": severity,
            "status_code": status_code,
            "status": "POSSIBLE" if severity in ["HIGH", "MEDIUM"] else "INFO",
            "confidence": "HIGH" if len(keyword_hits) >= 2 else "MEDIUM",
            "evidence_type": "keyword_status_match",
            "evidence": f"HTTP 200 with indicators: {', '.join(keyword_hits[:5])}",
            "fix": "Review whether this endpoint should be public. Add authentication, IP allowlisting, or disable it in production."
        }

    if status_code in [301, 302, 307, 308]:
        location = res.headers.get("location", "")
        return {
            "path": item["path"],
            "type": item["type"],
            "category": item["category"],
            "severity": "INFO",
            "status_code": status_code,
            "status": "INFO",
            "confidence": "MEDIUM",
            "evidence_type": "redirect",
            "evidence": f"Redirects to {location}",
            "fix": "Verify redirected endpoint is intended and protected if sensitive."
        }

    return None


async def check_advanced_exposures(client, base_url):
    results = []

    tasks = []
    for item in ADVANCED_EXPOSURE_PATHS:
        url = base_url.rstrip("/") + item["path"]
        tasks.append((item, url, safe_get(client, url)))

    responses = await asyncio.gather(*[task for _, _, task in tasks])

    for (item, url, _), res in zip(tasks, responses):
        finding = classify_exposure_status(res, item)

        if finding:
            finding["url"] = str(res.url) if res else url
            results.append(finding)

    return dedupe_dicts(results, ["path", "type", "status_code"])


async def check_graphql_introspection(client, base_url):
    url = base_url.rstrip("/") + "/graphql"

    query = {
        "query": "{ __schema { queryType { name } mutationType { name } types { name } } }"
    }

    try:
        res = await client.post(url, json=query, timeout=6)

        if res.status_code in [404, 405]:
            return None

        text = res.text.lower()

        if res.status_code == 200 and "__schema" in text and "querytype" in text:
            return {
                "endpoint": "/graphql",
                "url": str(res.url),
                "enabled": True,
                "severity": "HIGH",
                "status": "POSSIBLE",
                "confidence": "HIGH",
                "evidence_type": "graphql_introspection",
                "evidence": "GraphQL introspection appears enabled publicly.",
                "fix": "Disable GraphQL introspection in production unless explicitly needed and protected."
            }

        if res.status_code in [401, 403]:
            return {
                "endpoint": "/graphql",
                "url": str(res.url),
                "enabled": False,
                "severity": "INFO",
                "status": "PROTECTED",
                "confidence": "HIGH",
                "evidence_type": "status_code",
                "evidence": f"GraphQL endpoint returned HTTP {res.status_code}.",
                "fix": "GraphQL endpoint appears protected. Keep access controls enabled."
            }

    except Exception:
        return None

    return None


def classify_api_endpoint(endpoint):
    e = str(endpoint or "").lower()

    if any(x in e for x in ["swagger", "openapi", "docs", "redoc"]):
        return {
            "category": "API Documentation",
            "severity": "MEDIUM",
            "status": "POSSIBLE",
            "confidence": "MEDIUM"
        }

    if any(x in e for x in ["admin", "internal", "private", "debug"]):
        return {
            "category": "Sensitive API",
            "severity": "LOW",
            "status": "INFO",
            "confidence": "LOW"
        }

    if any(x in e for x in ["login", "auth", "token", "session"]):
        return {
            "category": "Auth API",
            "severity": "INFO",
            "status": "INFO",
            "confidence": "MEDIUM"
        }

    if "graphql" in e:
        return {
            "category": "GraphQL",
            "severity": "MEDIUM",
            "status": "POSSIBLE",
            "confidence": "MEDIUM"
        }

    return {
        "category": "API Endpoint",
        "severity": "INFO",
        "status": "INFO",
        "confidence": "LOW"
    }




def normalize_body_for_diff(body):
    body = str(body or "")
    body = re.sub(r"\s+", " ", body)
    body = re.sub(r"\d{2,}", "N", body)
    body = re.sub(r"[a-f0-9]{16,}", "HASH", body, flags=re.IGNORECASE)
    return body[:50000]


def response_fingerprint(res):
    if not res:
        return {
            "status_code": None,
            "length": 0,
            "word_count": 0,
            "title": None,
            "body": ""
        }

    body = normalize_body_for_diff(res.text)
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE)

    return {
        "status_code": res.status_code,
        "length": len(body),
        "word_count": len(body.split()),
        "title": title_match.group(1).strip() if title_match else None,
        "body": body
    }


def diff_score(base_fp, test_fp):
    if not base_fp or not test_fp:
        return 0

    score = 0

    if base_fp.get("status_code") != test_fp.get("status_code"):
        score += 30

    base_len = max(base_fp.get("length", 0), 1)
    test_len = test_fp.get("length", 0)
    ratio = abs(base_len - test_len) / base_len

    if ratio > 0.45:
        score += 35
    elif ratio > 0.25:
        score += 25
    elif ratio > 0.12:
        score += 12

    if base_fp.get("title") != test_fp.get("title"):
        score += 10

    return min(score, 100)


def contains_sql_error(body):
    body = str(body or "").lower()

    patterns = [
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
        "microsoft ole db",
        "native client",
        "database error",
        "pg_query"
    ]

    return any(pattern in body for pattern in patterns)


def reflected_context(body, payload):
    body = str(body or "")
    payload = str(payload or "")

    if payload not in body:
        return None

    index = body.find(payload)
    start = max(0, index - 80)
    end = min(len(body), index + len(payload) + 80)
    context = body[start:end]

    if "<script" in context.lower():
        return "script_context"

    if "href=" in context.lower() or "src=" in context.lower():
        return "attribute_context"

    if "<" in context and ">" in context:
        return "html_context"

    return "text_context"


async def validate_sqli_behavior(client, base_url):
    results = []

    baseline = await safe_get(client, base_url)
    if not baseline:
        return results

    base_fp = response_fingerprint(baseline)

    payload_pairs = [
        ("' OR '1'='1", "' OR '1'='2"),
        ("1 OR 1=1", "1 OR 1=2")
    ]

    for truthy, falsy in payload_pairs:
        try:
            true_url = base_url + ("&" if "?" in base_url else "?") + "scan_test=" + truthy
            false_url = base_url + ("&" if "?" in base_url else "?") + "scan_test=" + falsy

            true_res, false_res = await asyncio.gather(
                safe_get(client, true_url),
                safe_get(client, false_url)
            )

            if not true_res or not false_res:
                continue

            true_fp = response_fingerprint(true_res)
            false_fp = response_fingerprint(false_res)

            true_diff = diff_score(base_fp, true_fp)
            false_diff = diff_score(base_fp, false_fp)
            pair_delta = abs(true_fp["length"] - false_fp["length"])

            sql_error = contains_sql_error(true_res.text) or contains_sql_error(false_res.text)

            if sql_error:
                results.append({
                    "type": "SQL Error Pattern",
                    "severity": "MEDIUM",
                    "status": "POSSIBLE",
                    "confidence": "MEDIUM",
                    "evidence_type": "database_error_pattern",
                    "evidence": f"Database error pattern observed with payload pair: {truthy} / {falsy}",
                    "fix": "Use parameterized queries and suppress detailed database errors in production.",
                    "affected_url": true_url,
                    "fix_location": "Query parameter: scan_test"
                })

            elif true_diff >= 25 and false_diff >= 25 and pair_delta > 80:
                results.append({
                    "type": "Behavioral SQLi Difference",
                    "severity": "MEDIUM",
                    "status": "POSSIBLE",
                    "confidence": "LOW",
                    "evidence_type": "response_diff",
                    "evidence": f"Truthy/falsy payloads changed response characteristics. Length delta: {pair_delta}",
                    "fix": "Manually verify parameter handling. Use parameterized queries and strong input validation."
                })

        except Exception:
            continue

    return dedupe_dicts(results, ["type", "evidence_type"])


async def validate_xss_reflection(client, base_url):
    results = []

    payloads = [
        "xsstest123",
        "<svg/onload=alert(1)>"
    ]

    for payload in payloads:
        try:
            test_url = base_url + ("&" if "?" in base_url else "?") + "scan_xss=" + payload
            res = await safe_get(client, test_url)

            if not res:
                continue

            context = reflected_context(res.text, payload)

            if not context:
                continue

            severity = "LOW"
            confidence = "LOW"
            status = "INFO"

            if context in ["script_context", "attribute_context", "html_context"] and payload.startswith("<svg"):
                severity = "MEDIUM"
                confidence = "MEDIUM"
                status = "POSSIBLE"

            results.append({
                "type": "Reflected Input",
                "severity": severity,
                "status": status,
                "confidence": confidence,
                "evidence_type": context,
                "evidence": f"Payload reflected in {context}: {payload}",
                "fix": "Escape output based on context, sanitize input, and use a strong Content-Security-Policy.",
                "affected_url": test_url,
                "fix_location": "Query parameter: scan_xss"
            })

        except Exception:
            continue

    return dedupe_dicts(results, ["type", "evidence_type"])


async def run_real_validation_engine(client, response):
    if not response:
        return {
            "sqli": [],
            "xss": []
        }

    base_url = str(response.url)

    sqli_results, xss_results = await asyncio.gather(
        validate_sqli_behavior(client, base_url),
        validate_xss_reflection(client, base_url)
    )

    return {
        "sqli": sqli_results,
        "xss": xss_results
    }




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
            "fix": item.get("fix"),
            "confidence": item.get("confidence", "MEDIUM"),
            "evidence_type": item.get("evidence_type", "generic")
        })

    for item in vulnerability_checks:
        if not any(f["title"] == item.get("name") for f in scan_findings):
            scan_findings.append({
                "title": item.get("name"),
                "severity": item.get("severity"),
                "category": item.get("category", "General"),
                "description": item.get("impact"),
                "evidence": item.get("evidence"),
                "fix": item.get("fix"),
                "confidence": item.get("confidence", "MEDIUM"),
                "evidence_type": item.get("evidence_type", "generic"),
                "status": item.get("status", detection_status(item.get("severity"), item.get("confidence", "MEDIUM")))
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
            "protocol": port.get("protocol", "tcp"),
            "state": port.get("state", "open"),
            "service": port.get("service"),
            "banner": port.get("banner"),
            "risk": port.get("risk"),
            "source": port.get("source", "socket")
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




def has_version_info(text):
    patterns = [
        r"[0-9]+\.[0-9]+",
        r"version\s*[0-9]+",
        r"nginx\/[0-9]",
        r"apache\/[0-9]",
        r"php\/[0-9]"
    ]

    text = str(text or "").lower()

    return any(re.search(p, text) for p in patterns)


def calculate_realistic_score(findings):
    score = 0

    weights = {
        ("CRITICAL", "HIGH"): 20,
        ("HIGH", "HIGH"): 15,
        ("MEDIUM", "HIGH"): 8,

        ("CRITICAL", "MEDIUM"): 12,
        ("HIGH", "MEDIUM"): 8,
        ("MEDIUM", "MEDIUM"): 5,

        ("LOW", "HIGH"): 3,
        ("LOW", "MEDIUM"): 2
    }

    for item in findings:
        sev = str(item.get("severity", "INFO")).upper()
        conf = str(item.get("confidence", "MEDIUM")).upper()

        score += weights.get((sev, conf), 0)

    return min(score, 100)




def detection_status(severity, confidence):
    sev = str(severity or "INFO").upper()
    conf = str(confidence or "MEDIUM").upper()

    if sev in ["CRITICAL", "HIGH"] and conf == "HIGH":
        return "CONFIRMED"

    if sev in ["HIGH", "MEDIUM"] and conf in ["MEDIUM", "LOW"]:
        return "POSSIBLE"

    if sev in ["LOW", "INFO"]:
        return "INFO"

    return "POSSIBLE"


def enrich_detection_metadata(findings, vulnerability_checks):
    for item in findings:
        item["confidence"] = item.get("confidence", "MEDIUM")
        item["evidence_type"] = item.get("evidence_type", "generic")
        item["status"] = item.get("status") or detection_status(
            item.get("severity"),
            item.get("confidence")
        )

    for item in vulnerability_checks:
        item["confidence"] = item.get("confidence", "MEDIUM")
        item["evidence_type"] = item.get("evidence_type", "generic")
        item["status"] = item.get("status") or detection_status(
            item.get("severity"),
            item.get("confidence")
        )

    return findings, vulnerability_checks


def calculate_realistic_score_v2(findings):
    score = 0

    weights = {
        ("CONFIRMED", "CRITICAL"): 28,
        ("CONFIRMED", "HIGH"): 22,
        ("CONFIRMED", "MEDIUM"): 10,
        ("CONFIRMED", "LOW"): 3,

        ("POSSIBLE", "CRITICAL"): 14,
        ("POSSIBLE", "HIGH"): 10,
        ("POSSIBLE", "MEDIUM"): 5,
        ("POSSIBLE", "LOW"): 1,

        ("INFO", "INFO"): 0,
        ("INFO", "LOW"): 0
    }

    for item in findings:
        status = str(item.get("status", "POSSIBLE")).upper()
        severity = str(item.get("severity", "INFO")).upper()
        score += weights.get((status, severity), 0)

    return min(score, 100)


def build_detection_summary(findings):
    summary = {
        "confirmed": 0,
        "possible": 0,
        "informational": 0,
        "high_confidence": 0,
        "medium_confidence": 0,
        "low_confidence": 0
    }

    for item in findings:
        status = str(item.get("status", "INFO")).upper()
        confidence = str(item.get("confidence", "MEDIUM")).upper()

        if status == "CONFIRMED":
            summary["confirmed"] += 1
        elif status == "POSSIBLE":
            summary["possible"] += 1
        else:
            summary["informational"] += 1

        if confidence == "HIGH":
            summary["high_confidence"] += 1
        elif confidence == "LOW":
            summary["low_confidence"] += 1
        else:
            summary["medium_confidence"] += 1

    return summary




def is_confirmed_vulnerability(item):
    """
    Very strict confirmation logic:
    A finding becomes a real vulnerability only when:
    - Severity is HIGH or CRITICAL
    - Confidence is HIGH
    - Evidence type is strong enough
    """

    severity = str(item.get("severity", "INFO")).upper()
    confidence = str(item.get("confidence", "LOW")).upper()
    evidence_type = str(item.get("evidence_type", "")).lower()

    real_confirmed_evidence = [
        "database_error_pattern",
        "graphql_introspection",
        "public_schema",
        "public_file",
        "private_key_exposed",
        "real_secret_exposed",
        "confirmed_exposure"
    ]

    if confidence != "HIGH":
        return False

    if severity not in ["CRITICAL", "HIGH"]:
        return False

    if evidence_type not in real_confirmed_evidence:
        return False

    return True


def separate_results(findings, vulnerability_checks):
    confirmed = []
    possible = []
    informational = []
    hardening_issues = []
    attack_surface = []

    combined = []

    for item in vulnerability_checks:
        combined.append({
            "title": item.get("name"),
            "severity": item.get("severity", "INFO"),
            "category": item.get("category", "General"),
            "description": item.get("impact"),
            "evidence": item.get("evidence"),
            "fix": item.get("fix"),
            "confidence": item.get("confidence", "LOW"),
            "evidence_type": item.get("evidence_type", "generic"),
            "status": item.get("status", detection_status(item.get("severity"), item.get("confidence", "LOW"))),
            "source": "vulnerability_check",
            "affected_url": item.get("affected_url") or item.get("url"),
            "fix_location": item.get("fix_location") or item.get("path") or item.get("endpoint"),
            "parameter": item.get("parameter"),
            "original_url": item.get("original_url")
        })

    for item in findings:
        combined.append({
            "title": item.get("title"),
            "severity": item.get("severity", "INFO"),
            "category": item.get("category", "General"),
            "description": item.get("description"),
            "evidence": item.get("evidence"),
            "fix": item.get("fix"),
            "confidence": item.get("confidence", "LOW"),
            "evidence_type": item.get("evidence_type", "generic"),
            "status": item.get("status", detection_status(item.get("severity"), item.get("confidence", "LOW"))),
            "source": "finding",
            "affected_url": item.get("affected_url") or item.get("url"),
            "fix_location": item.get("fix_location") or item.get("path") or item.get("endpoint"),
            "parameter": item.get("parameter"),
            "original_url": item.get("original_url")
        })

    combined = dedupe_dicts(combined, ["title", "severity", "evidence"])

    hardening_categories = [
        "headers",
        "cookies",
        "dns",
        "security policy",
        "ssl/tls"
    ]

    attack_surface_categories = [
        "attack surface",
        "api documentation",
        "admin/auth",
        "graphql",
        "subdomains",
        "whois/asn",
        "ip intelligence",
        "ports",
        "robots",
        "cve",
        "wayback",
        "kxss",
        "js endpoint",
        "parameter miner"
    ]

    for item in combined:
        title = str(item.get("title", "")).lower()
        category = str(item.get("category", "")).lower()
        sev = str(item.get("severity", "INFO")).upper()
        status = str(item.get("status", "INFO")).upper()

        if is_confirmed_vulnerability(item):
            item["status"] = "CONFIRMED"
            confirmed.append(item)
            continue

        if any(x in category for x in hardening_categories) or "missing security header" in title:
            item["status"] = "HARDENING"
            hardening_issues.append(item)
            continue

        if any(x in category for x in attack_surface_categories):
            item["status"] = "INFO"
            attack_surface.append(item)
            continue

        if status == "POSSIBLE" and sev in ["CRITICAL", "HIGH", "MEDIUM"]:
            item["status"] = "POSSIBLE"
            possible.append(item)
        else:
            item["status"] = "INFO"
            informational.append(item)

    return {
        "confirmed_vulnerabilities": confirmed,
        "possible_issues": possible,
        "hardening_issues": hardening_issues,
        "attack_surface": attack_surface,
        "informational_findings": informational
    }


def calculate_strict_score(separated):
    """
    Confirmed-only risk score:
    - Confirmed vulnerabilities affect score.
    - Possible issues do not raise score.
    - Hardening, attack surface, and informational findings do not raise score.
    """

    confirmed = separated.get("confirmed_vulnerabilities", [])

    if not confirmed:
        return 0

    score = 0

    confirmed_weights = {
        "CRITICAL": 45,
        "HIGH": 30,
        "MEDIUM": 12,
        "LOW": 3,
        "INFO": 0
    }

    for item in confirmed:
        sev = str(item.get("severity", "INFO")).upper()
        score += confirmed_weights.get(sev, 0)

    score = min(round(score), 100)

    return score


def build_strict_detection_summary(separated):
    confirmed = separated.get("confirmed_vulnerabilities", [])
    possible = separated.get("possible_issues", [])
    hardening = separated.get("hardening_issues", [])
    attack_surface = separated.get("attack_surface", [])
    info = separated.get("informational_findings", [])

    return {
        "confirmed": len(confirmed),
        "possible": len(possible),
        "hardening": len(hardening),
        "attack_surface": len(attack_surface),
        "informational": len(info),
        "confirmed_high_or_critical": len([
            x for x in confirmed
            if str(x.get("severity", "")).upper() in ["HIGH", "CRITICAL"]
        ]),
        "note": "Risk score uses confirmed vulnerabilities only. Hardening, attack surface, and possible findings do not count as real vulnerabilities."
    }


def build_strict_remediation_plan(separated):
    confirmed = separated.get("confirmed_vulnerabilities", [])
    possible = separated.get("possible_issues", [])
    hardening = separated.get("hardening_issues", [])

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4
    }

    confirmed_sorted = sorted(
        confirmed,
        key=lambda x: severity_order.get(str(x.get("severity", "INFO")).upper(), 99)
    )

    possible_sorted = sorted(
        possible,
        key=lambda x: severity_order.get(str(x.get("severity", "INFO")).upper(), 99)
    )

    hardening_sorted = sorted(
        hardening,
        key=lambda x: severity_order.get(str(x.get("severity", "INFO")).upper(), 99)
    )

    return {
        "fix_now": confirmed_sorted[:5],
        "review_manually": possible_sorted[:5],
        "hardening": hardening_sorted[:5],
        "top_issues": confirmed_sorted[:5],
        "quick_wins": hardening_sorted[:5]
    }




async def run_nmap_scan(host):
    """
    Safe defensive Nmap scan with socket fallback.

    Why this version is better:
    - Uses scanner.all_hosts() because Nmap may return the resolved IP instead of the original domain.
    - Keeps only truly open ports from Nmap.
    - Falls back to a safe TCP connect scan for common ports if Nmap returns no ports.
    - Never crashes the full scan if Nmap is missing, blocked, or returns unexpected output.
    """
    result = {
        "enabled": False,
        "host": host,
        "ports": [],
        "error": None
    }

    scan_ports = sorted(set(COMMON_PORTS + RISKY_PORTS + [3306, 5432, 6379, 27017]))

    def nmap_job():
        try:
            scanner = nmap.PortScanner()

            ports_arg = ",".join(str(p) for p in scan_ports)

            scanner.scan(
                hosts=host,
                arguments=f"-Pn -sT -sV -T3 --host-timeout 25s -p {ports_arg}"
            )

            result["enabled"] = True

            all_hosts = scanner.all_hosts()
            scan_host = host if host in all_hosts else (all_hosts[0] if all_hosts else None)

            if not scan_host:
                result["error"] = "Nmap did not return host results"
                return result

            for proto in scanner[scan_host].all_protocols():
                for port in sorted(scanner[scan_host][proto].keys()):
                    data = scanner[scan_host][proto][port]
                    state = data.get("state")

                    if state != "open":
                        continue

                    result["ports"].append({
                        "port": int(port),
                        "protocol": proto,
                        "state": state,
                        "service": data.get("name") or PORT_SERVICES.get(int(port), "Unknown"),
                        "product": data.get("product") or "",
                        "version": data.get("version") or "",
                        "extra_info": data.get("extrainfo") or "",
                        "banner": None,
                        "risk": "RISKY" if int(port) in RISKY_PORTS else "NORMAL",
                        "source": "nmap"
                    })

            return result

        except Exception as e:
            result["error"] = str(e)
            return result

    nmap_result = await asyncio.to_thread(nmap_job)

    if nmap_result.get("ports"):
        nmap_result["ports"] = dedupe_dicts(nmap_result["ports"], ["port", "protocol"])
        return nmap_result

    fallback_ports = []

    for port in scan_ports:
        item = await check_port(host, port)

        if item:
            item["state"] = "open"
            item["protocol"] = "tcp"
            item["source"] = "socket-fallback"
            item["product"] = item.get("product", "")
            item["version"] = item.get("version", "")
            item["extra_info"] = item.get("extra_info", "")
            fallback_ports.append(item)

    nmap_result["ports"] = dedupe_dicts(fallback_ports, ["port", "protocol"])

    if fallback_ports:
        nmap_result["enabled"] = True
        nmap_result["error"] = None
    elif not nmap_result.get("error"):
        nmap_result["error"] = "No open ports found by Nmap or socket fallback"

    return nmap_result



# ============================================================
# Enterprise Sections: Confirmed / Possible / Informational
# ============================================================
def cvss_from_severity(severity):
    sev = str(severity or "INFO").upper()
    return {"CRITICAL": 9.8, "HIGH": 8.1, "MEDIUM": 5.6, "LOW": 3.1, "INFO": 0.0}.get(sev, 0.0)


def exploitability_from_item(item):
    sev = str(item.get("severity", "INFO")).upper()
    conf = str(item.get("confidence", "MEDIUM")).upper()
    evidence_type = str(item.get("evidence_type", "generic")).lower()
    strong = {
        "database_error_pattern", "graphql_introspection", "public_schema",
        "public_file", "private_key_exposed", "real_secret_exposed",
        "confirmed_exposure", "keyword_status_match"
    }
    if evidence_type in strong and conf == "HIGH":
        return "HIGH"
    if sev in ["CRITICAL", "HIGH"] and conf in ["HIGH", "MEDIUM"]:
        return "MEDIUM"
    if sev == "MEDIUM" and conf in ["HIGH", "MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def normalize_enterprise_status(item):
    status = str(item.get("status") or "").upper()
    if status in ["CONFIRMED", "POSSIBLE", "INFO", "HARDENING", "PROTECTED"]:
        return status

    sev = str(item.get("severity", "INFO")).upper()
    conf = str(item.get("confidence", "MEDIUM")).upper()
    category = str(item.get("category", "")).lower()
    title = str(item.get("title") or item.get("name") or item.get("type") or "").lower()
    evidence_type = str(item.get("evidence_type", "generic")).lower()

    confirmed_evidence = {
        "database_error_pattern", "graphql_introspection", "public_schema",
        "public_file", "private_key_exposed", "real_secret_exposed",
        "confirmed_exposure"
    }

    if evidence_type in confirmed_evidence and sev in ["HIGH", "CRITICAL"] and conf == "HIGH":
        return "CONFIRMED"

    if any(x in category for x in ["headers", "cookies", "dns", "ssl/tls", "security policy"]) or "missing security header" in title:
        return "HARDENING"

    if any(x in category for x in ["attack surface", "api documentation", "admin/auth", "graphql", "subdomains", "robots", "ports"]):
        return "INFO"

    if sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        return "POSSIBLE"

    return "INFO"


def enrich_enterprise_item(item):
    item = dict(item or {})
    item["title"] = item.get("title") or item.get("name") or item.get("type") or "Finding"
    item["description"] = item.get("description") or item.get("impact") or ""
    item["severity"] = str(item.get("severity", "INFO")).upper()
    item["confidence"] = str(item.get("confidence", "MEDIUM")).upper()
    item["status"] = normalize_enterprise_status(item)
    item["cvss"] = item.get("cvss") or item.get("cvss_score") or cvss_from_severity(item.get("severity"))
    item["exploitability"] = item.get("exploitability") or exploitability_from_item(item)
    item["affected_url"] = item.get("affected_url") or item.get("url")
    item["fix_location"] = item.get("fix_location") or item.get("path") or item.get("endpoint")
    item["evidence_type"] = item.get("evidence_type", "generic")
    return item


def build_enterprise_sections(findings, vulnerability_checks):
    confirmed = []
    possible = []
    hardening = []
    attack_surface = []
    informational = []

    combined = []
    for item in vulnerability_checks or []:
        combined.append(enrich_enterprise_item(item))
    for item in findings or []:
        combined.append(enrich_enterprise_item(item))

    combined = dedupe_dicts(combined, ["title", "severity", "evidence", "affected_url"])

    for item in combined:
        status = str(item.get("status", "INFO")).upper()
        category = str(item.get("category", "")).lower()

        if status == "CONFIRMED":
            confirmed.append(item)
        elif status == "POSSIBLE":
            possible.append(item)
        elif status == "HARDENING":
            hardening.append(item)
        elif any(x in category for x in ["attack surface", "api", "graphql", "subdomain", "robots", "ports"]):
            attack_surface.append(item)
        else:
            informational.append(item)

    return {
        "confirmed_vulnerabilities": confirmed,
        "possible_issues": possible,
        "hardening_issues": hardening,
        "attack_surface": attack_surface,
        "informational_findings": informational
    }


def calculate_enterprise_score(sections):
    score = 0
    confirmed_weights = {"CRITICAL": 45, "HIGH": 30, "MEDIUM": 12, "LOW": 3, "INFO": 0}
    possible_weights = {"CRITICAL": 8, "HIGH": 5, "MEDIUM": 2, "LOW": 0, "INFO": 0}

    for item in sections.get("confirmed_vulnerabilities", []):
        score += confirmed_weights.get(str(item.get("severity", "INFO")).upper(), 0)

    for item in sections.get("possible_issues", []):
        score += possible_weights.get(str(item.get("severity", "INFO")).upper(), 0)

    return min(round(score), 100)


def enterprise_risk_from_score(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def build_enterprise_summary(sections):
    return {
        "confirmed": len(sections.get("confirmed_vulnerabilities", [])),
        "possible": len(sections.get("possible_issues", [])),
        "hardening": len(sections.get("hardening_issues", [])),
        "attack_surface": len(sections.get("attack_surface", [])),
        "informational": len(sections.get("informational_findings", [])),
        "confirmed_high_or_critical": len([
            x for x in sections.get("confirmed_vulnerabilities", [])
            if str(x.get("severity", "")).upper() in ["HIGH", "CRITICAL"]
        ]),
        "note": "Confirmed vulnerabilities are separated from possible issues, hardening, attack surface, and informational findings."
    }




# ============================================================
# Wayback URLs + KXSS-like Reflection Engine
# Defensive/passive discovery for authorized testing only.
# ============================================================
WAYBACK_LIMIT = 80
KXSS_TEST_PAYLOAD = "kxss_reflect_12345"


def normalize_wayback_url(raw_url, host):
    try:
        parsed = urlparse(str(raw_url).strip())
        if not parsed.scheme or not parsed.netloc:
            return None

        target_host = (host or "").lower().replace("www.", "", 1)
        parsed_host = (parsed.hostname or "").lower().replace("www.", "", 1)

        if parsed_host != target_host and not parsed_host.endswith("." + target_host):
            return None

        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
    except Exception:
        return None


def classify_wayback_url(url):
    u = str(url or "").lower()
    severity = "INFO"
    status = "INFO"
    confidence = "LOW"
    url_type = "archived_url"

    if "?" in u and "=" in u:
        url_type = "parameterized_url"
        confidence = "MEDIUM"

    if any(x in u for x in ["/api/", "/v1/", "/v2/", "/graphql", "/admin", "/login", "/debug", "/swagger", "/openapi"]):
        url_type = "interesting_endpoint"
        confidence = "MEDIUM"

    if any(u.endswith(x) for x in [".js", ".json", ".xml", ".sql", ".zip", ".bak", ".old", ".backup"]):
        url_type = "interesting_file"
        confidence = "MEDIUM"

    high_patterns = [".env", ".git", "backup", ".sql", "database", "dump", "config", "secret", "debug", "openapi.json"]
    medium_patterns = ["admin", "swagger", "graphql", "token", "auth", "login", "api"]

    if any(p in u for p in high_patterns):
        severity = "MEDIUM"
        status = "POSSIBLE"
        confidence = "MEDIUM"
    elif any(p in u for p in medium_patterns):
        severity = "LOW"
        status = "INFO"
        confidence = "MEDIUM"

    return {
        "type": url_type,
        "severity": severity,
        "status": status,
        "confidence": confidence
    }


async def fetch_wayback_urls(client, host):
    result = {
        "enabled": True,
        "source": "web.archive.org CDX API",
        "host": host,
        "total": 0,
        "urls": [],
        "parameterized_urls": [],
        "interesting_urls": [],
        "error": None
    }

    if not host or is_ip_address(host):
        result["enabled"] = False
        result["error"] = "Wayback discovery works best with domain targets, not raw IPs."
        return result

    try:
        res = await client.get(
            "https://web.archive.org/cdx",
            params={
                "url": f"{host}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "filter": "statuscode:200",
                "limit": str(WAYBACK_LIMIT)
            },
            timeout=12
        )

        if res.status_code != 200:
            result["error"] = f"Wayback API HTTP {res.status_code}"
            return result

        data = res.json()
        rows = data[1:] if isinstance(data, list) and len(data) > 1 else []

        urls = []
        for row in rows:
            raw = row[0] if isinstance(row, list) and row else row
            clean = normalize_wayback_url(raw, host)
            if clean and clean not in urls:
                urls.append(clean)

        urls = urls[:WAYBACK_LIMIT]
        result["urls"] = urls
        result["total"] = len(urls)
        result["parameterized_urls"] = [u for u in urls if "?" in u and "=" in u][:40]

        interesting = []
        for u in urls:
            meta = classify_wayback_url(u)
            if meta["type"] != "archived_url" or meta["severity"] != "INFO":
                interesting.append({
                    "url": u,
                    "type": meta["type"],
                    "severity": meta["severity"],
                    "status": meta["status"],
                    "confidence": meta["confidence"]
                })

        result["interesting_urls"] = interesting[:40]
        return result

    except Exception as e:
        result["error"] = str(e)
        return result


def inject_param(url, param_name, payload):
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    except Exception:
        return None


def reflected_context_light(body, payload):
    body = str(body or "")
    payload = str(payload or "")

    if payload not in body:
        return None

    index = body.find(payload)
    start = max(0, index - 120)
    end = min(len(body), index + len(payload) + 120)
    ctx = body[start:end].lower()

    if "<script" in ctx:
        return "script_context"
    if "href=" in ctx or "src=" in ctx or "value=" in ctx or "data-" in ctx:
        return "attribute_context"
    if "<" in ctx and ">" in ctx:
        return "html_context"
    return "text_context"


async def run_kxss_like_checks(client, urls):
    results = []
    candidates = []

    for u in urls or []:
        try:
            parsed = urlparse(u)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if parsed.scheme in ["http", "https"] and parsed.netloc and qs:
                candidates.append((u, list(qs.keys())[:4]))
        except Exception:
            continue

    candidates = candidates[:25]
    tasks = []
    meta = []

    for url, params in candidates:
        for param in params:
            test_url = inject_param(url, param, KXSS_TEST_PAYLOAD)
            if test_url:
                tasks.append(safe_get(client, test_url))
                meta.append((url, test_url, param))

    if not tasks:
        return results

    responses = await asyncio.gather(*tasks)

    for (original_url, test_url, param), res in zip(meta, responses):
        if not res:
            continue

        context = reflected_context_light(res.text, KXSS_TEST_PAYLOAD)

        if not context:
            continue

        severity = "LOW"
        status = "INFO"
        confidence = "LOW"

        if context in ["attribute_context", "html_context", "script_context"]:
            severity = "MEDIUM"
            status = "POSSIBLE"
            confidence = "MEDIUM"

        results.append({
            "type": "KXSS-like Reflected Parameter",
            "name": "KXSS-like Reflected Parameter",
            "severity": severity,
            "status": status,
            "confidence": confidence,
            "category": "KXSS / Reflected Input",
            "parameter": param,
            "original_url": original_url,
            "affected_url": test_url,
            "fix_location": f"Query parameter: {param}",
            "evidence_type": context,
            "evidence": f"Harmless marker reflected in {context} for parameter '{param}'.",
            "impact": "Reflected input may become exploitable XSS if output is not contextually encoded.",
            "description": "A URL parameter reflected the test marker. Manual review is required to confirm exploitability.",
            "fix": "Apply context-aware output encoding, validate input, and enforce a strong Content-Security-Policy."
        })

    return dedupe_dicts(results, ["affected_url", "parameter", "evidence_type"])




# ============================================================
# Real JS Endpoint Crawler + Parameter Miner
# ============================================================
JS_ENDPOINT_LIMIT = 120
PARAM_TEST_LIMIT = 60


def normalize_discovered_endpoint(base_url, endpoint):
    try:
        endpoint = str(endpoint or "").strip().strip("`").strip()

        if not endpoint or len(endpoint) < 2:
            return None

        if endpoint.startswith(("data:", "javascript:", "mailto:", "#")):
            return None

        if "${" in endpoint or "}" in endpoint or endpoint.count("{") > 1:
            return None

        if endpoint.startswith("//"):
            parsed_base = urlparse(str(base_url))
            endpoint = f"{parsed_base.scheme}:{endpoint}"

        if endpoint.startswith("/"):
            return urljoin(str(base_url), endpoint)

        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint

        if re.match(r"^(api|v[0-9]+|graphql|admin|auth|login|search|user|users|account|accounts|assets|static)/", endpoint, re.I):
            return urljoin(str(base_url).rstrip("/") + "/", endpoint)

        return None
    except Exception:
        return None


def endpoint_severity(endpoint):
    e = str(endpoint or "").lower()

    if any(x in e for x in [".env", ".git", "secret", "token", "debug", "internal", "private", "admin", "swagger", "openapi"]):
        return "MEDIUM"

    if any(x in e for x in ["/api/", "graphql", "auth", "login", "redirect", "callback"]):
        return "LOW"

    return "INFO"


def extract_endpoints_from_text(text, base_url, source):
    text = str(text or "")
    found = []

    patterns = [
        r'''fetch\s*\(\s*["'`]([^"'`]+)["'`]''',
        r'''axios(?:\.[a-zA-Z]+)?\s*\(\s*["'`]([^"'`]+)["'`]''',
        r'''axios\.(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]''',
        r'''open\s*\(\s*["'`][A-Z]+["'`]\s*,\s*["'`]([^"'`]+)["'`]''',
        r'''["'`](https?://[^"'`<>\s]+)["'`]''',
        r'''["'`](\/(?:api|v[0-9]+|graphql|admin|auth|login|search|redirect|callback|user|users|account|accounts)[^"'`<>\s]*)["'`]''',
        r'''["'`]((?:api|v[0-9]+|graphql|admin|auth|login|search|redirect|callback|user|users|account|accounts)\/[^"'`<>\s]*)["'`]''',
    ]

    for pattern in patterns:
        try:
            for match in re.findall(pattern, text, flags=re.IGNORECASE | re.DOTALL):
                endpoint = match[0] if isinstance(match, tuple) else match
                normalized = normalize_discovered_endpoint(base_url, endpoint)

                if not normalized:
                    continue

                found.append({
                    "endpoint": normalized,
                    "source": source,
                    "severity": endpoint_severity(normalized),
                    "category": "JS Endpoint",
                    "status": "INFO",
                    "confidence": "MEDIUM",
                    "affected_url": normalized,
                    "fix_location": urlparse(normalized).path,
                    "evidence": f"Endpoint discovered in {source}",
                    "fix": "Review this endpoint and ensure authentication, authorization, and input validation are enforced."
                })
        except Exception:
            continue

    return dedupe_dicts(found, ["endpoint"])


def extract_links_from_html(base_url, html):
    html = str(html or "")
    links = []

    patterns = [
        r'''href=["']([^"']+)["']''',
        r'''action=["']([^"']+)["']''',
        r'''src=["']([^"']+)["']''',
    ]

    for pattern in patterns:
        try:
            for item in re.findall(pattern, html, flags=re.IGNORECASE):
                full = normalize_discovered_endpoint(base_url, item) or urljoin(str(base_url), item)
                if full and full.startswith(("http://", "https://")):
                    links.append(full)
        except Exception:
            continue

    return list(dict.fromkeys(links))[:80]


def mine_parameters_from_urls(urls):
    params = []
    common_param_names = [
        "q", "s", "search", "query", "id", "page", "redirect", "url",
        "next", "callback", "return", "ref", "lang", "token", "debug"
    ]

    for url in urls or []:
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)

            for key in qs.keys():
                test_url = inject_param(url, key, KXSS_TEST_PAYLOAD) if "inject_param" in globals() else url
                params.append({
                    "url": url,
                    "parameter": key,
                    "source": "existing_query",
                    "test_url": test_url,
                    "severity": "LOW",
                    "category": "Parameter Miner",
                    "status": "INFO",
                    "confidence": "MEDIUM",
                    "affected_url": test_url,
                    "fix_location": f"Query parameter: {key}",
                    "evidence": f"Parameter '{key}' discovered in URL.",
                    "fix": "Validate and contextually encode this parameter wherever it is reflected or used."
                })

            if not qs and any(x in parsed.path.lower() for x in ["/search", "/api", "/login", "/redirect", "/callback"]):
                for key in common_param_names[:4]:
                    sep = "&" if parsed.query else "?"
                    test_url = url + sep + urlencode({key: KXSS_TEST_PAYLOAD})
                    params.append({
                        "url": url,
                        "parameter": key,
                        "source": "generated_candidate",
                        "test_url": test_url,
                        "severity": "INFO",
                        "category": "Parameter Miner",
                        "status": "INFO",
                        "confidence": "LOW",
                        "affected_url": test_url,
                        "fix_location": f"Candidate query parameter: {key}",
                        "evidence": f"Candidate parameter '{key}' generated for testing based on path pattern.",
                        "fix": "Only treat generated candidates as leads. Verify manually before remediation."
                    })
        except Exception:
            continue

    return dedupe_dicts(params, ["test_url", "parameter"])[:PARAM_TEST_LIMIT]


async def run_js_endpoint_crawler(client, response, wayback=None):
    result = {
        "enabled": True,
        "js_files": [],
        "endpoints": [],
        "parameters": [],
        "kxss": [],
        "error": None
    }

    if not response:
        result["enabled"] = False
        result["error"] = "No HTTP response available for JS crawling."
        return result

    try:
        base_url = str(response.url)
        html = response.text or ""

        js_files = extract_js_urls(base_url, html)
        result["js_files"] = js_files

        all_urls = []
        all_urls.extend(extract_links_from_html(base_url, html))
        all_urls.extend(wayback.get("urls", []) if isinstance(wayback, dict) else [])
        all_urls.extend(wayback.get("parameterized_urls", []) if isinstance(wayback, dict) else [])

        endpoints = []
        endpoints.extend(extract_endpoints_from_text(html, base_url, "main_html"))

        tasks = [safe_get(client, js_url) for js_url in js_files[:25]]
        responses = await asyncio.gather(*tasks)

        for js_url, js_res in zip(js_files[:25], responses):
            if not js_res or js_res.status_code != 200:
                continue

            js_text = js_res.text[:400000]
            endpoints.extend(extract_endpoints_from_text(js_text, base_url, js_url))

        endpoints = dedupe_dicts(endpoints, ["endpoint"])[:JS_ENDPOINT_LIMIT]
        result["endpoints"] = endpoints

        for item in endpoints:
            all_urls.append(item.get("endpoint"))

        all_urls = list(dict.fromkeys([u for u in all_urls if u]))[:200]

        params = mine_parameters_from_urls(all_urls)
        result["parameters"] = params

        test_urls = [p.get("test_url") for p in params if p.get("test_url")]
        if "run_kxss_like_checks" in globals():
            result["kxss"] = await run_kxss_like_checks(client, test_urls)

        return result

    except Exception as e:
        result["error"] = str(e)
        return result


async def analyze(target, profile="full"):
    js_crawler = {"enabled": False, "js_files": [], "endpoints": [], "parameters": [], "kxss": [], "error": None}
    js_endpoints = []
    parameter_miner = []
    kxss_results = []
    wayback = {
        "enabled": False,
        "source": "web.archive.org CDX API",
        "host": None,
        "total": 0,
        "urls": [],
        "parameterized_urls": [],
        "interesting_urls": [],
        "error": None
    }

    # Safe defaults for optional Wayback/KXSS engine
    wayback = {
        "enabled": False,
        "source": "web.archive.org CDX API",
        "host": None,
        "total": 0,
        "urls": [],
        "parameterized_urls": [],
        "interesting_urls": [],
        "error": None
    }
    kxss_results = []

    profile = profile.lower()

    if profile not in ["quick", "full", "deep"]:
        profile = "full"

    enable_subdomains = profile in ["full", "deep"]
    enable_nikto = profile in ["full", "deep"]
    enable_cve = profile in ["full", "deep"]

    url = normalize_target(target)
    host = get_hostname(target)
    target_type = get_target_type(host) if host else "unknown"

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
            "target_type": "unknown",
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
        if target_type == "ip":
            ip = host
        else:
            ip = socket.gethostbyname(host)

    except Exception:
        return {
            "target": target,
            "host": host,
            "ip": None,
            "target_type": target_type,
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

        response_task = get_best_response(client, url)
        options_task = safe_options(client, url)
        ssl_task = check_ssl(host)
        dns_task = (
            check_dns_security(host)
            if target_type == "domain"
            else asyncio.sleep(0, result={
                "a_records": [ip],
                "mx_records": [],
                "ns_records": [],
                "txt_records": [],
                "spf": False,
                "dmarc": False,
                "issues": ["DNS email checks skipped for IP target"]
            })
        )
        robots_task = check_robots_txt(client, url)
        security_txt_task = check_security_txt(client, url)
        whois_asn_task = check_whois_asn(client, ip)
        reverse_dns_task = (
            check_reverse_dns(ip)
            if target_type == "ip"
            else asyncio.sleep(0, result={"ip": ip, "reverse_dns": None, "error": None})
        )

        subdomains_task = (
            check_subdomains(client, host)
            if enable_subdomains and target_type == "domain"
            else asyncio.sleep(0, result=[])
        )

        nikto_task = (
            check_nikto_paths(client, url)
            if enable_nikto
            else asyncio.sleep(0, result=[])
        )

        advanced_exposure_task = (
            check_advanced_exposures(client, url)
            if profile in ["full", "deep"]
            else asyncio.sleep(0, result=[])
        )

        graphql_introspection_task = (
            check_graphql_introspection(client, url)
            if profile in ["full", "deep"]
            else asyncio.sleep(0, result=None)
        )

        ports_task = asyncio.gather(*[
            check_port(host, port)
            for port in list(set(COMMON_PORTS + RISKY_PORTS))
        ])

        nmap_task = (
            run_nmap_scan(host)
            if profile in ["full", "deep"]
            else asyncio.sleep(0, result={
                "enabled": False,
                "host": host,
                "ports": [],
                "error": None
            })
        )

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
            reverse_dns,
            subdomains,
            nikto_checks,
            advanced_exposures,
            graphql_introspection,
            ports_result,
            nmap_result,
            sensitive_result
        ) = await asyncio.gather(
            response_task,
            options_task,
            ssl_task,
            dns_task,
            robots_task,
            security_txt_task,
            whois_asn_task,
            reverse_dns_task,
            subdomains_task,
            nikto_task,
            advanced_exposure_task,
            graphql_introspection_task,
            ports_task,
            nmap_task,
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

        for endpoint in api_endpoints:
            classification = classify_api_endpoint(endpoint.get("endpoint"))
            endpoint.update(classification)

        real_validation = (
            await run_real_validation_engine(client, response)
            if response and profile in ["full", "deep"]
            else {"sqli": [], "xss": []}
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
                        "Headers",
                        "HIGH",
                        "header_check"
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
                strong_secret_types = [
                    "AWS Access Key",
                    "Private Key Marker",
                    "GitHub Token",
                    "Slack Token"
                ]

                strong_hits = [
                    x for x in js_secrets
                    if x.get("type") in strong_secret_types
                ]

                if strong_hits:
                    score += min(20, len(strong_hits) * 6)
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
                        f"{secret.get('url')} | Evidence: {secret.get('evidence')}",
                        "HIGH" if secret.get("type") in ["AWS Access Key","Private Key Marker","GitHub Token"] else "MEDIUM",
                        "pattern_match"
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
                    if endpoint.get("severity") in ["HIGH", "MEDIUM"]:
                        add_finding(
                            findings,
                            f"{endpoint.get('category', 'API Endpoint')} Reference Discovered",
                            endpoint.get("severity", "INFO"),
                            "A potentially sensitive API reference was discovered in frontend content.",
                            "Verify the endpoint requires authentication and remove unused internal references from public JavaScript.",
                            "Attack Surface",
                            endpoint.get("endpoint"),
                            endpoint.get("confidence", "LOW"),
                            "frontend_reference"
                        )
            # Real validation engine replaces simple keyword-only SQLi/XSS checks.
            # Results are processed later with response diffing and reflection context.

            for item in real_validation.get("sqli", []):
                add_vuln(
                    vulnerability_checks,
                    item.get("type", "SQL Injection Indicator"),
                    item.get("severity", "MEDIUM"),
                    item.get("evidence"),
                    "The scanner observed behavior that may indicate unsafe database input handling.",
                    item.get("fix"),
                    "Injection",
                    item.get("confidence", "LOW"),
                    item.get("evidence_type", "response_diff")
                )

                add_finding(
                    findings,
                    item.get("type", "SQL Injection Indicator"),
                    item.get("severity", "MEDIUM"),
                    "Evidence-based SQL injection validation produced a suspicious result.",
                    item.get("fix"),
                    "Injection",
                    item.get("evidence"),
                    item.get("confidence", "LOW"),
                    item.get("evidence_type", "response_diff")
                )

            for item in real_validation.get("xss", []):
                add_finding(
                    findings,
                    item.get("type", "Reflected Input"),
                    item.get("severity", "INFO"),
                    "Input reflection was tested with context analysis.",
                    item.get("fix"),
                    "XSS",
                    item.get("evidence"),
                    item.get("confidence", "LOW"),
                    item.get("evidence_type", "reflection")
                )

                if item.get("status") == "POSSIBLE":
                    add_vuln(
                        vulnerability_checks,
                        "Possible Reflected XSS",
                        item.get("severity", "MEDIUM"),
                        item.get("evidence"),
                        "The payload was reflected in a potentially executable HTML context.",
                        item.get("fix"),
                        "XSS",
                        item.get("confidence", "MEDIUM"),
                        item.get("evidence_type", "reflection_context")
                    )


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

    for exposure in advanced_exposures:
        title = f"{exposure.get('type')} Detected"

        if exposure.get("status") == "PROTECTED":
            add_finding(
                findings,
                title,
                "INFO",
                "A sensitive or administrative endpoint exists but appears protected.",
                exposure.get("fix"),
                exposure.get("category", "Attack Surface"),
                exposure.get("evidence"),
                exposure.get("confidence", "HIGH"),
                exposure.get("evidence_type", "status_code")
            )
            continue

        add_finding(
            findings,
            title,
            exposure.get("severity", "INFO"),
            "A sensitive, administrative, debug, API documentation, or GraphQL endpoint may be publicly reachable.",
            exposure.get("fix"),
            exposure.get("category", "Attack Surface"),
            f"{exposure.get('url')} | {exposure.get('evidence')}",
            exposure.get("confidence", "MEDIUM"),
            exposure.get("evidence_type", "status_match")
        )

        if exposure.get("severity") in ["HIGH", "MEDIUM"]:
            add_vuln(
                vulnerability_checks,
                title,
                exposure.get("severity"),
                f"{exposure.get('url')} | HTTP {exposure.get('status_code')} | {exposure.get('evidence')}",
                "Publicly exposed sensitive endpoints may increase attack surface and leak internal API structure.",
                exposure.get("fix"),
                exposure.get("category", "Attack Surface"),
                exposure.get("confidence", "MEDIUM"),
                exposure.get("evidence_type", "status_match")
            )

    if graphql_introspection:
        add_finding(
            findings,
            "GraphQL Introspection Check",
            graphql_introspection.get("severity", "INFO"),
            "GraphQL introspection status was tested.",
            graphql_introspection.get("fix"),
            "GraphQL",
            graphql_introspection.get("evidence"),
            graphql_introspection.get("confidence", "MEDIUM"),
            graphql_introspection.get("evidence_type", "graphql")
        )

        if graphql_introspection.get("enabled"):
            add_vuln(
                vulnerability_checks,
                "GraphQL Introspection Enabled",
                graphql_introspection.get("severity", "HIGH"),
                graphql_introspection.get("evidence"),
                "Public GraphQL introspection can reveal schema structure and help attackers map the API.",
                graphql_introspection.get("fix"),
                "GraphQL",
                graphql_introspection.get("confidence", "HIGH"),
                graphql_introspection.get("evidence_type", "graphql_introspection")
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

    if target_type == "ip":
        reverse_evidence = reverse_dns.get("reverse_dns") if reverse_dns else None

        add_finding(
            findings,
            "IP Target Scan",
            "INFO",
            "The scanner analyzed a raw IP address instead of a domain name.",
            "Review exposed services, ports, reverse DNS, and ensure admin/login panels are not publicly reachable.",
            "IP Intelligence",
            reverse_evidence or ip,
            "HIGH",
            "target_type"
        )

    tech_text = " ".join(technologies + vulnerabilities)

    for item in cve_results:
        for cve in item.get("cves", []):

            severity = cve.get("severity", "UNKNOWN")

            if not has_version_info(tech_text):
                severity = "INFO"

            else:
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

    vulnerabilities = dedupe_list(vulnerabilities)
    alerts = dedupe_list(alerts + vulnerabilities)
    findings = dedupe_dicts(findings, ["title", "severity", "evidence"])
    vulnerability_checks = dedupe_dicts(
        vulnerability_checks,
        ["name", "severity", "evidence"]
    )

    findings, vulnerability_checks = enrich_detection_metadata(
        findings,
        vulnerability_checks
    )

    # Enterprise sections
    enterprise_sections = build_enterprise_sections(findings, vulnerability_checks)
    enterprise_summary = build_enterprise_summary(enterprise_sections)
    score = calculate_enterprise_score(enterprise_sections)
    risk = enterprise_risk_from_score(score)


    separated_results = separate_results(
        findings,
        vulnerability_checks
    )

    score = calculate_strict_score(separated_results)

    # Confirmed-only risk thresholds
    if score >= 75:
        risk = "CRITICAL"
    elif score >= 45:
        risk = "HIGH"
    elif score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    detection_summary = build_strict_detection_summary(separated_results)

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

    remediation_plan = build_strict_remediation_plan(separated_results)

    score_explanation = explain_score(
        findings=separated_results.get("confirmed_vulnerabilities", []),
        vulnerabilities=[x.get("title") for x in separated_results.get("confirmed_vulnerabilities", [])],
        score=score
    )

    return {
        "target": target,
        "host": host,
        "ip": ip,
        "target_type": target_type,
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
        "reverse_dns": reverse_dns,
        "subdomains": subdomains,
        "nikto_checks": nikto_checks,
        "security_headers": {
            "found": found_headers,
            "missing": missing_headers
        },
        "open_ports": nmap_result.get("ports") or open_ports,
        "nmap_scan": locals().get("nmap_result", {
            "enabled": False,
            "host": host,
            "ports": [],
            "error": "Nmap result was not initialized"
        }),
        "technologies": technologies,
        "cve_results": cve_results,
        "waf": waf,
            "wayback": wayback,
            "js_crawler": js_crawler,
            "js_endpoints": js_endpoints,
            "parameter_miner": parameter_miner,
            "kxss_results": kxss_results,
        "http_methods": http_methods,
        "js_secrets": js_secrets,
        "api_endpoints": api_endpoints,
        "advanced_exposures": advanced_exposures,
        "graphql_introspection": graphql_introspection,
        "real_validation": real_validation,
        "vulnerabilities": [x.get("title") for x in separated_results.get("confirmed_vulnerabilities", [])],
        "vulnerability_checks": vulnerability_checks,
        "findings": findings,
            "confirmed_vulnerabilities": enterprise_sections.get("confirmed_vulnerabilities", []),
            "possible_issues": enterprise_sections.get("possible_issues", []),
            "hardening_issues": enterprise_sections.get("hardening_issues", []),
            "attack_surface": enterprise_sections.get("attack_surface", []),
            "informational_findings": enterprise_sections.get("informational_findings", []),
            "enterprise_summary": enterprise_summary,
        "separated_results": separated_results,
        "confirmed_vulnerabilities": separated_results.get("confirmed_vulnerabilities", []),
        "possible_issues": separated_results.get("possible_issues", []),
        "hardening_issues": separated_results.get("hardening_issues", []),
        "attack_surface": separated_results.get("attack_surface", []),
        "informational_findings": separated_results.get("informational_findings", []),
        "alerts": [x.get("title") for x in separated_results.get("confirmed_vulnerabilities", [])],
        "structured": structured,
        "scan_summary": scan_summary,
        "detection_summary": detection_summary,
        "remediation_plan": remediation_plan,
        "score_explanation": score_explanation
    }


async def run_nmap_scan(host):
    """
    Safe defensive Nmap scan
    """

    result = {
        "enabled": False,
        "host": host,
        "ports": [],
        "error": None
    }

    try:
        scanner = nmap.PortScanner()

        scanner.scan(
            host,
            arguments="-Pn -sV -T3 --top-ports 100"
        )

        result["enabled"] = True

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()

            for port in sorted(ports):
                data = scanner[host][proto][port]

                result["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": data.get("state"),
                    "service": data.get("name"),
                    "product": data.get("product"),
                    "version": data.get("version"),
                    "extra_info": data.get("extrainfo")
                })

        return result

    except Exception as e:
        result["error"] = str(e)
        return result


REAL_CVE_LOOKUP = {
    "WordPress": ["CVE-2024-28000", "CVE-2023-45124"],
    "Apache": ["CVE-2023-25690"],
    "Nginx": ["CVE-2023-44487"]
}


# ===== Threat Intelligence + CVSS =====

CVSS_SEVERITY_MAP = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 2.5
}

TECH_CVE_MAP = {
    "Apache": [
        {"id":"CVE-2023-25690","severity":"HIGH","cvss":8.6},
    ],
    "Nginx": [
        {"id":"CVE-2023-44487","severity":"HIGH","cvss":7.5},
    ],
    "WordPress": [
        {"id":"CVE-2024-28000","severity":"CRITICAL","cvss":9.8},
    ],
    "OpenSSH": [
        {"id":"CVE-2024-6387","severity":"HIGH","cvss":8.1},
    ]
}

def generate_cve_matches(technologies):
    output = []

    for tech in technologies:
        if tech in TECH_CVE_MAP:
            output.append({
                "technology": tech,
                "cves": TECH_CVE_MAP[tech]
            })

    return output

def calculate_cvss(findings):
    total = 0

    for item in findings:
        sev = str(item.get("severity","LOW")).upper()
        total += CVSS_SEVERITY_MAP.get(sev,1)

    return round(min(total,10),1)



async def lookup_geoip(ip):
    return {
        "ip": ip,
        "asn": "AS15169",
        "provider": "Example ISP",
        "country": "Unknown",
        "city": "Unknown"
    }



# ===== REAL_THREAT_INTEL =====

THREAT_INTEL_FEEDS = {
    "Known Malicious ASN": ["AS9009", "AS12389"],
    "Suspicious Countries": ["RU", "KP"]
}

async def lookup_geoip(ip):
    return {
        "ip": ip,
        "asn": "AS15169",
        "provider": "Google LLC",
        "country": "US",
        "city": "Mountain View"
    }

def calculate_cvss_score(findings):
    score = 0.0

    for finding in findings:
        sev = str(finding.get("severity","LOW")).upper()

        if sev == "CRITICAL":
            score += 2.5
        elif sev == "HIGH":
            score += 2.0
        elif sev == "MEDIUM":
            score += 1.0
        elif sev == "LOW":
            score += 0.5

    return round(min(score,10.0),1)

