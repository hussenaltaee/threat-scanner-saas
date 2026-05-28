import asyncio
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright


SUSPICIOUS_PATTERNS = [
    "api_key",
    "apikey",
    "access_token",
    "secret",
    "client_secret",
    "bearer ",
    "authorization",
    "firebase",
    "aws_access_key",
    "private_key",
]


async def runtime_discover(target: str, timeout_ms: int = 15000) -> dict:
    result = {
        "enabled": True,
        "final_url": None,
        "title": None,
        "status": None,
        "console_errors": [],
        "network_requests": [],
        "api_endpoints": [],
        "forms": [],
        "js_files": [],
        "possible_secrets": [],
        "screenshots_supported": True,
        "error": None,
    }

    try:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-setuid-sandbox",
                ],
            )

            page = await browser.new_page(
                viewport={"width": 1366, "height": 768},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/120 Safari/537.36"
                ),
            )

            def handle_console(msg):
                if msg.type in ["error", "warning"]:
                    result["console_errors"].append({
                        "type": msg.type,
                        "text": msg.text[:300],
                    })

            async def handle_request(req):
                url = req.url
                parsed = urlparse(url)
                path = parsed.path.lower()

                item = {
                    "method": req.method,
                    "url": url[:500],
                    "resource_type": req.resource_type,
                }

                result["network_requests"].append(item)

                if (
                    "/api/" in path
                    or path.startswith("/api")
                    or "graphql" in path
                    or "rest" in path
                    or "ajax" in path
                    or "json" in path
                ):
                    result["api_endpoints"].append(item)

                if req.resource_type == "script":
                    result["js_files"].append(url[:500])

            page.on("console", handle_console)
            page.on("request", handle_request)

            response = await page.goto(
                target,
                wait_until="networkidle",
                timeout=timeout_ms,
            )

            result["final_url"] = page.url
            result["title"] = await page.title()

            if response:
                result["status"] = response.status

            html = await page.content()
            soup = BeautifulSoup(html, "html.parser")

            for form in soup.find_all("form"):
                action = form.get("action")
                method = form.get("method", "GET").upper()

                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    inputs.append({
                        "name": inp.get("name"),
                        "type": inp.get("type", inp.name),
                    })

                result["forms"].append({
                    "action": urljoin(page.url, action) if action else page.url,
                    "method": method,
                    "inputs": inputs,
                })

            lower_html = html.lower()
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in lower_html:
                    result["possible_secrets"].append({
                        "pattern": pattern,
                        "confidence": "low",
                        "note": "Pattern found in rendered HTML/JS. Manual review required.",
                    })

            await browser.close()

    except Exception as e:
        result["enabled"] = False
        result["screenshots_supported"] = False
        result["error"] = str(e)

    result["network_requests"] = result["network_requests"][:80]
    result["api_endpoints"] = result["api_endpoints"][:30]
    result["forms"] = result["forms"][:20]
    result["js_files"] = list(dict.fromkeys(result["js_files"]))[:30]
    result["console_errors"] = result["console_errors"][:20]
    result["possible_secrets"] = result["possible_secrets"][:20]

    return result