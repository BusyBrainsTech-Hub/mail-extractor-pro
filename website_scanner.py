#!/usr/bin/env python3

import ipaddress
import re
import socket
import time

from urllib.parse import urljoin, urlparse, urldefrag
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup


EMAIL_PATTERN = re.compile(
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+",
    re.IGNORECASE,
)

USER_AGENT = "BusyBrainsContactAudit/1.0"
MAX_PAGES = 10
MAX_PAGE_BYTES = 1_000_000
REQUEST_DELAY = 1.0
TIMEOUT = 10


def validate_public_url(url):
    """Accept only HTTP(S) URLs resolving exclusively to public IPs."""
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a valid public website URL.")

    host = parsed.hostname.rstrip(".").lower()

    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Localhost URLs are not allowed.")

    if host.endswith(".local"):
        raise ValueError("Local network URLs are not allowed.")

    try:
        literal_ip = ipaddress.ip_address(host)
        addresses = [literal_ip]
    except ValueError:
        try:
            addresses = [
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(
                    host, parsed.port or (443 if parsed.scheme == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
            ]
        except (OSError, ValueError):
            raise ValueError("The website hostname could not be resolved.")

    if not addresses or any(not addr.is_global for addr in addresses):
        raise ValueError(
            "The website must resolve exclusively to public IP addresses."
        )

    return parsed


def fetch_page(session, url):
    """Fetch a bounded HTML response and reject redirects to unsafe hosts."""
    validate_public_url(url)

    response = session.get(
        url,
        timeout=TIMEOUT,
        allow_redirects=False,
        stream=True,
        headers={"Accept": "text/html,application/xhtml+xml"},
    )

    try:
        if response.is_redirect:
            return None, None

        response.raise_for_status()

        content_type = response.headers.get("Content-Type", "").lower()

        if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            return None, None

        declared_length = response.headers.get("Content-Length")

        if declared_length:
            try:
                if int(declared_length) > MAX_PAGE_BYTES:
                    return None, None
            except ValueError:
                return None, None

        chunks = []
        total = 0

        for chunk in response.iter_content(chunk_size=8192):
            total += len(chunk)

            if total > MAX_PAGE_BYTES:
                return None, None

            chunks.append(chunk)

        encoding = response.encoding or "utf-8"
        html = b"".join(chunks).decode(encoding, errors="replace")

        return html, response.url

    finally:
        response.close()


def get_domain(url):
    return urlparse(url).hostname.rstrip(".").lower()


def is_same_host(url, original_host):
    return get_domain(url) == original_host


def inspect_website(start_url, max_pages=MAX_PAGES):
    """
    Inspect a small number of public pages on one authorized website.

    Returns addresses found, source pages, and non-sensitive scan notes.
    """
    start_url = start_url.strip()

    if not start_url:
        raise ValueError("Enter a website URL.")

    if "://" not in start_url:
        start_url = "https://" + start_url

    parsed = validate_public_url(start_url)
    original_host = parsed.hostname.rstrip(".").lower()

    max_pages = max(1, min(int(max_pages), MAX_PAGES))

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    queue = [urldefrag(start_url).url]
    visited = set()
    findings = {}
    notes = []
    robots = None
    last_request = 0.0

    try:
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        try:
            response = session.get(
                robots_url,
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
            )

            try:
                if response.status_code in (404, 410):
                    # No robots file: proceed with the site's public pages.
                    robots = RobotFileParser()
                    robots.set_url(robots_url)
                    robots.parse([])
                elif response.status_code == 200:
                    content_type = response.headers.get(
                        "Content-Type", ""
                    ).lower()

                    if "text/plain" not in content_type:
                        notes.append(
                            "Could not verify robots.txt; scan stopped."
                        )
                        return {
                            "pages_scanned": 0,
                            "emails": [],
                            "notes": notes,
                        }

                    robots_text = response.raw.read(
                        MAX_PAGE_BYTES + 1,
                        decode_content=True,
                    )

                    if len(robots_text) > MAX_PAGE_BYTES:
                        notes.append(
                            "robots.txt exceeded the size limit; scan stopped."
                        )
                        return {
                            "pages_scanned": 0,
                            "emails": [],
                            "notes": notes,
                        }

                    robots = RobotFileParser()
                    robots.set_url(robots_url)
                    robots.parse(
                        robots_text.decode(
                            "utf-8", errors="replace"
                        ).splitlines()
                    )
                else:
                    notes.append(
                        f"Could not verify robots.txt (HTTP "
                        f"{response.status_code}); scan stopped."
                    )
                    return {
                        "pages_scanned": 0,
                        "emails": [],
                        "notes": notes,
                    }
            finally:
                response.close()

        except (requests.RequestException, ValueError) as exc:
            notes.append(
                f"Could not verify robots.txt ({type(exc).__name__}); "
                "scan stopped."
            )
            return {
                "pages_scanned": 0,
                "emails": [],
                "notes": notes,
            }

        while queue and len(visited) < max_pages:
            current = queue.pop(0)

            if current in visited:
                continue

            try:
                current_parsed = validate_public_url(current)
            except ValueError:
                continue

            if current_parsed.hostname.rstrip(".").lower() != original_host:
                continue

            if not robots.can_fetch(USER_AGENT, current):
                notes.append("A page was skipped according to robots.txt.")
                continue

            wait = REQUEST_DELAY - (time.monotonic() - last_request)

            if wait > 0:
                time.sleep(wait)

            try:
                html, final_url = fetch_page(session, current)
                last_request = time.monotonic()
            except (requests.RequestException, ValueError) as exc:
                notes.append(
                    f"A page could not be inspected ({type(exc).__name__})."
                )
                visited.add(current)
                continue

            visited.add(current)

            if not html or not final_url:
                continue

            if not is_same_host(final_url, original_host):
                continue

            soup = BeautifulSoup(html, "html.parser")

            # Examine visible page text and mailto links.
            page_text = soup.get_text(" ", strip=True)
            candidates = set(EMAIL_PATTERN.findall(page_text))

            for link in soup.select('a[href^="mailto:"]'):
                address = link.get("href", "").split(":", 1)[1]
                address = address.split("?", 1)[0].strip()

                if EMAIL_PATTERN.fullmatch(address):
                    candidates.add(address)

            for address in candidates:
                address = address.lower()

                findings.setdefault(address, set()).add(final_url)

            # Queue ordinary same-host links only.
            for link in soup.find_all("a", href=True):
                absolute = urldefrag(
                    urljoin(final_url, link["href"])
                ).url

                target = urlparse(absolute)

                if target.scheme not in {"http", "https"}:
                    continue

                if target.hostname and (
                    target.hostname.rstrip(".").lower() == original_host
                ):
                    if absolute not in visited and absolute not in queue:
                        queue.append(absolute)

    finally:
        session.close()

    results = []

    for address, sources in sorted(findings.items()):
        results.append({
            "email": address,
            "sources": sorted(sources),
        })

    return {
        "pages_scanned": len(visited),
        "emails": results,
        "notes": notes,
    }
