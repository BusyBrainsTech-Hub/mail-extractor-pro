#!/usr/bin/env python3

import csv
import io
import json
import re
import sqlite3
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from email.utils import parseaddr
from website_scanner import inspect_website

BASE_DIR = Path.home() / "mail-extractor"
DATA_DIR = BASE_DIR / "data"
EXPORT_DIR = BASE_DIR / "exports"
DB_PATH = DATA_DIR / "mail_extractor.db"

HOST = "127.0.0.1"
PORT = 8765
MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_FILES = 100

for folder in (DATA_DIR, EXPORT_DIR, BASE_DIR / "logs"):
    folder.mkdir(parents=True, exist_ok=True)

EMAIL_PATTERN = re.compile(
    r"(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+",
    re.IGNORECASE,
)

SUPPORTED_EXTENSIONS = {
    ".txt", ".csv", ".html", ".htm", ".log", ".md", ".json"
}

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mail Extractor Pro | BusyBrains Tech-Hub</title>
<style>
:root {
  --navy:#071629;
  --panel:#10243b;
  --panel2:#142c46;
  --gold:#e3b34c;
  --text:#edf3fa;
  --muted:#a8b7c9;
  --line:#2b4058;
  --green:#69d6a5;
}
*{box-sizing:border-box}
body{
  margin:0;background:var(--navy);color:var(--text);
  font-family:Inter,system-ui,-apple-system,sans-serif;
}
header{
  padding:24px clamp(18px,5vw,64px);
  border-bottom:1px solid var(--line);
  display:flex;justify-content:space-between;align-items:center;
  gap:18px;flex-wrap:wrap
}
.brand{font-weight:800;letter-spacing:.3px}
.brand span{color:var(--gold)}
.tag{font-size:12px;color:var(--muted)}
main{max-width:1200px;margin:auto;padding:32px 20px 60px}
h1{font-size:clamp(28px,4vw,42px);margin:0 0 10px}
h1 span{color:var(--gold)}
.intro{color:var(--muted);line-height:1.7;max-width:760px}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:28px 0}
.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px}
.stat{font-size:30px;font-weight:800;color:var(--gold);margin-top:8px}
.label{font-size:13px;color:var(--muted)}
.panel{margin-top:20px}
h2{font-size:19px;margin:0 0 16px}
button,.button{
  display:inline-block;border:0;border-radius:9px;padding:12px 16px;
  background:var(--gold);color:#172235;font-weight:800;cursor:pointer;
  text-decoration:none;font-size:14px
}
button.secondary,.button.secondary{background:var(--panel2);color:var(--text);border:1px solid var(--line)}
button.danger{background:#702e3b;color:white}
input[type=file],input[type=text],select{
  max-width:100%;width:100%;background:#091a2c;color:var(--text);
  border:1px solid var(--line);border-radius:9px;padding:12px;margin:8px 0 14px
}
input[type=checkbox]{accent-color:var(--gold)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
small,.hint{color:var(--muted);line-height:1.6}
.status{padding:12px 14px;border-radius:9px;background:#0a3029;color:var(--green);margin-top:12px}
.tablewrap{overflow:auto}
table{border-collapse:collapse;width:100%;min-width:650px}
th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--gold)}
code{color:var(--gold)}
footer{border-top:1px solid var(--line);padding:22px;text-align:center;color:var(--muted);font-size:12px}
@media(max-width:700px){.grid{grid-template-columns:1fr}header{align-items:flex-start}}
</style>
</head>
<body>
<header>
  <div class="brand">BUSYBRAINS <span>TECH-HUB</span></div>
  <div class="tag">MAIL EXTRACTOR PRO · LOCAL WORKSPACE</div>
</header>
<main>
  <h1>Extract smarter.<br><span>Organize better.</span></h1>
  <p class="intro">
    A local email-extraction workspace for files you are authorized to process.
    Extract addresses, search results, filter domains and export reports.
    Your uploaded file contents are processed on this computer.
  </p>

  <section class="grid">
    <div class="card"><div class="label">Unique email addresses</div><div class="stat" id="total">0</div></div>
    <div class="card"><div class="label">Source files recorded</div><div class="stat" id="sources">0</div></div>
    <div class="card"><div class="label">Domains found</div><div class="stat" id="domains">0</div></div>
  </section>

  <section class="panel">
    <h2>01 / Extract from files</h2>
    <form id="uploadForm">
      <label for="files">Choose local files</label>
      <input id="files" name="files" type="file" multiple required
        accept=".txt,.csv,.html,.htm,.log,.md,.json">
      <div class="hint">Supported: TXT, CSV, HTML, LOG, Markdown and JSON.
      Maximum 2 MB per file, up to 100 files per batch.</div>
      <br><button type="submit">Extract email addresses</button>
    </form>
    <div id="uploadStatus" aria-live="polite"></div>
  </section>

  <section class="panel">
    <h2>02 / Inspect an authorized website</h2>
    <p class="hint">
      Inspect a website you own or are authorized to audit. The scanner
      respects robots.txt and limits the number of pages inspected.
    </p>
    <form id="websiteForm">
      <label for="websiteUrl">Website URL</label>
      <input id="websiteUrl" type="text"
        placeholder="https://your-own-website.example" required>
      <label for="websitePages">Maximum pages</label>
      <select id="websitePages">
        <option value="1">1 page</option>
        <option value="3">3 pages</option>
        <option value="5" selected>5 pages</option>
        <option value="10">10 pages</option>
      </select>
      <button type="submit">Inspect Website</button>
    </form>
    <div id="websiteStatus" aria-live="polite"></div>
    <h2>02 / Search and filter</h2>
    <div class="row">
      <div style="flex:2;min-width:200px">
        <label for="search">Search email or source</label>
        <input id="search" type="text" placeholder="e.g. support or contacts.csv">
      </div>
      <div style="flex:1;min-width:180px">
        <label for="domain">Filter by domain</label>
        <input id="domain" type="text" placeholder="example.com">
      </div>
    </div>
    <div class="row">
      <button id="applyFilter" type="button">Apply filters</button>
      <button id="resetFilter" class="secondary" type="button">Reset</button>
      <button id="refresh" class="secondary" type="button">Refresh</button>
    </div>
  </section>

  <section class="panel">
    <h2>03 / Results</h2>
    <div class="row" style="margin-bottom:16px">
      <a class="button secondary" href="/export?format=csv">Export CSV</a>
      <a class="button secondary" href="/export?format=txt">Export TXT</a>
      <a class="button secondary" href="/export?format=json">Export JSON</a>
    </div>
    <div class="tablewrap">
      <table>
        <thead><tr><th>Email</th><th>Domain</th><th>Source</th><th>First seen (UTC)</th></tr></thead>
        <tbody id="results"><tr><td colspan="4">Loading results…</td></tr></tbody>
      </table>
    </div>
    <p class="hint" id="resultCount"></p>
  </section>

  <section class="panel">
    <h2>04 / Data controls</h2>
    <p class="hint">Clear the locally saved extraction records when you no longer need them.
    This does not delete your original files or exported reports.</p>
    <button id="clear" class="danger" type="button">Clear saved records</button>
    <div id="clearStatus" aria-live="polite"></div>
  </section>

  <p class="hint">Educational project. Only process data you are authorized to use.
  This dashboard listens on localhost and is not intended to be exposed directly to the internet.</p>
</main>
<footer>© BusyBrains Tech-Hub · Mail Extractor Pro · Educational use</footer>

<script>
const $ = id => document.getElementById(id);

async function refreshResults() {
  const params = new URLSearchParams({
    q: $('search').value.trim(),
    domain: $('domain').value.trim()
  });
  try {
    const response = await fetch('/api/results?' + params);
    const data = await response.json();
    $('total').textContent = data.stats.emails;
    $('sources').textContent = data.stats.sources;
    $('domains').textContent = data.stats.domains;
    $('resultCount').textContent = data.results.length + ' result(s) displayed.';
    const tbody = $('results');
    tbody.replaceChildren();
    if (!data.results.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 4;
      td.textContent = 'No matching results yet.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const item of data.results) {
      const tr = document.createElement('tr');
      for (const value of [item.email, item.domain, item.source, item.created_at]) {
        const td = document.createElement('td');
        td.textContent = value;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  } catch (error) {
    $('resultCount').textContent = 'Could not load results. Is the server running?';
  }
}

$('uploadForm').addEventListener('submit', async event => {
  event.preventDefault();
  const files = $('files').files;
  if (!files.length) return;
  const form = new FormData();
  for (const file of files) form.append('files', file);
  $('uploadStatus').textContent = 'Processing files…';
  try {
    const response = await fetch('/api/extract', {method:'POST', body:form});
    const data = await response.json();
    $('uploadStatus').className = response.ok ? 'status' : 'hint';
    $('uploadStatus').textContent = data.message || data.error || 'Finished.';
    await refreshResults();
  } catch (error) {
    $('uploadStatus').textContent = 'Upload failed: ' + error.message;
  }
});


$('websiteForm').addEventListener('submit', async event => {
  event.preventDefault();
  const url = $('websiteUrl').value.trim();
  const maxPages = Number($('websitePages').value);
  const status = $('websiteStatus');

  status.textContent = 'Inspecting the authorized website… Please wait.';
  try {
    const response = await fetch('/api/scan-website', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url, max_pages: maxPages})
    });
    const data = await response.json();
    status.textContent = data.message || data.error || 'Scan finished.';
    await refreshResults();
  } catch (error) {
    status.textContent = 'Scan request failed: ' + error.message;
  }
});

$('applyFilter').addEventListener('click', refreshResults);
$('refresh').addEventListener('click', refreshResults);
$('resetFilter').addEventListener('click', () => {
  $('search').value = '';
  $('domain').value = '';
  refreshResults();
});
$('search').addEventListener('keydown', e => { if (e.key === 'Enter') refreshResults(); });
$('domain').addEventListener('keydown', e => { if (e.key === 'Enter') refreshResults(); });

$('clear').addEventListener('click', async () => {
  if (!confirm('Delete all saved extraction records? This cannot be undone.')) return;
  const response = await fetch('/api/clear', {method:'POST'});
  const data = await response.json();
  $('clearStatus').textContent = data.message || data.error;
  await refreshResults();
});

refreshResults();
</script>
</body>
</html>
"""


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS emails (
            email TEXT NOT NULL,
            domain TEXT NOT NULL,
            source TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (email, source)
        )
    """)
    conn.commit()
    return conn


def extract_emails(text):
    return sorted({match.group(0).strip(".,;:!?()[]{}<>\"'").lower()
                   for match in EMAIL_PATTERN.finditer(text)})


def safe_source_name(name):
    name = Path(name.replace("\\", "/")).name
    name = re.sub(r"[^A-Za-z0-9_. -]", "_", name)
    return name[:180] or "uploaded-file"


def save_emails(source, addresses):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn = connect_db()
    added = 0
    for address in addresses:
        domain = address.rsplit("@", 1)[1].lower()
        cur = conn.execute(
            "INSERT OR IGNORE INTO emails(email, domain, source, created_at) VALUES (?, ?, ?, ?)",
            (address, domain, source, now),
        )
        added += cur.rowcount
    conn.commit()
    conn.close()
    return added


def get_stats():
    conn = connect_db()
    emails = conn.execute("SELECT COUNT(DISTINCT email) FROM emails").fetchone()[0]
    sources = conn.execute("SELECT COUNT(DISTINCT source) FROM emails").fetchone()[0]
    domains = conn.execute("SELECT COUNT(DISTINCT domain) FROM emails").fetchone()[0]
    conn.close()
    return {"emails": emails, "sources": sources, "domains": domains}


def get_results(q="", domain=""):
    conn = connect_db()
    sql = "SELECT email, domain, source, created_at FROM emails WHERE 1=1"
    params = []
    if q:
        sql += " AND (email LIKE ? OR source LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    if domain:
        sql += " AND lower(domain) = lower(?)"
        params.append(domain.lstrip("@").strip())
    sql += " ORDER BY created_at DESC, email LIMIT 2000"
    rows = [dict(row) for row in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows


class Handler(BaseHTTPRequestHandler):
    server_version = "MailExtractorPro/1.0"

    def log_message(self, fmt, *args):
        (BASE_DIR / "logs" / "server.log").open("a", encoding="utf-8").write(
            f"{datetime.now(timezone.utc).isoformat()} {self.address_string()} {fmt % args}\n"
        )

    def send_bytes(self, status, body, content_type="application/json; charset=utf-8",
                   extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, payload):
        self.send_bytes(status, json.dumps(payload).encode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self.send_bytes(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return

        if parsed.path == "/favicon.ico":
            self.send_bytes(204, b"", "image/x-icon")
            return

        if parsed.path == "/api/results":
            params = parse_qs(parsed.query)
            q = params.get("q", [""])[0][:120]
            domain = params.get("domain", [""])[0][:253]
            if domain and not re.fullmatch(r"[A-Za-z0-9.-]+", domain.lstrip("@")):
                self.send_json(400, {"error": "Enter a valid domain filter."})
                return
            self.send_json(200, {"stats": get_stats(), "results": get_results(q, domain)})
            return

        if parsed.path == "/export":
            fmt = parse_qs(parsed.query).get("format", ["csv"])[0].lower()
            if fmt not in {"csv", "txt", "json"}:
                self.send_json(400, {"error": "Supported export formats: csv, txt, json."})
                return
            rows = get_results()
            if fmt == "json":
                content = json.dumps(rows, indent=2).encode("utf-8")
                mime = "application/json; charset=utf-8"
            elif fmt == "txt":
                content = ("\n".join(row["email"] for row in rows) + ("\n" if rows else "")).encode("utf-8")
                mime = "text/plain; charset=utf-8"
            else:
                output = io.StringIO(newline="")
                writer = csv.DictWriter(output, fieldnames=["email", "domain", "source", "created_at"])
                writer.writeheader()
                writer.writerows(rows)
                content = output.getvalue().encode("utf-8-sig")
                mime = "text/csv; charset=utf-8"
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            filename = f"mail-extractor-{stamp}.{fmt}"
            self.send_bytes(200, content, mime, {
                "Content-Disposition": f'attachment; filename="{filename}"'
            })
            return

        self.send_json(404, {"error": "Not found."})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/clear":
            conn = connect_db()
            conn.execute("DELETE FROM emails")
            conn.commit()
            conn.close()
            self.send_json(200, {"message": "Saved extraction records cleared."})
            return

 
        if parsed.path == "/api/scan-website":
            if not self.client_address[0] in ("127.0.0.1", "::1"):
                self.send_json(403, {"error": "This feature is available only locally."})
                return

            content_type = self.headers.get("Content-Type", "").lower()
            if not content_type.startswith("application/json"):
                self.send_json(400, {"error": "Expected a JSON request."})
                return

            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0

            if length <= 0 or length > 4096:
                self.send_json(413, {"error": "Invalid request size."})
                return

            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                url = str(payload.get("url", "")).strip()
                max_pages = int(payload.get("max_pages", 5))

                if not url or len(url) > 2048:
                    self.send_json(400, {"error": "Enter a valid website URL."})
                    return

                if max_pages not in (1, 3, 5, 10):
                    self.send_json(400, {"error": "Choose 1, 3, 5, or 10 pages."})
                    return

                # Normalize the URL for stable database source attribution.
                if "://" not in url:
                    url = "https://" + url

                parsed_url = urlparse(url)
                if not parsed_url.hostname:
                    self.send_json(400, {"error": "Enter a valid website URL."})
                    return

                result = inspect_website(url, max_pages=max_pages)
                raw_emails = result.get("emails", [])

                # Accept scanner output as strings or records containing an email.
                if isinstance(raw_emails, dict):
                    candidates = list(raw_emails.keys())
                elif isinstance(raw_emails, list):
                    candidates = raw_emails
                else:
                    candidates = []

                addresses = set()
                for item in candidates:
                    if isinstance(item, str):
                        candidate = item
                    elif isinstance(item, dict):
                        candidate = str(item.get("email", ""))
                    elif isinstance(item, (tuple, list)) and item:
                        candidate = str(item[0])
                    else:
                        continue

                    addresses.update(extract_emails(candidate))

                source_name = "website:" + parsed_url.hostname.lower()
                added = save_emails(source_name, sorted(addresses)) if addresses else 0
                notes = result.get("notes", [])

                self.send_json(200, {
                    "message": (
                        f"Scan complete: {result.get('pages_scanned', 0)} page(s) inspected; "
                        f"{len(addresses)} address(es) found; {added} new record(s) saved."
                    ),
                    "pages_scanned": result.get("pages_scanned", 0),
                    "emails_found": len(addresses),
                    "records_added": added,
                    "notes": notes
                })
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
            except Exception:
                self.send_json(502, {
                    "error": "The website scan could not be completed. Check the URL and server log."
                })
            return

        if parsed.path != "/api/extract":
            self.send_json(404, {"error": "Not found."})
            return

        content_type = self.headers.get("Content-Type", "")
        match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;]+))", content_type)
        if not content_type.lower().startswith("multipart/form-data") or not match:
            self.send_json(400, {"error": "Please upload files using the dashboard."})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > (MAX_FILE_SIZE + 4096) * MAX_FILES:
            self.send_json(413, {"error": "Upload is empty or exceeds the batch limit."})
            return

        raw = self.rfile.read(length)
        boundary = (match.group(1) or match.group(2)).encode("utf-8")
        marker = b"--" + boundary
        parts = raw.split(marker)
        processed = 0
        total_found = 0
        total_added = 0
        errors = []

        for part in parts:
            if not part or part in (b"--\r\n", b"--"):
                continue
            if part.startswith(b"\r\n"):
                part = part[2:]
            if part.endswith(b"\r\n"):
                part = part[:-2]
            if part.endswith(b"--"):
                part = part[:-2]
            if not part or b"\r\n\r\n" not in part:
                continue

            headers, body = part.split(b"\r\n\r\n", 1)
            disposition = re.search(
                rb'Content-Disposition:\s*form-data;[^\r\n]*name="files";\s*filename="([^"]*)"',
                headers, re.IGNORECASE
            )
            if not disposition:
                continue
            if processed >= MAX_FILES:
                errors.append("The batch was limited to 100 files.")
                break

            filename = safe_source_name(disposition.group(1).decode("utf-8", "replace"))
            if Path(filename).suffix.lower() not in SUPPORTED_EXTENSIONS:
                errors.append(f"{filename}: unsupported file type.")
                continue
            if len(body) > MAX_FILE_SIZE:
                errors.append(f"{filename}: file exceeds 2 MB.")
                continue

            text = body.decode("utf-8-sig", errors="replace")
            addresses = extract_emails(text)
            added = save_emails(filename, addresses)
            processed += 1
            total_found += len(addresses)
            total_added += added

        if processed == 0:
            self.send_json(400, {"error": "No supported files were processed. " + " ".join(errors)})
            return

        message = (
            f"Processed {processed} file(s); found {total_found} unique address(es) "
            f"across those files and saved {total_added} new email/source record(s)."
        )
        if errors:
            message += " Notes: " + " ".join(errors[:8])
        self.send_json(200, {
            "message": message,
            "processed_files": processed,
            "unique_found": total_found,
            "new_records": total_added,
            "notes": errors,
        })


def main():
    connect_db().close()
    server = HTTPServer((HOST, PORT), Handler)
    print("Mail Extractor Pro is running locally.")
    print(f"Open http://{HOST}:{PORT} in Firefox.")
    print("Press Ctrl+C here to stop the server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Mail Extractor Pro.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
