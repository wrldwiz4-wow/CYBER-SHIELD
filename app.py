import os, re, json, csv, io, sqlite3, socket, ssl, ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote
from flask import flask, render_template, request, jsonify, send_file, Response
import requests

app = flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-development-secret")
DB_PATH = os.path.join(os.path.dirname(__file__), "cyber_shield.db")
VT_API_KEY = os.environ.get("VT_API_KEY", "")
SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "")

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account", "password", "banking",
    "confirm", "signin", "wallet", "free", "gift", "prize", "urgent",
    "payment", "support", "recover", "unlock"
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rebrand.ly"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".work", ".country", ".gq", ".tk", ".ml", ".cf"}

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, domain TEXT,
            verdict TEXT NOT NULL, score INTEGER NOT NULL, reasons TEXT,
            scanned_at TEXT NOT NULL, source TEXT DEFAULT 'single'
        )""")

def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Please enter a URL.")
    if len(raw) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters).")
    if any(ord(c) < 32 for c in raw):
        raise ValueError("URL contains control characters.")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if p.username or p.password:
        raise ValueError("URLs containing embedded usernames or passwords are not accepted.")
    try:
        host = p.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except Exception:
        raise ValueError("The domain name is invalid.")
    if not host or "." not in host and host != "localhost":
        raise ValueError("Enter a fully qualified domain name.")
    return p._replace(netloc=host + ((":" + str(p.port)) if p.port else "")).geturl(), p._replace(netloc=host)

def public_host(host):
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = sorted({x[4][0] for x in infos})
        if not ips:
            return [], "No DNS records found."
        parsed = [ipaddress.ip_address(x) for x in ips]
        if any(not ip.is_global for ip in parsed):
            return ips, "Host resolves to a private, local, or reserved IP; live checks were skipped."
        return ips, None
    except Exception as e:
        return [], f"DNS lookup failed: {str(e)[:120]}"

def ssl_check(host, port):
    ips, err = public_host(host)
    if err:
        return {"status": "Not checked", "detail": err}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ips[0], port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {"status": "Valid", "detail": f"TLS connection verified · {ssock.version()}"}
    except Exception as e:
        return {"status": "Issue detected", "detail": str(e)[:150]}

def domain_age(host):
    # Query a fixed RDAP service endpoint; never fetch a user-supplied URL.
    try:
        r = requests.get("https://rdap.org/domain/" + host, timeout=4,
                         headers={"User-Agent": "CyberShield-Student-Project/1.0"})
        if r.status_code != 200:
            return {"status": "Unavailable", "detail": "Registration date was not returned by RDAP."}
        data = r.json()
        events = data.get("events", [])
        created = next((e.get("eventDate") for e in events if e.get("eventAction") in ("registration", "created")), None)
        if not created:
            return {"status": "Unavailable", "detail": "Creation date not published."}
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        days = max(0, (datetime.now(timezone.utc) - dt).days)
        return {"status": "Available", "detail": f"Registered {days} days ago · {created[:10]}", "days": days}
    except Exception:
        return {"status": "Unavailable", "detail": "RDAP lookup timed out or was unavailable."}

def reputation_checks(url):
    results = {}
    if VT_API_KEY:
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                             headers={"x-apikey": VT_API_KEY}, timeout=6)
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                bad = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                results["VirusTotal"] = {"status": "Flagged" if bad else "No detections", "detail": f"{bad} of {sum(stats.values())} engines flagged this URL."}
            elif r.status_code == 404:
                results["VirusTotal"] = {"status": "Not found", "detail": "URL not present in the current VirusTotal report."}
            else:
                results["VirusTotal"] = {"status": "Unavailable", "detail": f"API response: {r.status_code}"}
        except Exception:
            results["VirusTotal"] = {"status": "Unavailable", "detail": "API request failed."}
    else:
        results["VirusTotal"] = {"status": "Not configured", "detail": "Add VT_API_KEY to your environment to enable this check."}

    if SAFE_BROWSING_API_KEY:
        try:
            endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + SAFE_BROWSING_API_KEY
            payload = {"client": {"clientId": "cyber-shield-student", "clientVersion": "1.0"},
                       "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                                      "platformTypes": ["ANY_PLATFORM"], " threatEntryTypes": ["URL"],
                                      "threatEntries": [{"url": url}]}}
            payload["threatInfo"]["threatEntryTypes"] = payload["threatInfo"].pop(" threatEntryTypes")
            r = requests.post(endpoint, json=payload, timeout=6)
            if r.status_code == 200:
                matches = r.json().get("matches", [])
                results["Google Safe Browsing"] = {"status": "Threat found" if matches else "No matches", "detail": f"{len(matches)} threat match(es) returned."}
            else:
                results["Google Safe Browsing"] = {"status": "Unavailable", "detail": f"API response: {r.status_code}"}
        except Exception:
            results["Google Safe Browsing"] = {"status": "Unavailable", "detail": "API request failed."}
    else:
        results["Google Safe Browsing"] = {"status": "Not configured", "detail": "Add SAFE_BROWSING_API_KEY to enable this check."}
    return results

def analyze(raw, source="single"):
    url, parsed = normalize_url(raw)
    host = parsed.hostname or ""
    reasons, score = [], 0
    lower = unquote(url).lower()
    if parsed.scheme != "https":
        score += 10; reasons.append("Uses HTTP rather than HTTPS.")
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        score += 25; reasons.append("Uses an IP address instead of a domain name.")
    if "@" in parsed.netloc:
        score += 20; reasons.append("Contains an @ symbol in the URL authority.")
    if len(url) > 100:
        score += 10; reasons.append("Unusually long URL.")
    if host.count(".") >= 4:
        score += 10; reasons.append("Contains an unusually deep subdomain.")
    if "xn--" in host:
        score += 15; reasons.append("Contains an internationalized/punycode domain.")
    found = sorted({w for w in SUSPICIOUS_WORDS if w in lower})
    if found:
        score += min(20, len(found) * 4); reasons.append("Suspicious terms found: " + ", ".join(found) + ".")
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 10; reasons.append("Uses a TLD frequently seen in abuse reports.")
    if host in SHORTENERS:
        score += 15; reasons.append("Uses a URL-shortening service; destination is hidden.")
    if re.search(r"(%[0-9a-f]{2}){4,}", lower):
        score += 10; reasons.append("Contains extensive URL encoding.")
    score = min(score, 100)
    verdict = "Malicious" if score >= 60 else ("Suspicious" if score >= 25 else "Low risk")
    ips, dns_error = public_host(host)
    live_ssl = ssl_check(host, parsed.port or (443 if parsed.scheme == "https" else 80)) if parsed.scheme == "https" else {"status": "Not applicable", "detail": "URL uses HTTP."}
    age = domain_age(host) if "." in host and not re.match(r"^\d", host) else {"status": "Unavailable", "detail": "Domain age not available for IP address."}
    intel = reputation_checks(url)
    for provider, result in intel.items():
        if result["status"] in ("Flagged", "Threat found"):
            score = min(100, score + 35)
            reasons.append(f"{provider} reported a threat.")
    verdict = "Malicious" if score >= 60 else ("Suspicious" if score >= 25 else "Low risk")
    if not reasons:
        reasons.append("No obvious heuristic indicators were found. This does not guarantee the URL is safe.")
    result = {
        "url": url, "domain": host, "verdict": verdict, "score": score, "reasons": reasons,
        "https": parsed.scheme == "https", "dns": ips, "dns_note": dns_error,
        "ssl": live_ssl, "domain_age": age, "intelligence": intel,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "disclaimer": "This is an indicator-based assessment, not a guarantee. Do not open suspicious links."
    }
    with db() as con:
        con.execute("INSERT INTO scans(url,domain,verdict,score,reasons,scanned_at,source) VALUES(?,?,?,?,?,?,?)",
                    (url, host, verdict, score, json.dumps(reasons), result["scanned_at"], source))
    return result

@app.route("/")
def index():
    with db() as con:
        total = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        malicious = con.execute("SELECT COUNT(*) FROM scans WHERE verdict='Malicious'").fetchone()[0]
        suspicious = con.execute("SELECT COUNT(*) FROM scans WHERE verdict='Suspicious'").fetchone()[0]
        recent = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 7").fetchall()
    return render_template("index.html", total=total, malicious=malicious,
                           suspicious=suspicious, safe=max(0,total-malicious-suspicious), recent=recent)

@app.post("/api/scan")
def api_scan():
    try:
        return jsonify(analyze(request.json.get("url", "")))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.exception("Scan failed")
        return jsonify({"error": "Scan could not be completed. Check the URL and try again."}), 500

@app.post("/api/bulk")
def api_bulk():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "Choose a CSV or TXT file."}), 400
    text = f.read(1_000_000).decode("utf-8-sig", errors="replace")
    rows = []
    for line in text.splitlines()[:100]:
        candidate = line.strip().split(",")[0].strip().strip('"')
        if not candidate or candidate.lower() in ("url", "urls", "website"):
            continue
        try:
            r = analyze(candidate, "bulk")
            rows.append({"url": r["url"], "verdict": r["verdict"], "score": r["score"]})
        except ValueError:
            rows.append({"url": candidate[:200], "verdict": "Invalid", "score": 0})
    return jsonify({"results": rows})

@app.get("/api/history")
def history():
    with db() as con:
        rows = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(x) for x in rows])

@app.get("/export.csv")
def export_csv():
    with db() as con:
        rows = con.execute("SELECT url,domain,verdict,score,reasons,scanned_at,source FROM scans ORDER BY id DESC").fetchall()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["URL", "Domain", "Verdict", "Risk score", "Reasons", "Scanned at", "Source"])
    for r in rows:
        writer.writerow(list(r))
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=cyber_shield_report.csv"})

@app.get("/report/<int:scan_id>")
def report(scan_id):
    with db() as con:
        row = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return "Report not found", 404
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib import colors
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        c.setFillColor(colors.HexColor("#07111f")); c.rect(0, 0, 595, 842, fill=1, stroke=0)
        c.setFillColor(colors.HexColor("#55b7ff")); c.setFont("Helvetica-Bold", 22)
        c.drawString(48, 790, "CYBER SHIELD")
        c.setFillColor(colors.white); c.setFont("Helvetica", 12)
        c.drawString(48, 760, "URL Security Analysis Report")
        c.drawString(48, 720, "URL: " + row["url"][:85])
        c.drawString(48, 695, "Domain: " + str(row["domain"]))
        c.drawString(48, 670, "Verdict: " + row["verdict"])
        c.drawString(48, 645, "Risk score: " + str(row["score"]) + "/100")
        c.drawString(48, 620, "Scanned: " + row["scanned_at"])
        c.drawString(48, 575, "Indicators:")
        y = 550
        for item in json.loads(row["reasons"] or "[]"):
            c.drawString(60, y, "- " + item[:95]); y -= 22
            if y < 70:
                c.showPage(); y = 780
        c.setFont("Helvetica-Oblique", 9)
        c.drawString(48, 45, "Indicator-based result only. A low-risk result is not a guarantee of safety.")
        c.save(); buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=f"cyber_shield_scan_{scan_id}.pdf", mimetype="application/pdf")
    except ImportError:
        return "PDF support requires reportlab. Run: pip install reportlab", 501

@app.get("/health")
def health():
    return jsonify({"status": "ok", "app": "CYBER SHIELD"})

init_db()

if __name__ == "__main__":
    app.run(debug=True)
