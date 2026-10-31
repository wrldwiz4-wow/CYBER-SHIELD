# CYBER SHIELD — Python Flask URL Threat Intelligence Project

A responsive cybersecurity dashboard inspired by the supplied UI references. It uses a dark navy interface, blue accents and green/yellow/red risk indicators.

## Features
- Dashboard counters, scan activity chart and risk distribution
- URL parsing and heuristic risk scoring (0–100)
- Suspicious keyword, URL length, IP-host, subdomain, punycode, encoding and TLD indicators
- Public DNS resolution with private/reserved IP safeguards
- TLS certificate validation for public HTTPS hosts
- Domain registration-age lookup through RDAP (when published)
- Optional VirusTotal and Google Safe Browsing integrations
- Bulk CSV/TXT URL scan (up to 100 lines)
- QR image decoding in the browser
- SQLite scan history, CSV export and individual PDF reports

## Run on Windows (VS Code)
1. Extract the ZIP file.
2. Open the `CYBER_SHIELD` folder in VS Code.
3. Open Terminal → New Terminal.
4. Create a virtual environment (recommended):
   ```powershell
   py -m venv venv
   .\venv\Scripts\activate
   ```
5. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
6. Start the website:
   ```powershell
   python app.py
   ```
7. Open `http://127.0.0.1:5000` in Chrome.

## Optional threat-intelligence API keys
The website works without API keys; those providers show “Not configured”.
In PowerShell, set keys for the current terminal session before starting Flask:
```powershell
$env:VT_API_KEY="your_virustotal_api_key"
$env:SAFE_BROWSING_API_KEY="your_google_safe_browsing_key"
python app.py
```
Never publish API keys to GitHub or put them in frontend JavaScript. For a deployed app, configure environment variables in the hosting provider's secret settings.

## Important limitations and safety
- A heuristic score is an indicator, not a definitive verdict. Low risk does not mean guaranteed safe.
- HTTPS only encrypts the connection; it does not prove that a site is trustworthy.
- External API results depend on API coverage, quota and availability.
- QR decoding uses a browser CDN library and therefore needs internet access.
- Live DNS/TLS checks are skipped for hosts resolving to private, local or reserved IP ranges. This is a student demonstration, not a production security service.
- Do not open suspicious links. Do not use this project to scan systems without authorization.
