"""
SecretScanner - Exposed Secrets Detection Tool
For authorized security testing only
"""

import re
import uuid
import os
import socket
from urllib.parse import urljoin, urlparse
from flask import Flask, request, jsonify, render_template
import requests
from bs4 import BeautifulSoup

COMMON_PORTS = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 8888, 9000, 3306, 5432, 6379, 27017]

EXPOSED_FILES = [
    '/.env', '/.env.local', '/.env.production', '/.env.backup',
    '/config.json', '/config.php', '/config.js', '/wp-config.php',
    '/database.php', '/.git/config', '/backup.sql', '/phpinfo.php',
    '/api/keys', '/api/config', '/settings.json', '/app.js',
    '/main.js', '/bundle.js', '/static/js/main.chunk.js',
]

app = Flask(__name__)

SCANS = {}

SECRET_PATTERNS = {
    # Payment
    'Stripe Secret Key': r'sk_(live|test)_[a-zA-Z0-9]{20,}',
    'Stripe Publishable Key': r'pk_(live|test)_[a-zA-Z0-9]{20,}',
    'PayPal Client Secret': r'[Ee][Yy][A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    'Razorpay Key': r'rzp_(live|test)_[a-zA-Z0-9]{14,}',
    'Square Token': r'sq0atp-[0-9a-zA-Z\-_]{22}',

    # Cloud
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret': r'(?i)aws.{0,20}["\']?[0-9a-zA-Z/+=]{40}["\']?',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Firebase': r'https://[a-z0-9-]+\.firebaseio\.com',
    'Azure Key': r'[Aa]zure.{0,20}["\']?[0-9a-zA-Z+/=]{32,}["\']?',
    'GCP Service Account': r'"type": "service_account"',

    # Code/Dev
    'GitHub Token': r'gh[pousr]_[a-zA-Z0-9]{36,}',
    'GitLab Token': r'glpat-[a-zA-Z0-9\-_]{20}',
    'Heroku API Key': r'[hH]eroku.{0,20}["\']?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["\']?',

    # Communication
    'Slack Token': r'xox[baprs]-[0-9a-zA-Z\-]+',
    'Slack Webhook': r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+',
    'Discord Token': r'[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27}',
    'Telegram Bot Token': r'[0-9]{8,10}:[a-zA-Z0-9_\-]{35}',
    'Twilio': r'SK[0-9a-f]{32}',
    'SendGrid': r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
    'Mailgun': r'key-[0-9a-zA-Z]{32}',

    # Database
    'MongoDB URL': r'mongodb(\+srv)?://[^\s"\'<>]+',
    'MySQL/Postgres URL': r'(mysql|postgresql|postgres)://[^\s"\'<>]+',
    'Redis URL': r'redis://[^\s"\'<>]+',

    # Crypto
    'Private Key': r'-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----',
    'Bitcoin WIF': r'[5KL][1-9A-HJ-NP-Za-km-z]{50,51}',
    'Ethereum Private Key': r'0x[a-fA-F0-9]{64}',

    # Generic
    'JWT Token': r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
    'Basic Auth URL': r'https?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@',
    'Generic API Key': r'[Aa][Pp][Ii][_\-]?[Kk][Ee][Yy]["\s:=]+["\']?[a-zA-Z0-9\-_]{16,}',
    'Generic Secret': r'[Ss][Ee][Cc][Rr][Ee][Tt]["\s:=]+["\']?[a-zA-Z0-9\-_]{16,}',
    'Generic Token': r'[Tt][Oo][Kk][Ee][Nn]["\s:=]+["\']?[a-zA-Z0-9\-_]{16,}',
    'Generic Password': r'[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]["\s:=]+["\']?[a-zA-Z0-9\-_!@#$%]{8,}',
}

SEVERITY_MAP = {
    'Stripe Secret Key': 'critical',
    'Stripe Publishable Key': 'high',
    'PayPal Client Secret': 'critical',
    'Razorpay Key': 'critical',
    'Square Token': 'high',
    'AWS Access Key': 'critical',
    'AWS Secret': 'critical',
    'Google API Key': 'high',
    'Firebase': 'medium',
    'Azure Key': 'critical',
    'GCP Service Account': 'critical',
    'GitHub Token': 'critical',
    'GitLab Token': 'critical',
    'Heroku API Key': 'high',
    'Slack Token': 'high',
    'Slack Webhook': 'high',
    'Discord Token': 'critical',
    'Telegram Bot Token': 'high',
    'Twilio': 'high',
    'SendGrid': 'high',
    'Mailgun': 'high',
    'MongoDB URL': 'critical',
    'MySQL/Postgres URL': 'critical',
    'Redis URL': 'critical',
    'Private Key': 'critical',
    'Bitcoin WIF': 'critical',
    'Ethereum Private Key': 'critical',
    'JWT Token': 'medium',
    'Basic Auth URL': 'critical',
    'Generic API Key': 'medium',
    'Generic Secret': 'medium',
    'Generic Token': 'medium',
    'Generic Password': 'high',
}

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}


def mask_value(value):
    if len(value) <= 10:
        return value[:4] + '...'
    return value[:10] + '...'


def get_severity(secret_type):
    return SEVERITY_MAP.get(secret_type, 'medium')


def scan_content(content, source_name):
    findings = []
    lines = content.split('\n')
    for secret_type, pattern in SECRET_PATTERNS.items():
        for line_num, line in enumerate(lines, 1):
            matches = re.finditer(pattern, line)
            for match in matches:
                value = match.group(0)
                findings.append({
                    'type': secret_type,
                    'value': mask_value(value),
                    'source': source_name,
                    'line': line_num,
                    'severity': get_severity(secret_type),
                    'masked': True,
                })
    return findings


def extract_js_urls(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    js_urls = []
    for script in soup.find_all('script', src=True):
        src = script['src']
        full_url = urljoin(base_url, src)
        js_urls.append(full_url)
    return js_urls


def scan_ports(host):
    open_ports = []
    for port in COMMON_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports


def build_base_urls(host, open_ports):
    base_urls = []
    for port in open_ports:
        if port in (443, 8443):
            base_urls.append(f'https://{host}:{port}')
        elif port == 80:
            base_urls.append(f'http://{host}')
        else:
            base_urls.append(f'http://{host}:{port}')
            base_urls.append(f'https://{host}:{port}')
    return list(set(base_urls))


def check_exposed_files(base_urls):
    found = []
    for base in base_urls:
        for path in EXPOSED_FILES:
            try:
                r = requests.get(base + path, headers=HEADERS, timeout=5, verify=False, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 10:
                    content_secrets = scan_content(r.text, f'ExposedFile: {base}{path}')
                    parsed = urlparse(base)
                    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                    found.append({
                        'path': path,
                        'port': port,
                        'url': base + path,
                        'size': len(r.text),
                        'secrets_found': len(content_secrets),
                        'secrets': content_secrets,
                    })
            except Exception:
                pass
    return found


def scan_url_on_port(base_url):
    """Fetch homepage and JS files from a single base URL, return findings."""
    findings = []
    js_scanned = []
    try:
        resp = requests.get(base_url + '/', headers=HEADERS, timeout=10, verify=False)
        if resp.status_code == 200:
            html = resp.text
            page_findings = scan_content(html, f'Page: {base_url}/')
            findings.extend(page_findings)
            js_urls = extract_js_urls(html, base_url)
            for js_url in js_urls:
                try:
                    js_resp = requests.get(js_url, headers=HEADERS, timeout=8, verify=False)
                    if js_resp.status_code == 200:
                        js_name = urlparse(js_url).path.split('/')[-1] or js_url
                        js_scanned.append(js_name)
                        js_findings = scan_content(js_resp.text, f'JS: {js_name} ({base_url})')
                        findings.extend(js_findings)
                except Exception:
                    continue
    except Exception:
        pass
    return findings, js_scanned


def run_scan(url):
    findings = []
    js_files_scanned = []
    open_ports = []
    exposed_files = []

    parsed = urlparse(url)
    host = parsed.hostname or parsed.path.split('/')[0]

    # Step 1: Port scan
    open_ports = scan_ports(host)

    # Step 2: Build base URLs from open ports
    base_urls = build_base_urls(host, open_ports)

    # If no ports found via scan, still use the original URL
    if not base_urls:
        base_urls = [url.rstrip('/')]

    # Step 3: Scan homepage + JS on each open port
    for base_url in base_urls:
        port_findings, port_js = scan_url_on_port(base_url)
        findings.extend(port_findings)
        js_files_scanned.extend(port_js)

    # Step 4: Check exposed files on all open ports
    exposed_files = check_exposed_files(base_urls)

    # Collect secrets from exposed files into main findings
    for ef in exposed_files:
        findings.extend(ef.get('secrets', []))

    # Deduplicate findings by (type, value, source)
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f['type'], f['value'], f['source'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Clean exposed_files for response
    exposed_files_response = []
    for ef in exposed_files:
        exposed_files_response.append({
            'path': ef['path'],
            'port': ef['port'],
            'url': ef['url'],
            'size': ef['size'],
            'secrets_found': ef['secrets_found'],
        })

    return {
        'findings': unique_findings,
        'total_secrets': len(unique_findings),
        'js_files_scanned': len(js_files_scanned),
        'js_files': js_files_scanned,
        'open_ports': open_ports,
        'exposed_files': exposed_files_response,
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400

    url = data['url'].strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    scan_id = str(uuid.uuid4())[:8]
    SCANS[scan_id] = {'status': 'running', 'url': url}

    result = run_scan(url)

    SCANS[scan_id] = {
        'status': 'complete',
        'url': url,
        'result': result,
    }

    return jsonify({
        'scan_id': scan_id,
        'status': 'complete',
        **result,
    })


@app.route('/scan/<scan_id>/status')
def scan_status(scan_id):
    if scan_id not in SCANS:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(SCANS[scan_id])


if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
