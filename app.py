"""
SecretScanner - Exposed Secrets Detection Tool
For authorized security testing only
"""

import re
import uuid
import os
from urllib.parse import urljoin, urlparse
from flask import Flask, request, jsonify, render_template
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

SCANS = {}

SECRET_PATTERNS = {
    'Stripe Publishable Key': r'pk_(live|test)_[a-zA-Z0-9]{20,}',
    'Stripe Secret Key': r'sk_(live|test)_[a-zA-Z0-9]{20,}',
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'[a-zA-Z0-9/+=]{40}',
    'GitHub Token': r'gh[pousr]_[a-zA-Z0-9]{36,}',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Firebase URL': r'https://[a-z0-9-]+\.firebaseio\.com',
    'Slack Token': r'xox[baprs]-[0-9a-zA-Z\-]+',
    'Twilio Key': r'SK[0-9a-f]{32}',
    'SendGrid Key': r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
    'Mailgun Key': r'key-[0-9a-zA-Z]{32}',
    'PayPal/Braintree': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'Square Token': r'sq0atp-[0-9a-zA-Z\-_]{22}',
    'Private Key': r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
    'JWT Token': r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
    'Basic Auth in URL': r'https?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@',
    'MongoDB URL': r'mongodb(\+srv)?://[^\s]+',
    'MySQL/Postgres URL': r'(mysql|postgresql|postgres)://[^\s]+',
    'Generic API Key': r'[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]["\s:=]+["\']?[a-zA-Z0-9\-_]{16,}',
    'Generic Secret': r'[Ss][Ee][Cc][Rr][Ee][Tt]["\s:=]+["\']?[a-zA-Z0-9\-_]{16,}',
}

SEVERITY_MAP = {
    'Stripe Secret Key': 'critical',
    'AWS Access Key': 'critical',
    'AWS Secret Key': 'critical',
    'Private Key': 'critical',
    'GitHub Token': 'critical',
    'Stripe Publishable Key': 'high',
    'Google API Key': 'high',
    'Slack Token': 'high',
    'Twilio Key': 'high',
    'SendGrid Key': 'high',
    'Mailgun Key': 'high',
    'PayPal/Braintree': 'critical',
    'Square Token': 'high',
    'Firebase URL': 'medium',
    'JWT Token': 'medium',
    'Basic Auth in URL': 'critical',
    'MongoDB URL': 'critical',
    'MySQL/Postgres URL': 'critical',
    'Generic API Key': 'medium',
    'Generic Secret': 'medium',
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


def run_scan(url):
    findings = []
    js_files_scanned = []

    try:
        resp = requests.get(url, headers=HEADERS, timeout=15, verify=False)
        resp.raise_for_status()
        html = resp.text
    except Exception as e:
        return {'error': f'Failed to fetch URL: {str(e)}', 'findings': []}

    page_findings = scan_content(html, f'Page: {urlparse(url).path or "/"}')
    findings.extend(page_findings)

    js_urls = extract_js_urls(html, url)

    for js_url in js_urls:
        try:
            js_resp = requests.get(js_url, headers=HEADERS, timeout=10, verify=False)
            if js_resp.status_code == 200:
                js_name = urlparse(js_url).path.split('/')[-1] or js_url
                js_files_scanned.append(js_name)
                js_findings = scan_content(js_resp.text, f'JS: {js_name}')
                findings.extend(js_findings)
        except Exception:
            continue

    return {
        'findings': findings,
        'total_secrets': len(findings),
        'js_files_scanned': len(js_files_scanned),
        'js_files': js_files_scanned,
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
        url = 'https://' + url

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
