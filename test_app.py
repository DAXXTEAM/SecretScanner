import pytest
from app import app, scan_content, mask_value, get_severity, extract_js_urls


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_mask_value_long():
    assert mask_value('pk_test_abcdefghijklmnop') == 'pk_test_ab...'


def test_mask_value_short():
    assert mask_value('abc') == 'abc...'


def test_get_severity_critical():
    assert get_severity('Stripe Secret Key') == 'critical'
    assert get_severity('AWS Access Key') == 'critical'


def test_get_severity_high():
    assert get_severity('Google API Key') == 'high'


def test_get_severity_medium():
    assert get_severity('Generic API Key') == 'medium'


def test_get_severity_unknown():
    assert get_severity('Unknown Type') == 'medium'


def test_scan_content_stripe_key():
    # Use pk_test to avoid GitHub push protection
    content = 'var key = "pk_test_51OxxxxxFAKEFAKEFAKE";\n'
    findings = scan_content(content, 'test.js')
    assert len(findings) >= 1
    found_types = [f['type'] for f in findings]
    assert 'Stripe Publishable Key' in found_types
    stripe_finding = [f for f in findings if f['type'] == 'Stripe Publishable Key'][0]
    assert stripe_finding['masked'] is True
    assert stripe_finding['source'] == 'test.js'
    assert stripe_finding['line'] == 1
    assert stripe_finding['severity'] == 'high'
    assert '...' in stripe_finding['value']


def test_scan_content_aws_key():
    content = 'accessKeyId: "AKIAIOSFODNN7EXAMPLE"\n'
    findings = scan_content(content, 'config.js')
    found_types = [f['type'] for f in findings]
    assert 'AWS Access Key' in found_types


def test_scan_content_github_token():
    content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n'
    findings = scan_content(content, 'page')
    found_types = [f['type'] for f in findings]
    assert 'GitHub Token' in found_types


def test_scan_content_firebase():
    content = 'var url = "https://myproject-12345.firebaseio.com";\n'
    findings = scan_content(content, 'app.js')
    found_types = [f['type'] for f in findings]
    assert 'Firebase URL' in found_types


def test_scan_content_mongodb():
    content = 'const uri = "mongodb+srv://user:pass@cluster.mongodb.net/db";\n'
    findings = scan_content(content, 'db.js')
    found_types = [f['type'] for f in findings]
    assert 'MongoDB URL' in found_types


def test_scan_content_no_secrets():
    content = 'var x = 1;\nvar y = "hello";\n'
    findings = scan_content(content, 'clean.js')
    assert len(findings) == 0


def test_extract_js_urls():
    html = '''
    <html>
    <head><script src="/js/app.js"></script></head>
    <body>
    <script src="https://cdn.example.com/lib.js"></script>
    <script>var x = 1;</script>
    </body>
    </html>
    '''
    urls = extract_js_urls(html, 'https://example.com')
    assert 'https://example.com/js/app.js' in urls
    assert 'https://cdn.example.com/lib.js' in urls
    assert len(urls) == 2


def test_index_route(client):
    resp = client.get('/')
    assert resp.status_code == 200
    assert b'SecretScanner' in resp.data


def test_scan_no_url(client):
    resp = client.post('/scan', json={})
    assert resp.status_code == 400
    data = resp.get_json()
    assert 'error' in data


def test_scan_status_not_found(client):
    resp = client.get('/scan/nonexistent/status')
    assert resp.status_code == 404


def test_scan_content_private_key():
    content = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n'
    findings = scan_content(content, 'cert.pem')
    found_types = [f['type'] for f in findings]
    assert 'Private Key' in found_types


def test_scan_content_basic_auth():
    content = 'url = "https://admin:password123@api.example.com/v1"\n'
    findings = scan_content(content, 'config.js')
    found_types = [f['type'] for f in findings]
    assert 'Basic Auth in URL' in found_types
