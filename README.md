# SecretScanner 🔍

**Exposed API Keys & Secrets Scanner** — For authorized security testing only.

## What it does

SecretScanner passively scans a target URL's page source and all linked JavaScript files for exposed secrets, API keys, tokens, and credentials.

### Detected Secret Types (20+)
- Stripe Keys (Publishable & Secret)
- AWS Access/Secret Keys
- GitHub Tokens
- Google API Keys
- Firebase URLs
- Slack Tokens
- Twilio/SendGrid/Mailgun Keys
- PayPal/Braintree Tokens
- Private Keys (RSA/EC/DSA/OPENSSH)
- JWT Tokens
- Database URLs (MongoDB/MySQL/PostgreSQL)
- Basic Auth in URLs
- Generic API Keys & Secrets

### Features
- Dark cyberpunk web interface
- Passive scanning only (fetches page source + JS)
- All secrets are masked in output (first 10 chars only)
- Severity classification (critical/high/medium)
- Source file and line number tracking

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Server starts on port 5001 (configurable via `PORT` env var).

## Usage

1. Open `http://localhost:5001`
2. Enter target URL
3. Click SCAN
4. Review findings

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Only scan targets you have explicit written permission to test. Unauthorized scanning may violate:
- Information Technology Act 2000 (India)
- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)

## Author

**InsafeLabs** // Built by DAXX  
GitHub: [github.com/DAXXTEAM](https://github.com/DAXXTEAM)  
Website: [InsafeLabs.in](https://insafelabs.in)
