# Link Checker

A Python tool that checks a URL for common phishing and suspicious patterns.

## Features

- Flags raw IP addresses, URL shorteners, and risky domain endings
- Detects suspicious words like login, verify, and bank
- Warns about unencrypted http links and lookalike (punycode) domains
- Gives a risk level with clear reasons

## Requirements

- Python 3.8 or newer
- No extra libraries needed

## Usage

```
python link_checker.py "http://example.com/login"
```

## Author

Mahmoud Orabi Elnagar
