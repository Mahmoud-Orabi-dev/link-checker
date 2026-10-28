import re
import sys
from urllib.parse import urlparse

SUSPICIOUS_WORDS = ["login", "verify", "update", "secure", "account", "bank", "free", "bonus", "password"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
RISKY_TLDS = [".xyz", ".top", ".click", ".tk", ".gq", ".ml"]


def check_url(url):
    score = 0
    reasons = []

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""

    if parsed.scheme == "http":
        score += 1
        reasons.append("Connection is not encrypted (http)")

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 3
        reasons.append("Uses a raw IP address instead of a domain")

    if "@" in url:
        score += 2
        reasons.append("Contains an @ symbol, which can hide the real destination")

    if host.count(".") >= 4:
        score += 2
        reasons.append("Too many subdomains")

    if any(host == s or host.endswith("." + s) for s in SHORTENERS):
        score += 2
        reasons.append("Uses a URL shortener")

    if any(host.endswith(t) for t in RISKY_TLDS):
        score += 2
        reasons.append("Uses a domain ending often abused by scammers")

    if host.startswith("xn--") or "xn--" in host:
        score += 3
        reasons.append("Uses punycode, possible lookalike characters")

    found = [w for w in SUSPICIOUS_WORDS if w in url.lower()]
    if found:
        score += min(len(found), 3)
        reasons.append("Contains suspicious words: " + ", ".join(found))

    if len(url) > 100:
        score += 1
        reasons.append("Unusually long URL")

    if score >= 6:
        level = "HIGH RISK"
    elif score >= 3:
        level = "SUSPICIOUS"
    else:
        level = "LOOKS OK"
    return level, score, reasons


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python link_checker.py <url>")
        sys.exit(1)
    level, score, reasons = check_url(sys.argv[1])
    print("Result:", level, "(score " + str(score) + ")")
    for r in reasons:
        print(" -", r)
