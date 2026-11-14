#!/usr/bin/env python3
"""headercheck - HTTP security header and TLS certificate inspector.

Original code, stdlib only. Header set inspired by securityheaders.com's
checks; grading and implementation are ours.
"""
import argparse
import http.client
import json
import ssl
import socket
from datetime import datetime, timezone

# (header, points, why it matters)
HEADERS = [
    ("strict-transport-security", 20, "forces HTTPS on later visits"),
    ("content-security-policy", 20, "limits where scripts and frames can load from"),
    ("x-frame-options", 10, "stops clickjacking via iframes"),
    ("x-content-type-options", 10, "stops MIME sniffing"),
    ("referrer-policy", 10, "controls what the Referer header leaks"),
    ("permissions-policy", 10, "gates camera/mic/geolocation APIs"),
    ("cross-origin-opener-policy", 5, "isolates the browsing context"),
    ("cross-origin-resource-policy", 5, "limits cross-origin embedding"),
]

def analyze_headers(headers):
    """headers: dict (case-insensitive). Returns (score, grade, findings)."""
    lower = {k.lower(): v for k, v in headers.items()}
    findings = []
    got = 0
    for name, points, why in HEADERS:
        if name in lower:
            got += points
            findings.append({"header": name, "status": "present",
                             "detail": lower[name][:80]})
        else:
            findings.append({"header": name, "status": "missing", "detail": why})
    # cookie flags
    cookies = lower.get("set-cookie", "")
    if cookies:
        missing = [f for f in ("httponly", "secure", "samesite")
                   if f not in cookies.lower()]
        if missing:
            findings.append({"header": "set-cookie", "status": "weak",
                             "detail": "cookie missing flags: " + ", ".join(missing)})
        else:
            got += 10
            findings.append({"header": "set-cookie", "status": "present",
                             "detail": "Secure, HttpOnly, SameSite set"})
    score = min(100, got)
    grade = ("A" if score >= 90 else "B" if score >= 70 else
             "C" if score >= 50 else "D" if score >= 30 else "F")
    return score, grade, findings

def analyze_cert(not_after, tls_version, now=None):
    """not_after: 'Mar  5 23:59:59 2027 GMT'. Returns findings list."""
    now = now or datetime.now(timezone.utc)
    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (exp - now).days
    out = []
    if days < 0:
        out.append({"status": "bad", "detail": "certificate EXPIRED"})
    elif days < 14:
        out.append({"status": "warn", "detail": f"certificate expires in {days} days"})
    else:
        out.append({"status": "ok", "detail": f"certificate valid for {days} more days"})
    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append({"status": "bad", "detail": f"old protocol negotiated: {tls_version}"})
    else:
        out.append({"status": "ok", "detail": f"protocol: {tls_version}"})
    return out

def fetch(host, port=443, timeout=8):
    """Live fetch: returns (status, headers dict, tls info dict)."""
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    conn.request("GET", "/", headers={"User-Agent": "headercheck/1.0"})
    res = conn.getresponse()
    headers = {k: v for k, v in res.getheaders()}
    sock = conn.sock
    tls = {"version": sock.version() if sock else None,
           "cert": sock.getpeercert() if sock else None}
    res.read()
    conn.close()
    return res.status, headers, tls

def main(argv=None):
    ap = argparse.ArgumentParser(description="Security header + TLS inspector")
    ap.add_argument("host", help="host to check, e.g. example.com")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        status, headers, tls = fetch(a.host)
    except (socket.gaierror, ssl.SSLError, OSError) as e:
        print(f"could not connect to {a.host}: {e}")
        return 2
    score, grade, findings = analyze_headers(headers)
    cert_findings = []
    if tls.get("cert"):
        cert_findings = analyze_cert(tls["cert"].get("notAfter"), tls.get("version"))
    if a.json:
        print(json.dumps({"host": a.host, "http_status": status, "score": score,
                          "grade": grade, "headers": findings,
                          "tls": cert_findings}, indent=2))
    else:
        print(f"{a.host}  (HTTP {status})   header score {score}/100  grade {grade}")
        for f in findings:
            mark = {"present": "+", "missing": "-", "weak": "!"}.get(f["status"], "?")
            print(f"  [{mark}] {f['header']}: {f['status']} - {f['detail']}")
        for f in cert_findings:
            mark = {"ok": "+", "warn": "!", "bad": "-"}.get(f["status"], "?")
            print(f"  [{mark}] tls: {f['detail']}")
    return 0 if grade in "AB" else 1

if __name__ == "__main__":
    raise SystemExit(main())
