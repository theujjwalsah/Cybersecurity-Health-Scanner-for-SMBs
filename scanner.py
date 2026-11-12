import socket, ssl, datetime, os, ipaddress
import requests
import dns.resolver
from urllib.parse import urlparse

TIMEOUT = int(os.getenv("SCAN_TIMEOUT_SECONDS", "8"))

def valid_hostname(host):
    host = host.strip().lower().rstrip(".")
    if len(host) > 253 or "." not in host:
        return False
    try:
        labels = host.split(".")
        return all(1 <= len(x) <= 63 and x[0].isalnum() and x[-1].isalnum()
                   and all(c.isalnum() or c == "-" for c in x) for x in labels)
    except Exception:
        return False

def resolve_records(host, kind):
    try:
        ans = dns.resolver.resolve(host, kind, lifetime=TIMEOUT)
        return [str(x).strip('"') for x in ans]
    except Exception:
        return []

def add(findings, title, category, severity, description, evidence, recommendation):
    findings.append(dict(title=title, category=category, severity=severity,
                         description=description, evidence=evidence,
                         recommendation=recommendation))

def ensure_public_host(host):
    """Prevent the scanner from targeting localhost or private network addresses."""
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ValueError("The domain no longer resolves to a public address.") from exc
    if not addresses or any(not ipaddress.ip_address(addr).is_global for addr in addresses):
        raise ValueError("The domain resolves to a non-public address and cannot be scanned.")
    return sorted(addresses)

def run_scan(host):
    ensure_public_host(host)
    findings = []
    # DNS / address visibility
    a_records = resolve_records(host, "A")
    aaaa_records = resolve_records(host, "AAAA")
    mx_records = resolve_records(host, "MX")
    if not a_records and not aaaa_records:
        add(findings, "No public address record found", "DNS", "medium",
            "The domain did not return an A or AAAA record during this check.",
            "A and AAAA lookups returned no records.",
            "Confirm the domain's DNS hosting and publish the correct address records.")
    # SPF
    txt = resolve_records(host, "TXT")
    spf = [x for x in txt if x.lower().startswith("v=spf1")]
    if not spf:
        add(findings, "SPF record not detected", "Email security", "high",
            "No SPF policy was found at the domain apex. This can make it harder for receivers to identify authorized senders.",
            "TXT lookup contained no v=spf1 record.",
            "Publish an SPF TXT record that lists only your legitimate email-sending services. Avoid multiple SPF records.")
    # DMARC
    dmarc = resolve_records("_dmarc." + host, "TXT")
    dmarc_policy = [x for x in dmarc if x.lower().startswith("v=dmarc1")]
    if not dmarc_policy:
        add(findings, "DMARC record not detected", "Email security", "high",
            "A DMARC policy was not found at _dmarc." + host + ".",
            "TXT lookup at _dmarc returned no DMARC record.",
            "Create a DMARC TXT record. Start with p=none and reporting, then move toward quarantine/reject after validating legitimate mail flows.")
    elif not any("p=reject" in x.lower() or "p=quarantine" in x.lower() for x in dmarc_policy):
        add(findings, "DMARC enforcement policy is not enabled", "Email security", "medium",
            "The DMARC record appears to use monitoring-only policy.",
            "; ".join(dmarc_policy),
            "Review DMARC aggregate reports and consider moving to quarantine or reject when safe.")
    # DNSSEC
    ds = resolve_records(host, "DS")
    if not ds:
        add(findings, "DNSSEC could not be confirmed", "DNS", "low",
            "A DS record was not returned for this domain by the resolver.",
            "DS lookup returned no records; registrar/parent-zone status may affect this result.",
            "Check DNSSEC support with your registrar and DNS provider, then enable signing and publish the DS record if appropriate.")
    # HTTPS and headers
    response = None
    try:
        # Do not follow redirects: a redirect could point the scanner at an internal host.
        response = requests.get("https://" + host, timeout=TIMEOUT, allow_redirects=False,
                                headers={"User-Agent": "CyberHealth-SMB-Scanner/1.0"})
        headers = {k.lower(): v for k, v in response.headers.items()}
        if response.url.lower().startswith("https://"):
            pass
        for h, label, sev, rec in [
            ("strict-transport-security", "HSTS header missing", "medium", "Enable Strict-Transport-Security after confirming all relevant subdomains support HTTPS."),
            ("content-security-policy", "Content Security Policy missing", "low", "Define a Content-Security-Policy appropriate to your application; begin in report-only mode if needed."),
            ("x-content-type-options", "X-Content-Type-Options missing", "low", "Set X-Content-Type-Options: nosniff."),
            ("referrer-policy", "Referrer-Policy missing", "low", "Set a restrictive Referrer-Policy such as strict-origin-when-cross-origin.")
        ]:
            if h not in headers:
                add(findings, label, "HTTP security", sev,
                    "The HTTPS response did not include the " + h + " response header.",
                    "GET " + response.url + " returned HTTP " + str(response.status_code) + "; header absent.",
                    rec)
    except requests.exceptions.SSLError as e:
        add(findings, "TLS certificate validation failed", "TLS/SSL", "critical",
            "The HTTPS connection failed certificate validation.",
            str(e)[:500],
            "Install a valid certificate for the hostname, include the complete certificate chain, and verify renewal automation.")
    except requests.exceptions.RequestException as e:
        add(findings, "HTTPS endpoint could not be reached", "HTTPS", "medium",
            "The scanner could not complete an HTTPS request. This may be caused by network policy or an unavailable web service.",
            str(e)[:500],
            "Confirm that the domain is intended to serve HTTPS and that the service is publicly reachable.")
    # TLS certificate metadata
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days = (expiry - datetime.datetime.utcnow()).days
                if days < 30:
                    add(findings, "TLS certificate expires soon", "TLS/SSL", "high" if days < 7 else "medium",
                        "The certificate has " + str(days) + " day(s) remaining.",
                        "Certificate notAfter: " + cert["notAfter"],
                        "Renew the certificate and confirm automatic renewal is configured.")
    except Exception:
        # TLS failures are also surfaced by HTTPS check where possible.
        pass

    weights = {"critical": 25, "high": 12, "medium": 6, "low": 2}
    deduction = sum(weights.get(f["severity"], 0) for f in findings)
    score = max(0, min(100, 100 - deduction))
    return {"score": score, "findings": findings, "checked_at": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": {"a_records": a_records, "aaaa_records": aaaa_records, "mx_records": mx_records,
                        "spf": spf, "dmarc": dmarc_policy}}
