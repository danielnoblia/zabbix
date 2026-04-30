#!/usr/bin/env python3
"""
check_cert_chain.py - SSL/TLS certificate and chain monitor for Zabbix
External check script: place in the Zabbix ExternalScripts directory.
Requires: openssl in PATH, Python 3.6+

Usage: check_cert_chain.py <hostname> <port>
Output: JSON on stdout (always valid JSON, never raw exceptions)
"""

import sys
import json
import subprocess
import re
from datetime import datetime, timezone

CONNECT_TIMEOUT = 15


def run_openssl(args, stdin_bytes=None):
    try:
        result = subprocess.run(
            ["openssl"] + args,
            input=stdin_bytes,
            capture_output=True,
            timeout=CONNECT_TIMEOUT,
        )
        return (
            result.stdout.decode("utf-8", errors="replace"),
            result.stderr.decode("utf-8", errors="replace"),
            result.returncode,
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"openssl {args[0]} timed out after {CONNECT_TIMEOUT}s")
    except FileNotFoundError:
        raise RuntimeError("openssl not found in PATH")


def fetch_server_chain(hostname, port):
    """Connect to server and retrieve all presented PEM certificates plus metadata."""
    stdout, stderr, _ = run_openssl(
        [
            "s_client",
            "-connect", f"{hostname}:{port}",
            "-showcerts",
            "-servername", hostname,
        ],
        stdin_bytes=b"\n",
    )
    return stdout, stderr


def extract_pem_certs(s_client_output):
    """Return list of PEM certificate strings from openssl s_client output."""
    return re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        s_client_output,
        re.DOTALL,
    )


def extract_tls_version(s_client_output):
    """Extract negotiated TLS/SSL version from s_client output."""
    m = re.search(r"Protocol\s*:\s*(.+)", s_client_output)
    if m:
        return m.group(1).strip()
    m = re.search(r"New,\s*(TLSv[\d.]+|SSLv[\d.]+)", s_client_output)
    if m:
        return m.group(1).strip()
    return "unknown"


def parse_cert(pem_cert):
    """Parse a single PEM certificate via openssl x509 -text."""
    stdout, _, _ = run_openssl(
        ["x509", "-text", "-noout", "-nameopt", "RFC2253,sep_comma_plus"],
        stdin_bytes=pem_cert.encode(),
    )

    info = {}

    m = re.search(r"Subject:\s*(.+)", stdout)
    info["subject"] = m.group(1).strip() if m else ""

    m = re.search(r"Issuer:\s*(.+)", stdout)
    info["issuer"] = m.group(1).strip() if m else ""

    # Serial number may span multiple lines with colon-separated hex
    m = re.search(r"Serial Number:\s*\n\s*(.+)", stdout)
    if m:
        info["serial"] = m.group(1).strip().replace(":", "")
    else:
        m = re.search(r"Serial Number:\s*([0-9a-fA-F:]+)", stdout)
        info["serial"] = m.group(1).strip().replace(":", "") if m else ""

    m = re.search(r"Not Before\s*:\s*(.+)", stdout)
    if m:
        try:
            dt = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            info["not_before"] = dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            info["not_before"] = m.group(1).strip()

    m = re.search(r"Not After\s*:\s*(.+)", stdout)
    if m:
        try:
            dt = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            dt = dt.replace(tzinfo=timezone.utc)
            info["not_after"] = dt.isoformat()
            delta = dt - datetime.now(timezone.utc)
            info["days_remaining"] = delta.days
            info["is_expired"] = 1 if delta.days < 0 else 0
        except ValueError:
            info["not_after"] = m.group(1).strip()
            info["days_remaining"] = -999
            info["is_expired"] = 1

    # Subject Alternative Names
    san_match = re.search(r"Subject Alternative Name:\s*\n\s*(.+)", stdout)
    if san_match:
        san_text = san_match.group(1).strip()
        info["san"] = [
            s.strip().replace("DNS:", "")
            for s in san_text.split(",")
            if "DNS:" in s
        ]
    else:
        info["san"] = []

    info["is_ca"] = 1 if ("CA:TRUE" in stdout or "CA: TRUE" in stdout) else 0
    info["is_self_signed"] = (
        1 if (info.get("subject") and info["subject"] == info.get("issuer")) else 0
    )

    return info


def check_hostname_match(hostname, cert_info):
    """Return 1 if hostname matches any SAN or CN, 0 otherwise."""
    for san in cert_info.get("san", []):
        if san.startswith("*."):
            wildcard_domain = san[2:]
            parts = hostname.split(".")
            if len(parts) >= 2 and ".".join(parts[1:]).lower() == wildcard_domain.lower():
                return 1
        elif san.lower() == hostname.lower():
            return 1

    # Fallback: CN from subject (legacy, but still common)
    cn_m = re.search(r"CN=([^,]+)", cert_info.get("subject", ""))
    if cn_m:
        cn = cn_m.group(1).strip()
        if cn.startswith("*."):
            wildcard_domain = cn[2:]
            parts = hostname.split(".")
            if len(parts) >= 2 and ".".join(parts[1:]).lower() == wildcard_domain.lower():
                return 1
        elif cn.lower() == hostname.lower():
            return 1

    # No SANs at all and no CN match → if SANs are present, no match; CN already checked
    return 0


def get_cn(subject):
    m = re.search(r"CN=([^,]+)", subject)
    return m.group(1).strip() if m else subject


def classify_connection_error(stderr):
    err = stderr.lower()
    if "connection refused" in err:
        return "Connection refused"
    if "name or service not known" in err or "could not connect" in err or "no such host" in err:
        return "DNS resolution or connection failed"
    if "timed out" in err or "timeout" in err:
        return "Connection timed out"
    if "certificate verify failed" in err:
        return f"TLS verify failed: {stderr[:200].strip()}"
    if "ssl routines" in err:
        return f"TLS error: {stderr[:200].strip()}"
    return f"Connection failed: {stderr[:200].strip()}"


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"status": "error", "error": "Usage: check_cert_chain.py <hostname> <port>"}))
        sys.exit(1)

    hostname = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print(json.dumps({"status": "error", "error": f"Invalid port: {sys.argv[2]}"}))
        sys.exit(0)

    try:
        s_client_out, s_client_err = fetch_server_chain(hostname, port)
        pem_certs = extract_pem_certs(s_client_out)

        if not pem_certs:
            print(json.dumps({
                "status": "error",
                "error": classify_connection_error(s_client_err),
                "hostname": hostname,
                "port": port,
            }))
            return

        tls_version = extract_tls_version(s_client_out)
        cert_infos = [parse_cert(p) for p in pem_certs]
        leaf = cert_infos[0]
        leaf["hostname_match"] = check_hostname_match(hostname, leaf)

        depth = len(cert_infos)

        # Issuing CA check: the cert that directly signed the leaf must be present.
        # It must have a subject equal to the leaf's issuer field.
        leaf_issuer = leaf.get("issuer", "")
        issuing_ca_in_chain = 0
        for i in range(1, depth):
            if cert_infos[i].get("subject") == leaf_issuer:
                issuing_ca_in_chain = 1
                break

        # Chain path (human-readable summary)
        chain_path = []
        for i, cert in enumerate(cert_infos):
            role = "leaf" if i == 0 else ("root" if cert.get("is_self_signed") else "intermediate")
            chain_path.append({
                "index": i,
                "cn": get_cn(cert.get("subject", f"cert-{i}")),
                "role": role,
                "is_self_signed": cert.get("is_self_signed", 0),
            })

        result = {
            "status": "ok",
            "hostname": hostname,
            "port": port,
            "tls_version": tls_version,
            "leaf_cert": {
                "subject": leaf.get("subject", ""),
                "issuer": leaf.get("issuer", ""),
                "serial": leaf.get("serial", ""),
                "not_before": leaf.get("not_before", ""),
                "not_after": leaf.get("not_after", ""),
                "days_remaining": leaf.get("days_remaining", -999),
                "san": leaf.get("san", []),
                "hostname_match": leaf.get("hostname_match", 0),
                "is_expired": leaf.get("is_expired", 1),
                "is_self_signed": leaf.get("is_self_signed", 0),
            },
            "chain": {
                "depth": depth,
                "issuing_ca_in_chain": issuing_ca_in_chain,
                "path": chain_path,
                "certs": [
                    {
                        "index": i,
                        "subject": c.get("subject", ""),
                        "issuer": c.get("issuer", ""),
                        "not_after": c.get("not_after", ""),
                        "days_remaining": c.get("days_remaining", 0),
                        "is_ca": c.get("is_ca", 0),
                        "is_self_signed": c.get("is_self_signed", 0),
                    }
                    for i, c in enumerate(cert_infos)
                ],
            },
        }

        print(json.dumps(result))

    except TimeoutError as e:
        print(json.dumps({"status": "error", "error": str(e), "hostname": hostname, "port": port}))
    except RuntimeError as e:
        print(json.dumps({"status": "error", "error": str(e), "hostname": hostname, "port": port}))
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "hostname": hostname,
            "port": port,
        }))


if __name__ == "__main__":
    main()
