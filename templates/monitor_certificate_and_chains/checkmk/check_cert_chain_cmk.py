#!/usr/bin/env python3
"""
check_cert_chain_cmk.py - SSL/TLS certificate and chain check (CheckMK/Nagios compatible)
Requires: openssl in PATH, Python 3.6+

SETUP (CheckMK):
  1. Copy to ~/local/lib/nagios/plugins/ on the CheckMK site server
  2. chmod +x check_cert_chain_cmk.py
  3. In CheckMK Setup: add as "Classical active check" on the relevant host
     Command: check_cert_chain_cmk.py -H $HOSTADDRESS$ -p 443

Usage: check_cert_chain_cmk.py -H <hostname> [-p <port>] [-w <warn_days>] [-c <crit_days>]

Exit codes: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN
"""

import sys
import subprocess
import re
import argparse
from datetime import datetime, timezone

CONNECT_TIMEOUT = 15

STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3
STATE_NAMES = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}


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
    stdout, stderr, _ = run_openssl(
        ["s_client", "-connect", f"{hostname}:{port}", "-showcerts", "-servername", hostname],
        stdin_bytes=b"\n",
    )
    return stdout, stderr


def extract_pem_certs(output):
    return re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        output, re.DOTALL
    )


def extract_tls_version(output):
    m = re.search(r"Protocol\s*:\s*(.+)", output)
    if m:
        return m.group(1).strip()
    m = re.search(r"New,\s*(TLSv[\d.]+|SSLv[\d.]+)", output)
    if m:
        return m.group(1).strip()
    return "unknown"


def parse_cert(pem_cert):
    stdout, _, _ = run_openssl(
        ["x509", "-text", "-noout", "-nameopt", "RFC2253,sep_comma_plus"],
        stdin_bytes=pem_cert.encode()
    )

    info = {}

    m = re.search(r"Subject:\s*(.+)", stdout)
    info["subject"] = m.group(1).strip() if m else ""

    m = re.search(r"Issuer:\s*(.+)", stdout)
    info["issuer"] = m.group(1).strip() if m else ""

    m = re.search(r"Not After\s*:\s*(.+)", stdout)
    if m:
        try:
            dt = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            dt = dt.replace(tzinfo=timezone.utc)
            info["not_after"] = dt.isoformat()
            delta = dt - datetime.now(timezone.utc)
            info["days_remaining"] = delta.days
            info["is_expired"] = delta.days < 0
        except ValueError:
            info["days_remaining"] = -999
            info["is_expired"] = True

    san_match = re.search(r"Subject Alternative Name:\s*\n\s*(.+)", stdout)
    if san_match:
        info["san"] = [
            s.strip().replace("DNS:", "")
            for s in san_match.group(1).split(",")
            if "DNS:" in s
        ]
    else:
        info["san"] = []

    info["is_ca"] = "CA:TRUE" in stdout or "CA: TRUE" in stdout
    info["is_self_signed"] = bool(
        info.get("subject") and info["subject"] == info.get("issuer")
    )

    return info


def check_hostname_match(hostname, cert_info):
    for san in cert_info.get("san", []):
        if san.startswith("*."):
            parts = hostname.split(".")
            if len(parts) >= 2 and ".".join(parts[1:]).lower() == san[2:].lower():
                return True
        elif san.lower() == hostname.lower():
            return True

    cn_m = re.search(r"CN=([^,]+)", cert_info.get("subject", ""))
    if cn_m:
        cn = cn_m.group(1).strip()
        if cn.startswith("*."):
            parts = hostname.split(".")
            if len(parts) >= 2 and ".".join(parts[1:]).lower() == cn[2:].lower():
                return True
        elif cn.lower() == hostname.lower():
            return True
    return False


def get_cn(subject):
    m = re.search(r"CN=([^,]+)", subject)
    return m.group(1).strip() if m else subject


def plugin_exit(state, summary, details=None, perfdata=None):
    perf_str = " | " + " ".join(perfdata) if perfdata else ""
    print(f"{STATE_NAMES[state]} - {summary}{perf_str}")
    if details:
        for line in details:
            print(line)
    sys.exit(state)


def main():
    parser = argparse.ArgumentParser(
        description="SSL/TLS certificate and chain check for CheckMK/Nagios"
    )
    parser.add_argument("-H", "--hostname", required=True, help="Hostname to check")
    parser.add_argument("-p", "--port", type=int, default=443, help="TCP port (default: 443)")
    parser.add_argument("-w", "--warning", type=int, default=30, help="Warning days before expiry (default: 30)")
    parser.add_argument("-c", "--critical", type=int, default=14, help="Critical days before expiry (default: 14)")
    args = parser.parse_args()

    hostname = args.hostname
    port = args.port
    warn_days = args.warning
    crit_days = args.critical

    try:
        s_client_out, s_client_err = fetch_server_chain(hostname, port)
        pem_certs = extract_pem_certs(s_client_out)

        if not pem_certs:
            err = s_client_err.lower()
            if "connection refused" in err:
                msg = f"Connection refused to {hostname}:{port}"
            elif "name or service not known" in err or "could not connect" in err:
                msg = f"DNS resolution failed for {hostname}"
            elif "timed out" in err or "timeout" in err:
                msg = f"Connection timed out to {hostname}:{port}"
            else:
                msg = f"No certificates received from {hostname}:{port}"
            plugin_exit(STATE_UNKNOWN, msg)

        tls_version = extract_tls_version(s_client_out)
        cert_infos = [parse_cert(p) for p in pem_certs]
        leaf = cert_infos[0]

        hostname_match = check_hostname_match(hostname, leaf)
        days_remaining = leaf.get("days_remaining", -999)
        is_expired = leaf.get("is_expired", True)
        is_self_signed = leaf.get("is_self_signed", False)

        depth = len(cert_infos)
        leaf_issuer = leaf.get("issuer", "")
        issuing_ca_in_chain = any(
            cert_infos[i].get("subject") == leaf_issuer for i in range(1, depth)
        )

        cn = get_cn(leaf.get("subject", hostname))

        # Evaluate issues, worst state wins
        issues = []
        state = STATE_OK

        if is_expired:
            issues.append(f"certificate EXPIRED ({abs(days_remaining)} days ago)")
            state = STATE_CRITICAL
        elif days_remaining <= crit_days:
            issues.append(f"expires in {days_remaining} days")
            state = max(state, STATE_CRITICAL)
        elif days_remaining <= warn_days:
            issues.append(f"expires in {days_remaining} days")
            state = max(state, STATE_WARNING)

        if not issuing_ca_in_chain and not is_self_signed:
            issues.append("issuing CA missing from TLS chain")
            state = max(state, STATE_CRITICAL)

        if not hostname_match:
            issues.append(f"hostname mismatch (cert CN: {cn})")
            state = max(state, STATE_CRITICAL)

        if is_self_signed:
            issues.append("self-signed certificate")
            state = max(state, STATE_WARNING)

        # Performance data (for CheckMK graphs and thresholds)
        perfdata = [
            f"days_remaining={days_remaining};{warn_days};{crit_days};;",
            f"issuing_ca_in_chain={1 if issuing_ca_in_chain else 0};;;;",
            f"hostname_match={1 if hostname_match else 0};;;;",
            f"chain_depth={depth};;;;",
        ]

        # Summary line
        if state == STATE_OK:
            summary = (
                f"{hostname}:{port} - {cn}, {days_remaining} days remaining, "
                f"chain depth={depth}, {tls_version}"
            )
        else:
            summary = f"{hostname}:{port} - {'; '.join(issues)}"

        # Detail lines (shown in CheckMK service details)
        details = [
            f"Subject:           {cn}",
            f"Issuer:            {get_cn(leaf.get('issuer', ''))}",
            f"Expires:           {leaf.get('not_after', 'unknown')} ({days_remaining} days)",
            f"TLS version:       {tls_version}",
            f"Chain depth:       {depth}",
            f"Issuing CA present: {'Yes' if issuing_ca_in_chain else 'NO - missing from handshake'}",
            f"Hostname match:    {'Yes' if hostname_match else 'NO - mismatch'}",
            "",
            "Certificate path:",
        ]
        for i, cert in enumerate(cert_infos):
            role = "leaf" if i == 0 else ("root" if cert.get("is_self_signed") else "intermediate")
            days = cert.get("days_remaining", "?")
            details.append(f"  [{i}] {get_cn(cert.get('subject', ''))} ({role}, {days} days)")

        plugin_exit(state, summary, details, perfdata)

    except TimeoutError as e:
        plugin_exit(STATE_UNKNOWN, str(e))
    except RuntimeError as e:
        plugin_exit(STATE_UNKNOWN, str(e))
    except Exception as e:
        plugin_exit(STATE_UNKNOWN, f"{type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
