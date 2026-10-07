#!/usr/bin/env python3
"""
TCP port scanner. Threads + stdlib only.

Scans a host, reports open ports, guesses the service, and grabs banners
when the service sends one on connect (SSH does, HTTP doesn't).

    python3 port_scanner.py 192.168.1.10 -p 1-1000
    python3 port_scanner.py 127.0.0.1 -p 22,80,443 --json out.json

Only scan stuff you own or have permission to test.
"""

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# common ports -> service names. anything else shows up as "unknown".
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle-db",
    1723: "pptp",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}


def parse_ports(spec):
    """Turn "80", "1-1024", or "22,80,443" into a sorted list of ints."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2:
                raise ValueError("malformed range %r (expected START-END)" % part)
            start, end = (int(b) for b in bounds)
            if start > end:
                raise ValueError("range start > end in %r" % part)
        else:
            start = end = int(part)
        if not 1 <= start <= 65535 or not 1 <= end <= 65535:
            raise ValueError("ports must be in 1-65535 (got %r)" % part)
        ports.update(range(start, end + 1))
    if not ports:
        raise ValueError("no valid ports in %r" % spec)
    return sorted(ports)


def scan_port(host, port, timeout, grab_banner):
    """Connect to one port. Returns a dict with port/state/service/banner."""
    result = {
        "port": port,
        "state": "closed",
        "service": COMMON_SERVICES.get(port, "unknown"),
        "banner": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        # connect_ex returns 0 on success instead of raising - easier to read
        if sock.connect_ex((host, port)) != 0:
            return result
        result["state"] = "open"
        if grab_banner:
            try:
                # some services just sit there waiting, so don't wait long
                sock.settimeout(min(timeout, 2.0))
                data = sock.recv(1024)
                if data:
                    result["banner"] = data.decode("utf-8", errors="replace").strip()
            except (socket.timeout, OSError):
                pass  # no banner, fine
    except OSError:
        pass
    finally:
        sock.close()
    return result


def resolve_host(target):
    """Hostname -> IPv4 string. Bails with exit 2 if it doesn't resolve."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        sys.stderr.write("Error: cannot resolve %r: %s\n" % (target, exc))
        sys.exit(2)


def scan(host, ports, workers, timeout, grab_banner):
    """Fan the ports out across a thread pool. Returns (open ports, seconds)."""
    started = time.monotonic()
    open_results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_port, host, port, timeout, grab_banner): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                open_results.append(result)
    elapsed = time.monotonic() - started
    open_results.sort(key=lambda r: r["port"])
    return open_results, elapsed


def print_table(target, ip, results, total_ports, elapsed):
    """Plain text table. Nothing fancy."""
    print("Scan report for %s (%s)" % (target, ip))
    print("Scanned %d ports in %.2f seconds\n" % (total_ports, elapsed))
    if not results:
        print("No open ports found.")
        return
    print("%-8s %-8s %-14s %s" % ("PORT", "STATE", "SERVICE", "BANNER"))
    print("%-8s %-8s %-14s %s" % ("----", "-----", "-------", "------"))
    for r in results:
        banner = r["banner"]
        if len(banner) > 60:
            banner = banner[:57] + "..."  # long banners wreck the table
        print("%-8d %-8s %-14s %s" % (r["port"], r["state"], r["service"], banner))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Threaded TCP port scanner. Stdlib only, no dependencies."
    )
    parser.add_argument("target", help="hostname or IPv4 address to scan")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help='ports to scan: "80", "1-1024", or "22,80,443" (default: 1-1024)',
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=100,
        help="number of scan threads (default: 100)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0,
        help="per-connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="skip banner grabbing (faster, quieter)",
    )
    parser.add_argument(
        "--json", metavar="FILE",
        help="also write results to FILE in JSON format",
    )
    args = parser.parse_args(argv)

    if args.workers < 1:
        parser.error("--workers must be >= 1")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    ip = resolve_host(args.target)

    results, elapsed = scan(
        ip, ports, args.workers, args.timeout, grab_banner=not args.no_banner
    )

    print_table(args.target, ip, results, len(ports), elapsed)

    if args.json:
        payload = {
            "target": args.target,
            "ip": ip,
            "ports_scanned": len(ports),
            "elapsed_seconds": round(elapsed, 2),
            "open_ports": results,
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print("\nResults written to %s" % args.json)


if __name__ == "__main__":
    main()
