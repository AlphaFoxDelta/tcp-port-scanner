# tcp-port-scanner

A threaded TCP port scanner in one Python file. No dependencies, just the
standard library.

## Why I built this

I'm finishing up a BS in Cybersecurity and I kept running into port scanners
as a concept without ever having written one. Reading about SYN scans is one
thing; actually opening sockets and watching banners come back is another. So
I built this over a weekend to learn how it really works under the hood, and
to have something concrete to show for it.

I also wanted to get comfortable with threading in Python. Turns out a port
scanner is basically the perfect excuse: you've got thousands of independent,
I/O-bound tasks and you want them all happening at once. `ThreadPoolExecutor`
does most of the heavy lifting.

## What it does

- Scans a single host (hostname or IP) across a port range
- Runs the scan across a configurable thread pool. 10,000 ports takes
  about a second on localhost with 200 workers
- Takes port specs like `80`, `1-1024`, or `22,80,443`
- Grabs banners. If a service talks first (SSH, SMTP, FTP usually do),
  you get the version string. If it waits for you to talk first (HTTP),
  you get nothing. That's normal, not a bug
- Maps common ports to service names (22 -> ssh, 443 -> https, etc.)
- Prints a plain table, and can also dump everything to JSON with `--json`

## Usage

```bash
# default: ports 1-1024
python3 port_scanner.py 192.168.1.10

# full range, more threads, shorter timeout
python3 port_scanner.py 192.168.1.10 -p 1-65535 -w 500 -t 0.5

# a few specific ports, no banner grabbing, save results
python3 port_scanner.py 127.0.0.1 -p 22,80,443 --no-banner --json results.json
```

Sample run against some test servers I spun up locally:

```
$ python3 port_scanner.py 127.0.0.1 -p 1-10000 -w 200 -t 0.5
Scan report for 127.0.0.1 (127.0.0.1)
Scanned 10000 ports in 1.21 seconds

PORT     STATE    SERVICE        BANNER
----     -----    -------        ------
2222     open     unknown        SSH-2.0-TestServer_1.0
8888     open     unknown
9999     open     unknown        FAKE-HTTP/1.0 200 OK
```

The JSON output looks like this:

```json
{
  "target": "127.0.0.1",
  "ip": "127.0.0.1",
  "ports_scanned": 10000,
  "elapsed_seconds": 1.21,
  "open_ports": [
    {"port": 2222, "state": "open", "service": "unknown", "banner": "SSH-2.0-TestServer_1.0"}
  ]
}
```

## What tripped me up

Two things, honestly.

First, banner grabbing. My first version called `recv()` with the same
timeout as the connection, and scans would just hang on ports where a
service was listening but never sent anything. I didn't get it at first:
the port was open, so why was everything stalling? Because some services
wait for you to speak first. The fix was a separate, much shorter read
timeout (capped at 2 seconds) just for the banner grab. Obvious in
hindsight.

Second, `connect()` vs `connect_ex()`. I started with `connect()` in a
try/except and the error handling got messy: connection refused, timeouts,
and unreachable hosts all raise slightly different things. `connect_ex()`
just returns 0 on success and an error code otherwise, which made the whole
function about half as long.

## What I'd do differently

- This is a full TCP connect scan, which means it finishes the handshake.
  It's noisy. Any half-decent IDS will log it. A SYN scan with scapy
  would be stealthier but needs root and a third-party library, so I
  skipped it for now.
- No UDP support. UDP scanning is slow and unreliable by nature (no
  handshake to lean on), so it'd be a different project more than a
  feature.
- The service map is hand-written and small. Pulling in nmap's
  `nmap-services` file would be more complete, but then it's not really
  "one file, zero dependencies" anymore. Trade-offs.

## A note on using this

Only scan systems you own or have explicit permission to test. I built
this to learn and to scan my own lab. Pointing it at someone else's
network without permission can get you in real legal trouble, and it's
just not worth it.
