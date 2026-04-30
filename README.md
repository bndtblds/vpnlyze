# VPNlyze

VPNlyze is a small command-line tool for analyzing OpenVPN server logs in syslog format. It lists detected VPN sessions, shows authentication status, end reason, timestamps, and session duration.

## Features

- List OpenVPN sessions from historical log files
- Show successful, failed, and unknown authentication states
- Detect common end reasons such as `AUTH_FAILED`, timeout, reset, TLS errors, and bad packet length
- Calculate session duration in `HH:MM:SS`
- Inspect or export the original log lines for a single session
- Handle reused client source ports as separate sessions
- No external dependencies; Python standard library only

## Requirements

- Python 3.9 or newer
- An OpenVPN log file in the timestamp format `YYYY:MM:DD-HH:MM:SS`

## Installation

Run directly with Python:

```bash
python3 vpnlyze.py --help
```

Optional Linux/macOS install:

```bash
cp vpnlyze.py /usr/local/bin/vpnlyze
chmod +x /usr/local/bin/vpnlyze
```

Then run:

```bash
vpnlyze /var/log/openvpn.log summary
```

## Usage

Show all detected sessions:

```bash
vpnlyze /var/log/openvpn.log summary
```

Show sessions that have no clear authentication or end status:

```bash
vpnlyze /var/log/openvpn.log summary --show-unknown
```

Filter by username:

```bash
vpnlyze /var/log/openvpn.log summary --user testuser1
```

Inspect one session by ID from the summary table:

```bash
vpnlyze /var/log/openvpn.log session --id 42
```

Inspect one session by `IP:PORT`:

```bash
vpnlyze /var/log/openvpn.log session --key 192.0.2.100:5000
```

`IP:PORT` is not always unique because clients can reuse source ports. If a key matches multiple sessions, VPNlyze prints the matching session IDs and asks you to use `--id`.

Export one session to a file:

```bash
vpnlyze /var/log/openvpn.log session --id 42 --output session_42.log
```

## Summary Output

Example:

```text
  ID  Auth      End                   User                 IP:Port                   Start                End Time             Duration
---------------------------------------------------------------------------------------------------------------------------------------
   1  success   sigusr1_ping_restart  testuser1            192.0.2.100:5000          2026:04:30-10:00:00  2026:04:30-10:30:45  00:30:45
   2  failed    auth_failed           testuser2            2001:db8::1:5001          2026:04:30-10:05:00  2026:04:30-10:05:04  00:00:04
```

Columns:

| Column | Meaning |
|--------|---------|
| `ID` | Session ID used with `session --id` |
| `Auth` | `success`, `failed`, or `unknown` |
| `End` | Detected end reason |
| `User` | Username or `-` |
| `IP:Port` | Client address and source port |
| `Start` | First timestamp assigned to the session |
| `End Time` | Last timestamp assigned to the session |
| `Duration` | Duration in `HH:MM:SS` |

Common end reasons:

| End reason | Meaning |
|------------|---------|
| `auth_failed` | Authentication failed |
| `bad_packet_length` | Bad encapsulated packet length |
| `tls_error` | TLS/SSL error |
| `timeout` | Inactivity timeout |
| `client_disconnect` | Client disconnected explicitly |
| `connection_reset` | Connection reset |
| `sigusr1_*` | OpenVPN SIGUSR1 restart reason |
| `unknown` | No clear end reason detected |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Input or parsing error, for example missing log file |
| `2` | Requested session was not found or the session key is ambiguous |

## Privacy

Do not paste real IP addresses, usernames, hostnames, certificates, or raw production logs into public issues or commits. Documentation examples use RFC 5737 / RFC 3849 test addresses.

## License

VPNlyze is released under the [MIT License](LICENSE).
