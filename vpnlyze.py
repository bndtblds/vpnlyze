#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPNlyze - OpenVPN Session Analyzer

Copyright (c) 2026 bndtblds
Licensed under the MIT License.

Analyze OpenVPN syslog files and extract sessions, authentication results,
end reasons, and durations.

Usage:
  vpnlyze <logfile> summary [--user USER] [--show-unknown]
  vpnlyze <logfile> session --id <ID> [--output file]
  vpnlyze <logfile> session --key <IP:PORT>

Features:
  - Extract sessions from OpenVPN log files
  - Calculate session duration (HH:MM:SS)
  - Track authentication result (success/failed/unknown)
  - Detect end reasons (timeout, auth_failed, TLS errors, etc.)
  - Inspect or export one complete session
  - Filter by username
"""

import argparse
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set


__author__ = "bndtblds"
__license__ = "MIT"


# ============================================================================
# DATA MODEL: Session class
# ============================================================================

@dataclass
class Session:
    """Represents one OpenVPN session.
    
    Attributes:
        session_id: Unique number in discovery order
        key: IP:PORT display key for the connection, not globally unique
        ip: Client IP address
        port: Client source port
        user: Session username
        cn: Certificate name from the TLS handshake
        auth_result: Authentication result (success/failed/unknown)
        end_reason: Session end reason (timeout, reset, etc.)
        end_details: Additional end reason details
        start_ts: First assigned log timestamp (YYYY:MM:DD-HH:MM:SS)
        end_ts: Last assigned log timestamp (YYYY:MM:DD-HH:MM:SS)
        start_line_no: First assigned source line number
        end_line_no: Last assigned source line number
        lines: Original log lines assigned to this session
    """
    session_id: int
    key: str
    ip: str
    port: str
    user: Optional[str] = None
    cn: Optional[str] = None
    auth_result: str = "unknown"    # success | failed | unknown
    end_reason: str = "unknown"     # See set_end_reason() for priorities.
    end_details: Optional[str] = None
    start_ts: Optional[str] = None
    end_ts: Optional[str] = None
    start_line_no: Optional[int] = None
    end_line_no: Optional[int] = None
    lines: List[str] = field(default_factory=list)


# ============================================================================
# REGEX PATTERNS: log line detection
# ============================================================================
# These patterns detect OpenVPN events in syslog lines.
# Format: YYYY:MM:DD-HH:MM:SS ... openvpn[PID]: <Event-Details>

RE_IP = r'(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+)'
RE_ENDPOINT = rf'(?P<ip>{RE_IP}):(?P<port>\d+)'
RE_AF_ENDPOINT = rf'\[AF_INET6?\]{RE_ENDPOINT}'

RE_LINE_PREFIX = re.compile(
    r'^(?P<ts>\d{4}:\d{2}:\d{2}-\d{2}:\d{2}:\d{2}) .*? openvpn\[\d+\]: (?P<rest>.*)$'
)

RE_IP_PORT_AT_START = re.compile(
    rf'^{RE_ENDPOINT}'
)

# TCP handshake start
RE_TCP_ESTABLISHED = re.compile(
    rf'TCP connection established with {RE_AF_ENDPOINT}'
)

# TLS handshake complete, CN detected
RE_PEER_INITIATED = re.compile(
    rf'\[(?P<cn>[^\]]+)\] Peer Connection Initiated with {RE_AF_ENDPOINT}'
)

# Username/password authentication requested
RE_AUTH_DEFERRED = re.compile(
    rf"{RE_ENDPOINT}.*?Username/Password authentication deferred for username '(?P<user>[^']+)'"
)

# Successful login event
RE_CONNECTION_STARTED = re.compile(
    r'event="Connection started".*?username="(?P<user>[^"]+)".*?srcip="(?P<ip>[^"]+)"'
)

# User/IP:Port combination
RE_USER_IP_PORT = re.compile(
    rf'^(?P<user>[^/\s]+)/{RE_ENDPOINT}'
)

# Authentication failed
RE_AUTH_FAILED = re.compile(
    rf"{RE_ENDPOINT}.*?SENT CONTROL \[(?P<user>[^\]]+)\]: 'AUTH_FAILED'"
)

# Connection reset
RE_CONN_RESET = re.compile(
    rf'{RE_ENDPOINT}.*?Connection reset'
)

# SIGUSR1 received (restart/reload)
RE_SIGUSR1 = re.compile(
    rf'{RE_ENDPOINT}.*?SIGUSR1\[soft,(?P<reason>[^\]]+)\]'
)

# Inactivity timeout
RE_INACTIVITY = re.compile(
    rf'{RE_ENDPOINT}.*?Inactivity timeout'
)

# Explicit client disconnect
RE_EXPLICIT_EXIT = re.compile(
    rf'{RE_ENDPOINT}.*?(Connection, Client disconnected|client-instance exiting)'
)

# TLS/SSL error
RE_TLS_ERROR = re.compile(
    rf'{RE_ENDPOINT}.*?TLS Error'
)

# Packet length error, often caused by network issues
RE_BAD_PACKET_LENGTH = re.compile(
    rf'{RE_ENDPOINT}.*?Bad encapsulated packet length'
)


# ============================================================================
# HELPERS
# ============================================================================

def make_key(ip: str, port: str) -> str:
    """Build the IP:Port display key for a connection."""
    return f"{ip}:{port}"


def create_session(
    sessions_in_order: List[Session],
    ip: str,
    port: str,
) -> Session:
    """Create a new session instance.
    
    Args:
        sessions_in_order: List preserving discovery order
        ip: Client IP address
        port: Client source port
    
    Returns:
        Newly created session object
    """
    sess = Session(
        session_id=len(sessions_in_order) + 1,
        key=make_key(ip, port),
        ip=ip,
        port=port,
    )
    sessions_in_order.append(sess)
    return sess


def get_active_session(
    active_sessions_by_key: Dict[str, Session],
    sessions_in_order: List[Session],
    ip: str,
    port: str,
) -> Session:
    """Find the currently active session by IP:Port or create a new one.
    
    TCP source ports can be reused later in the same log file. Therefore a TCP
    connection start always creates a new session, while follow-up events use the
    most recent active session for the same IP:Port.
    """
    key = make_key(ip, port)
    if key not in active_sessions_by_key:
        active_sessions_by_key[key] = create_session(sessions_in_order, ip, port)
    return active_sessions_by_key[key]


def is_pending_login_candidate(session: Session, ip: str, user: str) -> bool:
    """Return whether a session is plausible for a portless login event."""
    if session.ip != ip:
        return False
    if session.auth_result == "success" or session.end_reason != "unknown":
        return False
    return session.user is None or session.user.lower() == user.lower()


def attach_line(
    session: Session,
    line: str,
    ts: str,
    line_no: int,
    store_line: bool = True,
) -> None:
    """Attach a log line to a session and update timestamps.
    
    Args:
        session: Session object
        line: Original log line
        ts: Timestamp from the log line
        line_no: Source file line number
        store_line: Store original line for detail view/export
    """
    if session.start_ts is None:
        session.start_ts = ts
        session.start_line_no = line_no
    session.end_ts = ts
    session.end_line_no = line_no
    if store_line:
        session.lines.append(line)


def set_end_reason(session: Session, reason: str, details: Optional[str] = None) -> None:
    """Set end reason while respecting priority.
    
    Prevents low-value reasons (for example connection_reset) from overwriting
    higher-value reasons (for example auth_failed).
    
    Priority from low to high:
        0: unknown
        1: connection_reset, sigusr1_connection_reset
        2: client_disconnect  
        3: timeout, sigusr1_ping_restart
        4: tls_error, sigusr1_tls_error
        5: bad_packet_length
        6: auth_failed (highest priority)
    
    Args:
        session: Session object
        reason: New end reason
        details: Optional additional details
    """
    priority = {
        "unknown": 0,
        "connection_reset": 1,
        "sigusr1_connection_reset": 1,
        "client_disconnect": 2,
        "timeout": 3,
        "sigusr1_ping_restart": 3,
        "tls_error": 4,
        "sigusr1_tls_error": 4,
        "bad_packet_length": 5,
        "auth_failed": 6,
    }

    current = priority.get(session.end_reason, 0)
    new = priority.get(reason, 0)

    if new >= current:
        session.end_reason = reason
        session.end_details = details


def calculate_duration(start_ts: Optional[str], end_ts: Optional[str]) -> str:
    """Calculate session duration between two timestamps.
    
    Args:
        start_ts: Start timestamp (format: YYYY:MM:DD-HH:MM:SS)
        end_ts: End timestamp (format: YYYY:MM:DD-HH:MM:SS)
    
    Returns:
        Formatted duration as HH:MM:SS, or "-" if unavailable.
    
    Example:
        calculate_duration("2025:04:21-10:00:00", "2025:04:21-10:30:45")
        → "00:30:45"
    """
    if not start_ts or not end_ts:
        return "-"
    
    try:
        fmt = "%Y:%m:%d-%H:%M:%S"
        start = datetime.strptime(start_ts, fmt)
        end = datetime.strptime(end_ts, fmt)
        
        delta = end - start
        total_seconds = int(delta.total_seconds())
        
        if total_seconds < 0:
            return "-"  # End before start should not happen.
        
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    except (ValueError, Exception):
        return "-"  # Fallback for invalid timestamp formats.


# ============================================================================
# LOG PARSER
# ============================================================================

def parse_log(
    path: Path,
    store_lines: bool = True,
    store_session_ids: Optional[Set[int]] = None,
) -> List[Session]:
    """Parse an OpenVPN syslog file and extract all sessions.
    
    Reads the log file line by line, detects OpenVPN events via regex, and
    creates session objects with metadata (user, auth result, end reason, etc.).
    
    Args:
        path: Path to the openvpn.log file
        store_lines: Store original log lines in session objects
        store_session_ids: Optional set of session IDs to store lines for
    
    Returns:
        Session objects sorted by discovery order
    
    Processed events:
        - TCP connection established
        - Peer Connection Initiated (CN extraction)
        - Username/Password deferred
        - Connection started (successful login)
        - AUTH_FAILED (failed login)
        - Connection reset
        - SIGUSR1 (Signal)
        - Inactivity timeout
        - Client disconnected
        - TLS Error
        - Bad packet length
    """
    active_sessions_by_key: Dict[str, Session] = {}
    sessions_in_order: List[Session] = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")

            m_prefix = RE_LINE_PREFIX.match(line)
            if not m_prefix:
                continue

            ts = m_prefix.group("ts")
            rest = m_prefix.group("rest")

            touched_session: Optional[Session] = None

            # TCP connection established
            m = RE_TCP_ESTABLISHED.search(rest)
            if m:
                touched_session = create_session(
                    sessions_in_order, m.group("ip"), m.group("port")
                )
                active_sessions_by_key[touched_session.key] = touched_session

            # Peer Connection Initiated + CN
            m = RE_PEER_INITIATED.search(rest)
            if m:
                touched_session = get_active_session(
                    active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                )
                touched_session.cn = m.group("cn")
                if not touched_session.user:
                    touched_session.user = m.group("cn")

            # Username/Password authentication deferred
            m = RE_AUTH_DEFERRED.search(rest)
            if m:
                touched_session = get_active_session(
                    active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                )
                touched_session.user = m.group("user")

            # user/ip:port lines
            m = RE_USER_IP_PORT.search(rest)
            if m:
                touched_session = get_active_session(
                    active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                )
                if not touched_session.user:
                    touched_session.user = m.group("user")

            # Successful login
            m = RE_CONNECTION_STARTED.search(rest)
            if m:
                ip = m.group("ip")
                user = m.group("user")

                candidate = None
                for sess in reversed(sessions_in_order):
                    if is_pending_login_candidate(sess, ip, user):
                        candidate = sess
                        break

                if candidate is None:
                    candidate = create_session(sessions_in_order, ip, "unknown")

                touched_session = candidate
                touched_session.user = user
                touched_session.auth_result = "success"

            # Failed login
            m = RE_AUTH_FAILED.search(rest)
            if m:
                touched_session = get_active_session(
                    active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                )
                touched_session.user = m.group("user")
                touched_session.auth_result = "failed"
                set_end_reason(touched_session, "auth_failed")

            # Connection reset
            m = RE_CONN_RESET.search(rest)
            if m:
                touched_session = get_active_session(
                    active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                )
                set_end_reason(touched_session, "connection_reset")

            # SIGUSR1
            m = RE_SIGUSR1.search(rest)
            if m:
                touched_session = get_active_session(
                    active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                )
                reason = m.group("reason").replace("-", "_")
                set_end_reason(
                    touched_session,
                    f"sigusr1_{reason}",
                    details=m.group("reason"),
                )

            # Timeout
            m = RE_INACTIVITY.search(rest)
            if m:
                touched_session = get_active_session(
                    active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                )
                set_end_reason(touched_session, "timeout")

            # Explicit disconnect
            m = RE_EXPLICIT_EXIT.search(rest)
            if m:
                touched_session = get_active_session(
                    active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                )
                set_end_reason(touched_session, "client_disconnect")

            # TLS Error
            m = RE_TLS_ERROR.search(rest)
            if m:
                touched_session = get_active_session(
                    active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                )
                set_end_reason(touched_session, "tls_error")

            # Bad encapsulated packet length
            m = RE_BAD_PACKET_LENGTH.search(rest)
            if m:
                touched_session = get_active_session(
                    active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                )
                set_end_reason(touched_session, "bad_packet_length")

            # If the line starts directly with ip:port
            if touched_session is None:
                m = RE_IP_PORT_AT_START.match(rest)
                if m:
                    touched_session = get_active_session(
                        active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                    )

            if touched_session:
                should_store_line = store_lines and (
                    store_session_ids is None
                    or touched_session.session_id in store_session_ids
                )
                attach_line(touched_session, line, ts, line_no, store_line=should_store_line)

    return sessions_in_order


# ============================================================================
# OUTPUT
# ============================================================================

def print_summary(
    sessions: List[Session],
    show_unknown: bool = False,
    user_filter: Optional[str] = None,
) -> None:
    """Print a summary table of sessions.
    
    Args:
        sessions: Session objects
        show_unknown: Also show sessions without clear status
        user_filter: Case-insensitive username filter
    
    Output columns:
        ID: Session number
        Auth: success | failed | unknown
        End: End reason
        User: Username
        IP:Port: Client address
        Start: First timestamp
        End Time: Last timestamp
        Duration: Calculated session duration (HH:MM:SS)
    """
    filtered = []

    for s in sessions:
        if not show_unknown and s.auth_result == "unknown" and s.end_reason == "unknown":
            continue
        if user_filter and (s.user or "").lower() != user_filter.lower():
            continue
        filtered.append(s)

    if not filtered:
        print("No matching sessions found.")
        return

    print(
        f"{'ID':>4}  {'Auth':<8}  {'End':<20}  {'User':<20}  {'IP:Port':<24}  "
        f"{'Start':<19}  {'End Time':<19}  {'Duration':<9}"
    )
    print("-" * 135)

    for s in filtered:
        user = s.user or "-"
        duration = calculate_duration(s.start_ts, s.end_ts)
        print(
            f"{s.session_id:>4}  "
            f"{s.auth_result:<8}  "
            f"{s.end_reason:<20}  "
            f"{user:<20.20}  "
            f"{s.key:<24}  "
            f"{(s.start_ts or '-'): <19}  "
            f"{(s.end_ts or '-'): <19}  "
            f"{duration:<9}"
        )


def print_session(session: Session) -> None:
    """Print full session details with all original log lines.
    
    Args:
        session: Session object
    
    Output:
        Metadata header followed by all original log lines.
    """
    duration = calculate_duration(session.start_ts, session.end_ts)
    print(
        f"# Session {session.session_id}\n"
        f"# User        : {session.user or '-'}\n"
        f"# CN          : {session.cn or '-'}\n"
        f"# Auth Result : {session.auth_result}\n"
        f"# End Reason  : {session.end_reason}\n"
        f"# End Details : {session.end_details or '-'}\n"
        f"# Key         : {session.key}\n"
        f"# Start       : {session.start_ts or '-'}\n"
        f"# End         : {session.end_ts or '-'}\n"
        f"# Duration    : {duration}\n"
        f"# Lines       : {session.start_line_no or '-'} - {session.end_line_no or '-'}\n"
    )
    for line in session.lines:
        print(line)


def find_session(
    sessions: List[Session],
    session_id: int,
) -> Optional[Session]:
    """Find a specific session by unique session ID.
    
    Args:
        sessions: Session objects
        session_id: Session ID from the summary command
    
    Returns:
        Session object or None if not found
    """
    for s in sessions:
        if s.session_id == session_id:
            return s

    return None


def find_sessions_by_key(sessions: List[Session], key: str) -> List[Session]:
    """Find all sessions with an IP:Port key."""
    return [s for s in sessions if s.key == key]


# ============================================================================
# CLI
# ============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands.
    
    Returns:
        ArgumentParser object with summary and session subcommands
    """
    parser = argparse.ArgumentParser(
        description="OpenVPN Log Analyzer - parses openvpn.log and analyzes sessions",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )

    parser.add_argument("-h", "--help", action="help", help="Show this help message")
    parser.add_argument(
        "logfile",
        help="Path to the OpenVPN log file, for example /var/log/openvpn.log"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # summary Command
    p_summary = subparsers.add_parser(
        "summary",
        help="Show a summary table of detected sessions"
    )
    p_summary.add_argument(
        "--show-unknown",
        action="store_true",
        help="Show sessions without a clear status"
    )
    p_summary.add_argument(
        "--user",
        help="Filter by username (case-insensitive)"
    )

    # session Command
    p_session = subparsers.add_parser(
        "session",
        help="Show all log lines for one session"
    )
    group = p_session.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--id",
        type=int,
        help="Session ID from the summary command, for example --id 5"
    )
    group.add_argument(
        "--key",
        help="Session key as IP:PORT, for example --key 192.0.2.100:5000"
    )
    p_session.add_argument(
        "--output",
        help="Write output to a text file instead of stdout"
    )

    return parser


def print_usage_hint() -> None:
    """Print usage hints with examples."""
    print("""
Use VPNlyze to analyze OpenVPN log files.

QUICK START:
  1. Show the session summary:
     vpnlyze /var/log/openvpn.log summary
  
  2. Inspect one session by ID or IP:Port:
     vpnlyze /var/log/openvpn.log session --id 1
     vpnlyze /var/log/openvpn.log session --key 192.0.2.100:5000

COMMANDS:
  vpnlyze <logfile> summary [--show-unknown] [--user USER]
    Show a summary table of detected sessions
    --show-unknown: include sessions without clear status
    --user testuser: filter by username
  
  vpnlyze <logfile> session --id <ID> [--output file]
    Show all log lines for a session ID
    --output: write to file
  
  vpnlyze <logfile> session --key <IP:PORT> [--output file]
    Show log lines for an IP:PORT key

EXAMPLES:
  vpnlyze /var/log/openvpn.log summary
  vpnlyze /var/log/openvpn.log summary --show-unknown
  vpnlyze /var/log/openvpn.log summary --user testuser1
  vpnlyze /var/log/openvpn.log session --id 42
  vpnlyze /var/log/openvpn.log session --key 192.0.2.100:5000
  vpnlyze /var/log/openvpn.log session --id 42 --output session_42.log

SUMMARY COLUMNS:
  ID       = Session ID
  Auth     = success | failed | unknown
  End      = Session end reason
  User     = Username
  IP:Port  = Client address
  Start    = First timestamp
  End Time = Last timestamp
  Duration = Calculated session duration (HH:MM:SS)
""")


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:
    """Parse arguments, load the log file, and generate output.
    
    Returns:
        0: Success
        1: Loading/parsing error
        2: Session not found or ambiguous
    """
    parser = build_arg_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        print_usage_hint()
        return 0

    args = parser.parse_args()

    if not args.logfile:
        parser.print_help()
        print_usage_hint()
        return 1

    log_path = Path(args.logfile)
    if not log_path.is_file():
        print(f"File not found: {log_path}", file=sys.stderr)
        return 1

    sessions = parse_log(log_path, store_lines=False)

    if args.command == "summary":
        print_summary(
            sessions,
            show_unknown=args.show_unknown,
            user_filter=args.user,
        )
        return 0

    if args.command == "session":
        sess = None
        if args.key:
            matches = find_sessions_by_key(sessions, args.key)
            if len(matches) > 1:
                ids = ", ".join(str(s.session_id) for s in matches)
                print(
                    f"Session key is ambiguous: {args.key} "
                    f"(session IDs: {ids}). Please use --id.",
                    file=sys.stderr,
                )
                return 2
            if len(matches) == 1:
                sess = matches[0]
        else:
            sess = find_session(sessions, args.id)

        if not sess:
            print("Session not found.", file=sys.stderr)
            return 2

        detail_sessions = parse_log(
            log_path,
            store_lines=True,
            store_session_ids={sess.session_id},
        )
        sess = find_session(detail_sessions, sess.session_id)
        if not sess:
            print("Session nicht gefunden.", file=sys.stderr)
            return 2

        if args.output:
            out_path = Path(args.output)
            with out_path.open("w", encoding="utf-8") as f:
                duration = calculate_duration(sess.start_ts, sess.end_ts)
                header = (
                    f"# Session {sess.session_id}\n"
                    f"# User        : {sess.user or '-'}\n"
                    f"# CN          : {sess.cn or '-'}\n"
                    f"# Auth Result : {sess.auth_result}\n"
                    f"# End Reason  : {sess.end_reason}\n"
                    f"# End Details : {sess.end_details or '-'}\n"
                    f"# Key         : {sess.key}\n"
                    f"# Start       : {sess.start_ts or '-'}\n"
                    f"# End         : {sess.end_ts or '-'}\n"
                    f"# Duration    : {duration}\n"
                    f"# Lines       : {sess.start_line_no or '-'} - {sess.end_line_no or '-'}\n\n"
                )
                f.write(header)
                for line in sess.lines:
                    f.write(line + "\n")
            print(f"Session saved: {out_path}")
        else:
            print_session(sess)

        return 0

    parser.print_help()
    print_usage_hint()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
