#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPNlyze - OpenVPN Session Analyzer

Copyright (c) 2026 bndtblds
Licensed under the MIT License.

Ein Python-Tool zur Analyse von OpenVPN Syslog-Dateien (openvpn.log).
Parser extrahiert Sessions, Auth-Ergebnisse und Beendigungsgründe.

Anwendung:
  vpnlyze <logfile> summary [--user USER] [--show-unknown]
  vpnlyze <logfile> session --id <ID> [--output file]
  vpnlyze <logfile> session --key <IP:PORT>

Features:
  - Sessions automatisch aus Logdatei extrahieren
  - Session-Dauer berechnen (HH:MM:SS)
  - Auth-Ergebnisse tracking (success/failed)
  - Beendigungsgründe erkennen (timeout, auth_failed, etc.)
  - Einzelne Sessions komplett inspizieren
  - Nach User filtern
"""

import argparse
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


__author__ = "bndtblds"
__license__ = "MIT"


# ============================================================================
# DATENMODELL: Session Class
# ============================================================================

@dataclass
class Session:
    """Repräsentiert eine OpenVPN-Session (VPN-Verbindung).
    
    Attribute:
        session_id: Eindeutige Nummer (Reihenfolge der Entdeckung)
        key: IP:PORT Kombination der Verbindung (nicht global eindeutig)
        ip: Client IP-Adresse
        port: Client Port
        user: Benutzername der Session
        cn: Certificate Name (aus TLS Handshake)
        auth_result: Authentifizierungsergebnis (success/failed/unknown)
        end_reason: Grund der Sitzungsbeendigung (timeout, reset, etc.)
        end_details: Zusätzliche Details zum Beendigungsgrund
        start_ts: Erste Logzeile (YYYY:MM:DD-HH:MM:SS)
        end_ts: Letzte Logzeile (YYYY:MM:DD-HH:MM:SS)
        start_line_no: Erste Zeilennummer in Logdatei
        end_line_no: Letzte Zeilennummer in Logdatei
        lines: Alle Original-Logzeilen dieser Session
    """
    session_id: int
    key: str
    ip: str
    port: str
    user: Optional[str] = None
    cn: Optional[str] = None
    auth_result: str = "unknown"    # success | failed | unknown
    end_reason: str = "unknown"     # siehe set_end_reason() für Prioritäten
    end_details: Optional[str] = None
    start_ts: Optional[str] = None
    end_ts: Optional[str] = None
    start_line_no: Optional[int] = None
    end_line_no: Optional[int] = None
    lines: List[str] = field(default_factory=list)


# ============================================================================
# REGEX PATTERNS: Logzeilen-Erkennung
# ============================================================================
# Diese Patterns erkennen verschiedene OpenVPN-Ereignisse in Syslog-Zeilen.
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

# TCP-Handshake Start
RE_TCP_ESTABLISHED = re.compile(
    rf'TCP connection established with {RE_AF_ENDPOINT}'
)

# TLS Handshake abgeschlossen, CN erkannt
RE_PEER_INITIATED = re.compile(
    rf'\[(?P<cn>[^\]]+)\] Peer Connection Initiated with {RE_AF_ENDPOINT}'
)

# Passwort-Authentifizierung angefordert
RE_AUTH_DEFERRED = re.compile(
    rf"{RE_ENDPOINT}.*?Username/Password authentication deferred for username '(?P<user>[^']+)'"
)

# Erfolgreiches Login erkannt
RE_CONNECTION_STARTED = re.compile(
    r'event="Connection started".*?username="(?P<user>[^"]+)".*?srcip="(?P<ip>[^"]+)"'
)

# User/IP:Port Kombination
RE_USER_IP_PORT = re.compile(
    rf'^(?P<user>[^/\s]+)/{RE_ENDPOINT}'
)

# Authentifizierung fehlgeschlagen
RE_AUTH_FAILED = re.compile(
    rf"{RE_ENDPOINT}.*?SENT CONTROL \[(?P<user>[^\]]+)\]: 'AUTH_FAILED'"
)

# Verbindung zurückgesetzt
RE_CONN_RESET = re.compile(
    rf'{RE_ENDPOINT}.*?Connection reset'
)

# Signal SIGUSR1 empfangen (Neustart/Neuladen)
RE_SIGUSR1 = re.compile(
    rf'{RE_ENDPOINT}.*?SIGUSR1\[soft,(?P<reason>[^\]]+)\]'
)

# Timeout durch Inaktivität
RE_INACTIVITY = re.compile(
    rf'{RE_ENDPOINT}.*?Inactivity timeout'
)

# Client disconnect (explizit)
RE_EXPLICIT_EXIT = re.compile(
    rf'{RE_ENDPOINT}.*?(Connection, Client disconnected|client-instance exiting)'
)

# TLS/SSL Fehler
RE_TLS_ERROR = re.compile(
    rf'{RE_ENDPOINT}.*?TLS Error'
)

# Paketlängen-Fehler (meist Netzwerkprobleme)
RE_BAD_PACKET_LENGTH = re.compile(
    rf'{RE_ENDPOINT}.*?Bad encapsulated packet length'
)


# ============================================================================
# HILFSFUNKTIONEN
# ============================================================================

def make_key(ip: str, port: str) -> str:
    """Erstellt eindeutigen Session-Schlüssel aus IP:Port."""
    return f"{ip}:{port}"


def create_session(
    sessions_in_order: List[Session],
    ip: str,
    port: str,
) -> Session:
    """Erstellt eine neue Session-Instanz.
    
    Args:
        sessions_in_order: Liste zur Erhaltung der Reihenfolge
        ip: Client IP-Adresse
        port: Client Port
    
    Returns:
        Neu erstelltes Session-Objekt
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
    """Findet die aktuell aktive Session nach IP:Port oder erstellt eine neue.
    
    TCP source ports can be reused later in the same log file. Therefore a TCP
    connection start always creates a new session, while follow-up events use the
    most recent active session for the same IP:Port.
    """
    key = make_key(ip, port)
    if key not in active_sessions_by_key:
        active_sessions_by_key[key] = create_session(sessions_in_order, ip, port)
    return active_sessions_by_key[key]


def is_pending_login_candidate(session: Session, ip: str, user: str) -> bool:
    """Prüft, ob eine Session für ein portloses Login-Event plausibel ist."""
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
    """Fügt Logzeile zu Session hinzu und aktualisiert Timestamps.
    
    Args:
        session: Session-Objekt
        line: Original-Logzeile
        ts: Timestamp aus Logzeile
        line_no: Zeilennummer in Datei
        store_line: Originalzeile speichern (für Detailansicht/Export)
    """
    if session.start_ts is None:
        session.start_ts = ts
        session.start_line_no = line_no
    session.end_ts = ts
    session.end_line_no = line_no
    if store_line:
        session.lines.append(line)


def set_end_reason(session: Session, reason: str, details: Optional[str] = None) -> None:
    """Setzt Beendigungsgrund mit Prioritäten-Prüfung.
    
    Verhindert, dass unwichtige Gründe (z.B. connection_reset) wichtigere
    Gründe (z.B. auth_failed) überschreiben.
    
    Priorität (niedrig→hoch):
        0: unknown
        1: connection_reset, sigusr1_connection_reset
        2: client_disconnect  
        3: timeout, sigusr1_ping_restart
        4: tls_error, sigusr1_tls_error
        5: bad_packet_length
        6: auth_failed (höchste Priorität)
    
    Args:
        session: Session-Objekt
        reason: Neuer Beendigungsgrund
        details: Optionale Zusatzinformation
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
    """Berechnet Session-Dauer zwischen zwei Timestamps.
    
    Args:
        start_ts: Start-Timestamp (Format: YYYY:MM:DD-HH:MM:SS)
        end_ts: End-Timestamp (Format: YYYY:MM:DD-HH:MM:SS)
    
    Returns:
        Formatierte Dauer als HH:MM:SS oder "-" wenn nicht berechenbar.
    
    Beispiele:
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
            return "-"  # End vor Start sollte nicht vorkommen
        
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    except (ValueError, Exception):
        return "-"  # Fallback bei ungültigem Format


# ============================================================================
# LOG PARSER: Hauptanalyse-Funktion
# ============================================================================

def parse_log(path: Path, store_lines: bool = True) -> List[Session]:
    """Parst OpenVPN Syslog-Datei und extrahiert alle Sessions.
    
    Liest Logdatei zeilenweise, erkennt OpenVPN-Events per Regex,
    erstellt Session-Objekte mit Metadata (User, Auth, End-Reason, etc.).
    
    Args:
        path: Pfad zur openvpn.log Datei
        store_lines: Original-Logzeilen in Session-Objekten speichern
    
    Returns:
        Liste von Session-Objekten sortiert nach Entdeckungs-Reihenfolge
    
    Verarbeitete Events:
        - TCP connection established
        - Peer Connection Initiated (CN extraction)
        - Username/Password deferred
        - Connection started (erfolgreicher Login)
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

            # user/ip:port-Zeilen
            m = RE_USER_IP_PORT.search(rest)
            if m:
                touched_session = get_active_session(
                    active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                )
                if not touched_session.user:
                    touched_session.user = m.group("user")

            # Erfolgreiche Anmeldung
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

            # Fehlgeschlagene Anmeldung
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

            # Expliziter Disconnect
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

            # Falls Zeile direkt mit ip:port beginnt
            if touched_session is None:
                m = RE_IP_PORT_AT_START.match(rest)
                if m:
                    touched_session = get_active_session(
                        active_sessions_by_key, sessions_in_order, m.group("ip"), m.group("port")
                    )

            if touched_session:
                attach_line(touched_session, line, ts, line_no, store_line=store_lines)

    return sessions_in_order


# ============================================================================
# AUSGABE: Formatierte Tabellen und Details
# ============================================================================

def print_summary(
    sessions: List[Session],
    show_unknown: bool = False,
    user_filter: Optional[str] = None,
) -> None:
    """Gibt Übersichtstabelle aller Sessions aus.
    
    Args:
        sessions: Liste von Session-Objekten
        show_unknown: Zeige auch Sessions ohne klaren Status
        user_filter: Filter nach bestimmtem Benutzername (case-insensitive)
    
    Output-Spalten:
        ID: Session-Nummer
        Auth: success | failed | unknown
        Ende: Beendigungsgrund
        User: Benutzername
        IP:Port: Client-Adresse
        Start: Erste Logzeile (Timestamp)
        Ende-Zeit: Letzte Logzeile (Timestamp)
        Dauer: Berechnete Session-Dauer (HH:MM:SS)
    """
    filtered = []

    for s in sessions:
        if not show_unknown and s.auth_result == "unknown" and s.end_reason == "unknown":
            continue
        if user_filter and (s.user or "").lower() != user_filter.lower():
            continue
        filtered.append(s)

    if not filtered:
        print("Keine passenden Sessions gefunden.")
        return

    print(
        f"{'ID':>4}  {'Auth':<8}  {'Ende':<20}  {'User':<20}  {'IP:Port':<24}  "
        f"{'Start':<19}  {'Ende-Zeit':<19}  {'Dauer':<9}"
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
    """Gibt vollständige Session-Details mit allen Logzeilen aus.
    
    Args:
        session: Session-Objekt
    
    Output:
        Header mit Metadaten gefolgt von allen Original-Logzeilen.
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
        f"# Ende        : {session.end_ts or '-'}\n"
        f"# Dauer       : {duration}\n"
        f"# Zeilen      : {session.start_line_no or '-'} - {session.end_line_no or '-'}\n"
    )
    for line in session.lines:
        print(line)


def find_session(
    sessions: List[Session],
    session_id: Optional[int] = None,
    key: Optional[str] = None,
) -> Optional[Session]:
    """Sucht spezifische Session nach ID oder IP:Port Key.
    
    Args:
        sessions: Liste von Session-Objekten
        session_id: Session-ID (von summary Command)
        key: IP:PORT String (z.B. "192.0.2.1:5000")
    
    Returns:
        Session-Objekt oder None wenn nicht gefunden
    """
    if session_id is not None:
        for s in sessions:
            if s.session_id == session_id:
                return s

    if key is not None:
        for s in sessions:
            if s.key == key:
                return s

    return None


def find_sessions_by_key(sessions: List[Session], key: str) -> List[Session]:
    """Sucht alle Sessions mit einem IP:Port-Key."""
    return [s for s in sessions if s.key == key]


# ============================================================================
# CLI: Argument Parser und Hilfe
# ============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    """Erstellt Argument Parser mit all Subcommands.
    
    Returns:
        ArgumentParser-Objekt mit summary und session Subcommands
    """
    parser = argparse.ArgumentParser(
        description="OpenVPN Log Analyzer - Parst openvpn.log und analysiert Sessions",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )

    parser.add_argument("-h", "--help", action="help", help="Diese Hilfe anzeigen")
    parser.add_argument(
        "logfile",
        help="Pfad zur OpenVPN Logdatei (z.B. /var/log/openvpn.log)"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # summary Command
    p_summary = subparsers.add_parser(
        "summary",
        help="Übersichtstabelle aller erkannten Sessions"
    )
    p_summary.add_argument(
        "--show-unknown",
        action="store_true",
        help="Auch Sessions ohne klaren Status anzeigen"
    )
    p_summary.add_argument(
        "--user",
        help="Filter: nur Sessions dieses Users (case-insensitive)"
    )

    # session Command
    p_session = subparsers.add_parser(
        "session",
        help="Zeige alle Logzeilen einer spezifischen Session"
    )
    group = p_session.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--id",
        type=int,
        help="Session-ID aus summary Command (z.B. --id 5)"
    )
    group.add_argument(
        "--key",
        help="Session Key als IP:PORT (z.B. --key 192.0.2.100:5000)"
    )
    p_session.add_argument(
        "--output",
        help="Speichere Output in Textdatei statt stdout"
    )

    return parser


def print_usage_hint() -> None:
    """Gibt Bedienungsanleitung mit Beispielen aus."""
    print("""
Nutzen Sie VPNlyze zur Analyse von OpenVPN Logdateien.

EINFACHE VERWENDUNG:
  1. Zunächst Summary der Sessions abrufen:
     vpnlyze /var/log/openvpn.log summary
  
  2. Dann spezifische Session analysieren (per ID oder IP:Port):
     vpnlyze /var/log/openvpn.log session --id 1
     vpnlyze /var/log/openvpn.log session --key 192.0.2.100:5000

ALLE BEFEHLE:
  vpnlyze <logfile> summary [--show-unknown] [--user USER]
    Zeige Übersichtstabelle aller Sessions
    --show-unknown: auch Sessions ohne Status
    --user testuser: Filter nach User
  
  vpnlyze <logfile> session --id <ID> [--output datei]
    Zeige alle Logzeilen für Session-ID
    --output: speichere in Datei
  
  vpnlyze <logfile> session --key <IP:PORT> [--output datei]
    Zeige Logzeilen für IP:PORT Kombination

BEISPIELE (mit anonymen Testdaten):
  vpnlyze /var/log/openvpn.log summary
  vpnlyze /var/log/openvpn.log summary --show-unknown
  vpnlyze /var/log/openvpn.log summary --user testuser1
  vpnlyze /var/log/openvpn.log session --id 42
  vpnlyze /var/log/openvpn.log session --key 192.0.2.100:5000
  vpnlyze /var/log/openvpn.log session --id 42 --output session_42.log

SPALTEN-ERKLÄRUNG (Summary):
  ID       = Session-Nummer
  Auth     = success | failed | unknown
  Ende     = Beendigungsgrund der Sitzung
  User     = Benutzername
  IP:Port  = Client-Adresse
  Start    = Erste Logzeile (Timestamp)
  Ende-Zeit= Letzte Logzeile (Timestamp)
  Dauer    = Berechnete Session-Dauer (HH:MM:SS)
""")


# ============================================================================
# MAIN: Einstiegspunkt
# ============================================================================

def main() -> int:
    """Hauptprogramm - Argumente parsen, Logdatei laden, Ausgabe generieren.
    
    Returns:
        0: Erfolg
        1: Fehler beim Laden/Parsing
        2: Session nicht gefunden
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
        print(f"Datei nicht gefunden: {log_path}", file=sys.stderr)
        return 1

    sessions = parse_log(log_path, store_lines=args.command == "session")

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
                    f"Session-Key ist mehrdeutig: {args.key} "
                    f"(Session-IDs: {ids}). Bitte --id verwenden.",
                    file=sys.stderr,
                )
                return 2
            if len(matches) == 1:
                sess = matches[0]
        else:
            sess = find_session(sessions, session_id=args.id)

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
                    f"# Ende        : {sess.end_ts or '-'}\n"
                    f"# Dauer       : {duration}\n"
                    f"# Zeilen      : {sess.start_line_no or '-'} - {sess.end_line_no or '-'}\n\n"
                )
                f.write(header)
                for line in sess.lines:
                    f.write(line + "\n")
            print(f"Session gespeichert: {out_path}")
        else:
            print_session(sess)

        return 0

    parser.print_help()
    print_usage_hint()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
