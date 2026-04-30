# VPNlyze

VPNlyze ist ein kleines Python-CLI zur Analyse von OpenVPN-Serverlogs im Syslog-Format. Das Tool extrahiert Sessions aus `openvpn.log`, ordnet Logzeilen einer Verbindung zu und zeigt Auth-Status, Endgrund und Dauer pro Session an.

## Features

- Sessions automatisch extrahieren
- Session-Dauer in `HH:MM:SS` berechnen
- Erfolgreiche und fehlgeschlagene Authentifizierungen unterscheiden
- Beendigungsgrunde wie Timeout, `AUTH_FAILED`, Reset oder TLS-Fehler erkennen
- Einzelne Sessions komplett inspizieren oder in eine Datei exportieren
- Wiederverwendete Client-Ports als getrennte Sessions behandeln
- Keine Abhangigkeiten, nur Python-Standardbibliothek

---

## Installation

Direkt mit Python ausfuhren:

```bash
python3 vpnlyze.py --help
```

Optional als Kommando installierbar:

```bash
cp vpnlyze.py /usr/local/bin/vpnlyze
chmod +x /usr/local/bin/vpnlyze
```

Danach:

```bash
vpnlyze /var/log/openvpn.log summary
```

---

## Verwendung

### 1. Übersicht aller Sessions

```bash
vpnlyze /var/log/openvpn.log summary
```

Beispiel:
```
ID  Auth      Ende                User                 IP:Port              Start               Ende-Zeit            Dauer    
---------------------------------------------------------------------------------------
  1  success   client_disconnect   testuser1            192.0.2.1:5000       2025:04:21-10:00:00  2025:04:21-10:30:45  00:30:45 
  2  success   timeout              testuser2            192.0.2.2:5001       2025:04:21-10:05:00  2025:04:21-11:15:30  01:10:30 
  3  failed    auth_failed         testuser3            192.0.2.3:5002       2025:04:21-10:10:00  2025:04:21-10:10:15  00:00:15 
  4  success   connection_reset    testuser1            192.0.2.4:5003       2025:04:21-10:20:00  2025:04:21-10:25:00  00:05:00 
```

### 2. Unbekannte Sessions anzeigen

Sessions ohne klaren Status:

```bash
vpnlyze /var/log/openvpn.log summary --show-unknown
```

### 3. Nach Benutzer filtern

```bash
vpnlyze /var/log/openvpn.log summary --user testuser1
```

Beispiel:
```
ID  Auth      Ende                User                 IP:Port              Start               Ende-Zeit            Dauer    
---------------------------------------------------------------------------------------
  1  success   client_disconnect   testuser1            192.0.2.1:5000       2025:04:21-10:00:00  2025:04:21-10:30:45  00:30:45 
  4  success   connection_reset    testuser1            192.0.2.4:5003       2025:04:21-10:20:00  2025:04:21-10:25:00  00:05:00 
```

### 4. Spezifische Session detailliert anschauen

Nach Session-ID (aus summary):

```bash
vpnlyze /var/log/openvpn.log session --id 1
```

Beispiel:
```
# Session 1
# User        : testuser1
# CN          : testuser1
# Auth Result : success
# End Reason  : client_disconnect
# End Details : -
# Key         : 192.0.2.1:5000
# Start       : 2025:04:21-10:00:00
# Ende        : 2025:04:21-10:30:45
# Dauer       : 00:30:45
# Zeilen      : 12 - 145

2025:04:21-10:00:00 srv.example.com openvpn[1234]: TCP connection established with [AF_INET]192.0.2.1:5000
2025:04:21-10:00:01 srv.example.com openvpn[1234]: [testuser1] Peer Connection Initiated with [AF_INET]192.0.2.1:5000
2025:04:21-10:00:05 srv.example.com openvpn[1234]: event="Connection started" username="testuser1" srcip="192.0.2.1"
... weitere Logzeilen ...
2025:04:21-10:30:45 srv.example.com openvpn[1234]: Connection, Client disconnected
```

Nach IP:Port:

```bash
vpnlyze /var/log/openvpn.log session --key 192.0.2.1:5000
```

Hinweis: `IP:Port` ist nicht garantiert eindeutig, weil Clients Source-Ports
spaeter erneut verwenden koennen. Fuer genaue Detailansichten ist die
Session-ID aus `summary` vorzuziehen.

### 5. Session in Datei exportieren

```bash
vpnlyze /var/log/openvpn.log session --id 1 --output session_1.log
# Output: Session gespeichert: session_1.log
```

---

## Spalten erklärt (Summary)

| Spalte | Bedeutung |
|--------|-----------|
| **ID** | Session-Nummer (fortlaufend) |
| **Auth** | `success` = erfolgreiches Login<br/>`failed` = Authentifizierung fehlgeschlagen<br/>`unknown` = Status unklar |
| **Ende** | Beendigungsgrund (siehe unten) |
| **User** | Benutzername (oder `-` wenn nicht ermittelt) |
| **IP:Port** | Client IP-Adresse:Port |
| **Start** | Zeitstempel erste Logzeile |
| **Ende-Zeit** | Zeitstempel letzte Logzeile |
| **Dauer** | Berechnete Sessionlänge in HH:MM:SS |

---

## Beendigungsgründe (End-Reason)

| Grund | Bedeutung |
|-------|-----------|
| **auth_failed** | Anmeldung fehlgeschlagen (höchste Priorität) |
| **bad_packet_length** | Fehlerhafte Paketgröße empfangen |
| **tls_error** | TLS/SSL Fehler |
| **timeout** | Sitzung durch Inaktivität beendet |
| **client_disconnect** | Client hat Verbindung explizit beendet |
| **connection_reset** | Verbindung von Server zurückgesetzt |
| **sigusr1_*** | Signal SIGUSR1 (z.B. `sigusr1_soft_restart`) |
| **unknown** | Beendigung nicht ermittelt |

> Wenn mehrere Grunde erkannt werden, gewinnt der mit der hochsten Prioritat. `auth_failed` uberschreibt also z. B. `connection_reset`.

---

## Architektur

Das Projekt bleibt bewusst einfach:

1. **Parse-Phase** – Liest Logdatei zeilenweise, matched gegen Regex-Patterns
2. **Session-Aggregation** – Jede TCP-Verbindung startet eine neue Session; Folgezeilen werden der aktuell aktiven Session fuer `IP:Port` zugeordnet
3. **Daten-Bereicherung** – Extrahiert User, CN, Auth-Result, End-Reason
4. **Ausgabe-Phase** – Formatiert Daten als Tabelle oder Detail-View

Es gibt keine Datenbank, keinen Cache und keine externen Pakete. Alles lauft in-memory auf einer Liste von Session-Objekten. Die Summary-Ausgabe speichert keine Original-Logzeilen; Detailansicht und Export laden sie bei Bedarf.

---

## Anonyme Testdaten

Alle Beispiele verwenden anonyme IPs (RFC 5737 TEST-Net):
- `192.0.2.0/24` – Beispiele in dieser Dokumentation
- Usernames: `testuser1`, `testuser2`, `testuser3`
- Zertifikate: `testuser1`, `testuser2` 

Echte personenbezogene Daten gehoren nicht in Beispiele, Issues oder Commits.

---

## Regular Expressions (Regex Patterns)

Das Script erkennt folgende OpenVPN-Ereignisse automatisch:

```
RE_TCP_ESTABLISHED       → "TCP connection established with [AF_INET]<IP>:<PORT>"
RE_PEER_INITIATED        → "[<CN>] Peer Connection Initiated with [AF_INET]<IP>:<PORT>"
RE_AUTH_DEFERRED         → "Username/Password authentication deferred for username '<USER>'"
RE_CONNECTION_STARTED    → 'event="Connection started" username="<USER>" srcip="<IP>"'
RE_AUTH_FAILED           → "SENT CONTROL [<USER>]: 'AUTH_FAILED'"
RE_CONN_RESET            → "Connection reset"
RE_SIGUSR1               → "SIGUSR1[soft,<REASON>]"
RE_INACTIVITY            → "Inactivity timeout"
RE_EXPLICIT_EXIT         → "Connection, Client disconnected" oder "client-instance exiting"
RE_TLS_ERROR             → "TLS Error"
RE_BAD_PACKET_LENGTH     → "Bad encapsulated packet length"
```

Alle Patterns matching IPs und Ports: `\d{1,3}(?:\.\d{1,3}){3}:\d+`

---

## Fehlerbehandlung

- Fehlerhafte Logzeilen werden ignoriert
- Ungultige Timestamps fallen auf `-` zuruck
- Fehlende User/CN fallen auf `-` zuruck
- Nicht gefundene Sessions liefern Exit-Code `2`

---

## Performance

Typische Log-Dateien:
- 100.000 Zeilen: ~0.5 Sekunden
- 1.000.000 Zeilen: ~5 Sekunden
- 10.000.000 Zeilen: ~50 Sekunden

Speicherbedarf: grob `~10 MB` pro Million Zeilen, abhangig von Session-Anzahl und Loginhalt.

---

## Exit Codes

```
0 → Erfolg
1 → Fehler (Datei nicht gefunden, Parse-Fehler)
2 → Session nicht gefunden (bei session Command)
```

---

## Code-Struktur

```
vpnlyze.py
├── Session (Dataclass)
├── Regex Patterns (RE_*)
├── Hilfsfunktionen
│   ├── make_key()
│   ├── create_session()
│   ├── get_active_session()
│   ├── is_pending_login_candidate()
│   ├── attach_line()
│   ├── set_end_reason() (mit Prioritäts-System)
│   └── calculate_duration()
├── Parser
│   └── parse_log() (Hauptlogik)
├── Ausgabe
│   ├── print_summary()
│   ├── print_session()
│   └── find_session()
├── CLI
│   ├── build_arg_parser()
│   └── print_usage_hint()
└── main()
```

---

## Entwicklung und Erweiterungen

### Unit Tests hinzufügen

```python
import unittest

class TestCalculateDuration(unittest.TestCase):
    def test_30_minutes(self):
        result = calculate_duration("2025:04:21-10:00:00", "2025:04:21-10:30:00")
        assert result == "00:30:00"
```

### Neue Regex Patterns

```python
# Neuen Pattern hinzufügen
RE_CUSTOM_EVENT = re.compile(r'<pattern>')

# In parse_log() matcher:
m = RE_CUSTOM_EVENT.search(rest)
if m:
    # ...
```

### CSV Export

```python
import csv

def export_summary_csv(sessions, filename):
    with open(filename, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'Auth', 'EndReason', 'User', 'IP:Port', 'Duration'])
        for s in sessions:
            writer.writerow([
                s.session_id,
                s.auth_result,
                s.end_reason,
               s.user or '-',
                s.key,
                calculate_duration(s.start_ts, s.end_ts)
            ])
```

---

## Hinweise fur das offentliche Repo

- Lizenz: [MIT](LICENSE)
- Hauptdatei: `vpnlyze.py`

---

## Weitere Ressourcen

- **OpenVPN Logging**: https://openvpn.net/
- **Syslog Format**: RFC 3164

---

## Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](LICENSE).
