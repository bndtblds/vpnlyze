import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import vpnlyze


def parse_lines(lines, store_lines=True):
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
        tmp.write("\n".join(lines))
        tmp.write("\n")
        path = Path(tmp.name)

    try:
        return vpnlyze.parse_log(path, store_lines=store_lines)
    finally:
        path.unlink(missing_ok=True)


class ParserTests(unittest.TestCase):
    def test_reused_ip_port_creates_new_sessions(self):
        sessions = parse_lines(
            [
                "2026:04:30-10:00:00 host openvpn[1]: TCP connection established with [AF_INET]192.0.2.1:5000",
                "2026:04:30-10:00:01 host openvpn[1]: 192.0.2.1:5000 Connection reset, restarting",
                "2026:04:30-10:01:00 host openvpn[1]: TCP connection established with [AF_INET]192.0.2.1:5000",
                "2026:04:30-10:01:01 host openvpn[1]: 192.0.2.1:5000 Connection reset, restarting",
            ]
        )

        self.assertEqual(len(sessions), 2)
        self.assertEqual([s.key for s in sessions], ["192.0.2.1:5000", "192.0.2.1:5000"])
        self.assertEqual([s.start_ts for s in sessions], ["2026:04:30-10:00:00", "2026:04:30-10:01:00"])

    def test_connection_started_matches_latest_pending_session(self):
        sessions = parse_lines(
            [
                "2026:04:30-10:00:00 host openvpn[1]: TCP connection established with [AF_INET]192.0.2.1:5000",
                "2026:04:30-10:00:01 host openvpn[1]: 192.0.2.1:5000 Username/Password authentication deferred for username 'testuser1'",
                "2026:04:30-10:00:02 host openvpn[1]: TCP connection established with [AF_INET]192.0.2.1:5001",
                "2026:04:30-10:00:03 host openvpn[1]: 192.0.2.1:5001 Username/Password authentication deferred for username 'testuser1'",
                '2026:04:30-10:00:04 host openvpn[1]: event="Connection started" username="testuser1" srcip="192.0.2.1"',
            ]
        )

        self.assertEqual(sessions[0].auth_result, "unknown")
        self.assertEqual(sessions[1].auth_result, "success")

    def test_connection_started_uses_latest_session_after_port_reuse(self):
        sessions = parse_lines(
            [
                "2026:04:30-10:00:00 host openvpn[1]: TCP connection established with [AF_INET]192.0.2.1:5000",
                "2026:04:30-10:00:01 host openvpn[1]: 192.0.2.1:5000 Username/Password authentication deferred for username 'testuser1'",
                "2026:04:30-10:00:02 host openvpn[1]: TCP connection established with [AF_INET]192.0.2.1:5001",
                "2026:04:30-10:00:03 host openvpn[1]: 192.0.2.1:5001 Username/Password authentication deferred for username 'testuser1'",
                "2026:04:30-10:00:04 host openvpn[1]: TCP connection established with [AF_INET]192.0.2.1:5000",
                "2026:04:30-10:00:05 host openvpn[1]: 192.0.2.1:5000 Username/Password authentication deferred for username 'testuser1'",
                '2026:04:30-10:00:06 host openvpn[1]: event="Connection started" username="testuser1" srcip="192.0.2.1"',
            ]
        )

        self.assertEqual(sessions[0].auth_result, "unknown")
        self.assertEqual(sessions[1].auth_result, "unknown")
        self.assertEqual(sessions[2].auth_result, "success")

    def test_unmatched_connection_started_creates_separate_unknown_sessions(self):
        sessions = parse_lines(
            [
                '2026:04:30-10:00:00 host openvpn[1]: event="Connection started" username="testuser1" srcip="192.0.2.1"',
                '2026:04:30-10:01:00 host openvpn[1]: event="Connection started" username="testuser2" srcip="192.0.2.1"',
            ]
        )

        self.assertEqual(len(sessions), 2)
        self.assertEqual([s.user for s in sessions], ["testuser1", "testuser2"])
        self.assertEqual([s.key for s in sessions], ["192.0.2.1:unknown", "192.0.2.1:unknown"])

    def test_sigusr1_respects_priority_system(self):
        sessions = parse_lines(
            [
                "2026:04:30-10:00:00 host openvpn[1]: TCP connection established with [AF_INET]192.0.2.1:5000",
                "2026:04:30-10:00:01 host openvpn[1]: 192.0.2.1:5000 Bad encapsulated packet length from peer",
                "2026:04:30-10:00:02 host openvpn[1]: 192.0.2.1:5000 SIGUSR1[soft,connection-reset] received, process restarting",
            ]
        )

        self.assertEqual(sessions[0].end_reason, "bad_packet_length")

    def test_summary_mode_can_skip_original_line_storage(self):
        sessions = parse_lines(
            [
                "2026:04:30-10:00:00 host openvpn[1]: TCP connection established with [AF_INET]192.0.2.1:5000",
                "2026:04:30-10:00:01 host openvpn[1]: 192.0.2.1:5000 Connection reset, restarting",
            ],
            store_lines=False,
        )

        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].lines, [])
        self.assertEqual(sessions[0].start_ts, "2026:04:30-10:00:00")
        self.assertEqual(sessions[0].end_ts, "2026:04:30-10:00:01")


class CliTests(unittest.TestCase):
    def test_command_is_required(self):
        parser = vpnlyze.build_arg_parser()

        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                parser.parse_args(["openvpn.log"])

        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
