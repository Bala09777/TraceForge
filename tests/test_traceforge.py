import unittest
from datetime import datetime, timedelta, timezone

from traceforge import build_alert, correlate_alerts, extract_source_ip

BASE = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)


def record(minutes, process="sshd", evidence="SSH_AUTH_LOG_PATTERN",
           source_ip="192.0.2.10"):
    return {
        "timestamp_utc": (BASE + timedelta(minutes=minutes)).isoformat(),
        "event_type": "AUTHENTICATION_FAILURE_PATTERN",
        "evidence_type": evidence,
        "host": "kali-lab",
        "process": process,
        "source_ip": source_ip,
        "message": "Failed password test",
    }


class TraceForgeTests(unittest.TestCase):
    def test_extract_ipv4(self):
        self.assertEqual(
            extract_source_ip("Failed password from 192.0.2.10 port 2222"),
            "192.0.2.10",
        )

    def test_extract_ipv6(self):
        self.assertEqual(
            extract_source_ip("Failed password from 2001:db8::1 port 22"),
            "2001:db8::1",
        )

    def test_no_ip_returns_none(self):
        self.assertIsNone(extract_source_ip("Failed password for demo"))

    def test_simulated_event_is_labelled_test(self):
        alert = build_alert({
            "MESSAGE": "TRACEFORGE_TEST: Failed password from 192.0.2.10 port 2222",
            "_COMM": "logger",
            "_HOSTNAME": "kali",
        })
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "TEST")
        self.assertTrue(alert["simulated"])
        self.assertEqual(alert["source_ip"], "192.0.2.10")

    def test_unrelated_real_process_is_ignored(self):
        alert = build_alert({
            "MESSAGE": "Failed password for demo",
            "_COMM": "some-app",
            "_HOSTNAME": "kali",
        })
        self.assertIsNone(alert)

    def test_non_matching_message_is_ignored(self):
        alert = build_alert({
            "MESSAGE": "System started successfully",
            "_COMM": "sshd",
            "_HOSTNAME": "kali",
        })
        self.assertIsNone(alert)

    def test_three_events_create_incident(self):
        incidents = correlate_alerts([
            record(0), record(1), record(2)
        ])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["event_count"], 3)
        self.assertEqual(incidents[0]["source_ip"], "192.0.2.10")

    def test_two_events_do_not_create_incident(self):
        self.assertEqual(
            correlate_alerts([record(0), record(1)]), []
        )

    def test_events_outside_window_do_not_create_incident(self):
        self.assertEqual(
            correlate_alerts([record(0), record(6), record(12)]), []
        )

    def test_different_ips_are_separate_groups(self):
        incidents = correlate_alerts([
            record(0, source_ip="192.0.2.10"),
            record(1, source_ip="192.0.2.11"),
            record(2, source_ip="192.0.2.12"),
        ])
        self.assertEqual(incidents, [])

    def test_simulated_incident_remains_test_severity(self):
        incidents = correlate_alerts([
            record(i, process="traceforge-sim",
                   evidence="SIMULATED_TEST_EVENT")
            for i in range(3)
        ])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["severity"], "TEST")
        self.assertTrue(incidents[0]["simulated"])

    def test_invalid_window_is_rejected(self):
        with self.assertRaises(ValueError):
            correlate_alerts([], window_minutes=0)

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            correlate_alerts([], threshold=0)


if __name__ == "__main__":
    unittest.main()
