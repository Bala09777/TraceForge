import unittest
from datetime import datetime, timedelta, timezone

from traceforge_correlate import correlate_alerts


BASE = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)


def event(minutes, evidence="SIMULATED_TEST_EVENT", process="logger"):
    timestamp = (BASE + timedelta(minutes=minutes)).isoformat()
    return {
        "timestamp_utc": timestamp,
        "event_type": "AUTHENTICATION_FAILURE_PATTERN",
        "evidence_type": evidence,
        "host": "kali",
        "process": process,
        "message": "controlled test event",
    }


class CorrelationTests(unittest.TestCase):
    def test_three_events_within_window_create_incident(self):
        incidents = correlate_alerts([event(0), event(1), event(2)])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["event_count"], 3)
        self.assertTrue(incidents[0]["simulated"])
        self.assertEqual(incidents[0]["severity"], "TEST")

    def test_two_events_do_not_create_incident(self):
        incidents = correlate_alerts([event(0), event(1)])
        self.assertEqual(incidents, [])

    def test_events_outside_window_do_not_group(self):
        incidents = correlate_alerts([event(0), event(6), event(12)])
        self.assertEqual(incidents, [])

    def test_different_processes_are_separate_groups(self):
        incidents = correlate_alerts([
            event(0, process="procA"),
            event(1, process="procB"),
            event(2, process="procC"),
        ])
        self.assertEqual(incidents, [])

    def test_live_evidence_is_not_labelled_as_test(self):
        incidents = correlate_alerts([
            event(0, evidence="SYSTEM_JOURNAL_EVENT"),
            event(1, evidence="SYSTEM_JOURNAL_EVENT"),
            event(2, evidence="SYSTEM_JOURNAL_EVENT"),
        ])
        self.assertEqual(len(incidents), 1)
        self.assertFalse(incidents[0]["simulated"])
        self.assertEqual(incidents[0]["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
