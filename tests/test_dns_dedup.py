import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "traceforge_dns_anomaly.py"

SPEC = importlib.util.spec_from_file_location(
    "traceforge_dns_anomaly_dedup_test",
    MODULE_PATH,
)


class TestDNSAlertDeduplication(unittest.TestCase):
    def test_rerunning_detector_does_not_append_duplicate_alerts(self):
        module = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(module)

        with tempfile.TemporaryDirectory(
            prefix="traceforge-dedup-test-"
        ) as temp_dir:
            temp_path = Path(temp_dir)
            events_file = temp_path / "network_events.jsonl"
            alerts_file = temp_path / "alerts.jsonl"

            event = {
                "evidence_type": "LIVE_TSHARK_DNS_METADATA",
                "event_type": "DNS_QUERY",
                "domain": "example.com",
                "source_ip": "10.0.2.15",
            }
            events_file.write_text(
                "".join(json.dumps(event) + "\n" for _ in range(35)),
                encoding="utf-8",
            )

            module.EVENTS_FILE = events_file
            module.ALERTS_FILE = alerts_file

            with redirect_stdout(StringIO()):
                module.main()
            first_run = alerts_file.read_text(
                encoding="utf-8"
            ).splitlines()

            with redirect_stdout(StringIO()):
                module.main()
            second_run = alerts_file.read_text(
                encoding="utf-8"
            ).splitlines()

            self.assertGreater(len(first_run), 0)
            self.assertEqual(len(second_run), len(first_run))


if __name__ == "__main__":
    unittest.main()
