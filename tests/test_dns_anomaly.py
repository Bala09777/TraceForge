import unittest

from traceforge_dns_anomaly import calculate_entropy, inspect_domain


class TestDNSAnomaly(unittest.TestCase):
    def test_empty_string_entropy_is_zero(self):
        self.assertEqual(calculate_entropy(""), 0.0)

    def test_repeated_character_entropy_is_zero(self):
        self.assertEqual(calculate_entropy("aaaaaaaa"), 0.0)

    def test_varied_characters_have_positive_entropy(self):
        self.assertGreater(calculate_entropy("abcdef123456"), 0.0)

    def test_synthetic_test_domains_are_excluded(self):
        for domain in (
            "tf-test-1792739135.example.org",
            "tf-check-1792739239.example.org",
            "traceforge-test-1792738685.example.com",
        ):
            with self.subTest(domain=domain):
                self.assertEqual(inspect_domain(domain), [])

    def test_normal_short_domain_has_no_indicators(self):
        self.assertEqual(inspect_domain("www.example.com"), [])

    def test_long_label_is_flagged(self):
        domain = "a" * 30 + ".example.com"
        indicators = inspect_domain(domain)
        self.assertIn(
            "LONG_DNS_LABEL",
            [item["indicator"] for item in indicators],
        )

    def test_high_entropy_label_is_flagged(self):
        domain = "abcdefghijklmnopqrstuvwx1234.example.com"
        indicators = inspect_domain(domain)
        self.assertIn(
            "HIGH_ENTROPY_DNS_LABEL",
            [item["indicator"] for item in indicators],
        )


if __name__ == "__main__":
    unittest.main()
