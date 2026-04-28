import unittest
from unittest.mock import MagicMock, patch

# Import the classes we want to test
from src.detector.phishing_detector import PhishingDetector
from src.detector.threat_report import ThreatReport
from src.inputs.url_input import URLInput
from src.inputs.email_input import EmailInput

class TestThreatReport(unittest.TestCase):

    def test_phishing_label(self):
        # A score above 0.5 should give label PHISHING
        report = ThreatReport(score=0.92, reasons=["URL contains @ symbol"])
        self.assertEqual(report.label, "PHISHING")
        self.assertTrue(report.is_phishing())

    def test_legitimate_label(self):
        # A score below 0.5 should give label LEGITIMATE
        report = ThreatReport(score=0.12, reasons=[])
        self.assertEqual(report.label, "LEGITIMATE")
        self.assertFalse(report.is_phishing())

    def test_to_json_contains_score(self):
        # to_json() output should contain the score
        report = ThreatReport(score=0.85, reasons=["No HTTPS"])
        json_output = report.to_json()
        self.assertIn("0.85", json_output)

    def test_to_json_contains_label(self):
        # to_json() output should contain the label
        report = ThreatReport(score=0.85, reasons=["No HTTPS"])
        json_output = report.to_json()
        self.assertIn("PHISHING", json_output)


class TestPhishingDetector(unittest.TestCase):

    def test_invalid_url_raises_error(self):
        # An invalid URL should raise a ValueError
        detector = PhishingDetector()
        invalid_url = URLInput("not-a-valid-url")
        with self.assertRaises(ValueError):
            detector.analyze(invalid_url)

    def test_invalid_email_raises_error(self):
        # An email with invalid sender should raise a ValueError
        detector = PhishingDetector()
        invalid_email = EmailInput(
            raw_text="",
            subject="Test",
            sender="notvalid"
        )
        with self.assertRaises(ValueError):
            detector.analyze(invalid_email)


# This runs all tests when you execute this file directly
if __name__ == "__main__":
    unittest.main()