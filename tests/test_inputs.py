# unittest is Python's built-in testing framework
import unittest

# Import the classes we want to test
from src.inputs.email_input import EmailInput
from src.inputs.url_input import URLInput

class TestEmailInput(unittest.TestCase):

    def test_valid_email(self):
        # Create a normal valid email
        email = EmailInput(
            raw_text="Please verify your account immediately",
            subject="Urgent action required",
            sender="support@paypal.com"
        )
        # validate() should return True for a valid email
        self.assertTrue(email.validate())

    def test_empty_body(self):
        # An email with empty body should fail validation
        email = EmailInput(
            raw_text="",
            subject="Hello",
            sender="test@gmail.com"
        )
        self.assertFalse(email.validate())

    def test_invalid_sender(self):
        # A sender without @ should fail validation
        email = EmailInput(
            raw_text="Click here to verify",
            subject="Urgent",
            sender="notanemailaddress"
        )
        self.assertFalse(email.validate())

    def test_timestamp_exists(self):
        # Every EmailInput should have a timestamp
        email = EmailInput(
            raw_text="Hello",
            subject="Test",
            sender="test@test.com"
        )
        self.assertIsNotNone(email.timestamp)

    def test_combined_text(self):
        # get_combined_text() should merge subject and body
        email = EmailInput(
            raw_text="your account is suspended",
            subject="Urgent notice",
            sender="test@test.com"
        )
        combined = email.get_combined_text()
        # Both subject and body should appear in combined text
        self.assertIn("Urgent notice", combined)
        self.assertIn("your account is suspended", combined)


class TestURLInput(unittest.TestCase):

    def test_valid_url(self):
        # A proper URL should pass validation
        url = URLInput("https://www.google.com")
        self.assertTrue(url.validate())

    def test_invalid_url_no_protocol(self):
        # URL without http:// or https:// should fail
        url = URLInput("www.google.com")
        self.assertFalse(url.validate())

    def test_https_detection(self):
        # is_https should be True for HTTPS URLs
        url = URLInput("https://www.google.com")
        self.assertTrue(url.is_https)

    def test_http_not_https(self):
        # is_https should be False for HTTP URLs
        url = URLInput("http://suspicious-site.com")
        self.assertFalse(url.is_https)

    def test_domain_extraction(self):
        # extract_domain() should return the real domain
        url = URLInput("http://paypal-secure.login-now.com/verify")
        self.assertEqual(url.domain, "login-now.com")

    def test_content_stored(self):
        # self.content should store the original URL
        url = URLInput("https://www.google.com")
        self.assertEqual(url.content, "https://www.google.com")


# This runs all tests when you execute this file directly
if __name__ == "__main__":
    unittest.main()