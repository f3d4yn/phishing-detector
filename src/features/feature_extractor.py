# re is used for pattern matching in text (regular expressions)
import re

# We import both input types so FeatureExtractor knows what it's working with
from src.inputs.base_input import BaseInput
from src.inputs.email_input import EmailInput
from src.inputs.url_input import URLInput

# TextCleaner is our utility class to clean raw text before analysis
from src.features.text_cleaner import TextCleaner

class FeatureExtractor:

    def __init__(self, input_data: BaseInput):
        # Store the input object (can be EmailInput or URLInput)
        self.input_data = input_data
        
        # Initialize the text cleaner for text processing
        self.cleaner = TextCleaner()
        
        # This dictionary will store all extracted features
        # It gets filled when extract() is called
        self.features = {}

    def get_url_features(self) -> dict:
        # Get the URL string from the input
        url = self.input_data.content
        
        # Feature 1: length of the URL
        # Phishing URLs tend to be longer than legitimate ones
        url_length = len(url)
        
        # Feature 2: check if URL contains @ symbol
        # Example: "http://google.com@evil.com" is a classic phishing trick
        has_at_symbol = 1 if "@" in url else 0
        
        # Feature 3: check if URL contains an IP address instead of a domain
        # Example: "http://192.168.1.1/login" is suspicious
        has_ip = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
        
        # Feature 4: check if URL uses HTTPS
        # HTTP (not secure) is more common in phishing URLs
        is_https = 1 if url.startswith("https://") else 0
        
        # Feature 5: count the number of subdomains
        # Example: "paypal.secure.login.evil.com" has 3 subdomains -> suspicious
        from src.inputs.url_input import URLInput
        import tldextract
        result = tldextract.extract(url)
        subdomain_count = len(result.subdomain.split('.')) if result.subdomain else 0
        
        # Feature 6: count special characters in the URL
        # Phishing URLs often have many special characters to confuse users
        special_chars = len(re.findall(r'[-_=&?%]', url))
        
        # Feature 7: length of the domain name
        # Very long domain names are often suspicious
        domain_length = len(result.domain)

        return {
            "url_length": url_length,
            "has_at_symbol": has_at_symbol,
            "has_ip": has_ip,
            "is_https": is_https,
            "subdomain_count": subdomain_count,
            "special_chars": special_chars,
            "domain_length": domain_length
        }

    def get_text_features(self) -> dict:
        # Get the text content and clean it first
        if isinstance(self.input_data, EmailInput):
            # For emails, use the combined subject + body text
            raw_text = self.input_data.get_combined_text()
        else:
            # For URLs, use the URL string itself as text
            raw_text = self.input_data.content

        # Clean the text using our TextCleaner
        cleaned_text = self.cleaner.clean(raw_text)

        # Feature 1: total number of words in the text
        word_count = len(cleaned_text.split())

        # Feature 2: count suspicious words commonly found in phishing
        # These words create urgency or ask for sensitive information
        suspicious_words = [
            "verify", "account", "password", "login", "urgent",
            "click", "confirm", "update", "secure", "bank",
            "suspend", "limited", "access", "credential"
        ]
        suspicious_count = sum(
            1 for word in suspicious_words if word in cleaned_text
        )

        # Feature 3: check if text contains a URL
        # Phishing emails often embed hidden URLs in the text
        has_url_in_text = 1 if re.search(r'http[s]?://', raw_text) else 0

        # Feature 4: check if text contains a phone number
        # Some phishing attempts ask you to call a fake number
        has_phone = 1 if re.search(r'\d{10}|\d{3}[-.\s]\d{3}[-.\s]\d{4}', raw_text) else 0

        return {
            "word_count": word_count,
            "suspicious_count": suspicious_count,
            "has_url_in_text": has_url_in_text,
            "has_phone": has_phone,
            "cleaned_text": cleaned_text
        }

    def extract(self) -> dict:
        # This is the main method that combines all features into one dictionary
        
        # Always extract URL features
        url_features = self.get_url_features()
        
        # Always extract text features
        text_features = self.get_text_features()
        
        # Merge both dictionaries into self.features
        self.features = {**url_features, **text_features}
        
        return self.features