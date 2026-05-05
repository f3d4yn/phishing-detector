import re
import pandas as pd
import tldextract
from src.inputs.base_input import BaseInput
from src.inputs.email_input import EmailInput
from src.inputs.url_input import URLInput
from src.features.feature_extractor import FeatureExtractor
from src.model.ml_model import MLModel
from src.detector.threat_report import ThreatReport
from src.alert.alert_system import AlertSystem

TRUSTED_DOMAINS = [
    "github.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "twitter.com", "linkedin.com",
    "stackoverflow.com", "wikipedia.org", "youtube.com",
    "gitlab.com", "bitbucket.org"
]
TRUSTED_SENDERS = [
    "github.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "twitter.com", "linkedin.com",
    "stackoverflow.com", "youtube.com", "gitlab.com"
]

class PhishingDetector:

    def __init__(self, model_path: str = None, vectorizer_path: str = None):
        self.extractor       = None
        self.model           = MLModel()
        self.url_threshold   = 0.50
        self.email_threshold = 0.75
        self.alert           = AlertSystem(threshold=self.url_threshold)
        if model_path and vectorizer_path:
            self.model.load(model_path, vectorizer_path)

    def analyze(self, input_data: BaseInput) -> ThreatReport:
        if not input_data.validate():
            raise ValueError("Invalid input. Please check your email or URL.")

        # ✅ Whitelist — domaines de confiance
        if isinstance(input_data, URLInput):
            result            = tldextract.extract(input_data.content)
            registered_domain = f"{result.domain}.{result.suffix}"
            if registered_domain in TRUSTED_DOMAINS:
                report = ThreatReport(
                    score=0.01,
                    reasons=["Domain is in trusted whitelist"],
                    threshold=self.url_threshold
                )
                self.alert.send_alert(report)
                return report

        self.extractor = FeatureExtractor(input_data)
        features       = self.extractor.extract()
        X              = pd.DataFrame([features])
        score          = float(self.model.predict(X))

        # ✅ Whitelist expéditeurs de confiance
        if isinstance(input_data, EmailInput):
            sender_domain = tldextract.extract(input_data.sender)
            registered    = f"{sender_domain.domain}.{sender_domain.suffix}"
            if registered in TRUSTED_SENDERS:
                report = ThreatReport(
                    score=0.01,
                    reasons=["Sender domain is trusted"],
                    threshold=self.email_threshold
                )
                self.alert.send_alert(report)
                return report

    def _get_reasons(self, features: dict, score: float, input_data: BaseInput, threshold: float) -> list:
        reasons = []

        if isinstance(input_data, URLInput):
            url    = input_data.content
            result = tldextract.extract(url)

            if features.get("has_at_symbol"):
                reasons.append("URL contains @ symbol")

            if features.get("has_ip"):
                reasons.append("URL uses IP address instead of domain")

            if not features.get("is_https"):
                reasons.append("SECURITY WARNING: No HTTPS encryption")

            if features.get("url_length", 0) > 75:
                reasons.append("URL is unusually long")

            if features.get("subdomain_count", 0) > 2:
                reasons.append("URL has too many subdomains")

            suspicious_tlds = ['.support', '.click', '.top', '.xyz', '.online', '.site', '.tk']
            if any(url.lower().endswith(tld) or tld + '/' in url.lower() for tld in suspicious_tlds):
                reasons.append("URL uses a suspicious domain extension")

            brands = ['paypal', 'google', 'facebook', 'apple', 'amazon', 'microsoft', 'netflix']
            domain = input_data.domain.lower()
            for brand in brands:
                if brand in url.lower() and brand not in domain:
                    reasons.append(f"URL impersonates {brand} in the path")
                    break

            if result.domain.count('-') >= 2:
                reasons.append("Domain contains multiple hyphens")

            full_domain       = f"{result.subdomain}.{result.domain}".lower()
            phishing_keywords = ['secure', 'login', 'verify', 'account', 'update', 'confirm']
            matched           = [kw for kw in phishing_keywords if kw in full_domain]
            if len(matched) >= 2:
                reasons.append(f"Domain contains suspicious keywords: {', '.join(matched)}")

            if features.get("url_suspicious_count", 0) > 0:
                reasons.append("URL contains suspicious keywords")

            if features.get("domain_entropy", 0) > 3.5:
                reasons.append("Domain name appears randomly generated")

            if features.get("has_suspicious_tld"):
                reasons.append("URL uses a suspicious TLD")

            if features.get("digit_ratio", 0) > 0.2:
                reasons.append("URL contains an unusual amount of digits")

            if score > threshold and not reasons:
                reasons.append("ML model detected suspicious patterns in URL structure")

        if isinstance(input_data, EmailInput):
            urgent_keywords = ['urgent', 'suspension', 'supprimé', 'vérifier', 'sécurité']
            content_lower   = input_data.content.lower()
            found_urgent    = [word for word in urgent_keywords if word in content_lower]
            if len(found_urgent) >= 2:
                reasons.append(f"Email uses urgent language: {', '.join(found_urgent)}")

            if any(ext in input_data.sender for ext in ['.xyz', '.online', '.top']):
                reasons.append("Sender address uses a suspicious domain extension")

            if score > 0.60:
                reasons.append("ML model detected high-risk patterns in text")

        return reasons

    def load_model(self, model_path: str, vectorizer_path: str) -> None:
        self.model.load(model_path, vectorizer_path)