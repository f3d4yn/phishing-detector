import re
import pandas as pd
from src.inputs.base_input import BaseInput
from src.inputs.email_input import EmailInput
from src.inputs.url_input import URLInput
from src.features.feature_extractor import FeatureExtractor
from src.model.ml_model import MLModel
from src.detector.threat_report import ThreatReport
from src.alert.alert_system import AlertSystem

class PhishingDetector:

    def __init__(self, model_path: str = None, vectorizer_path: str = None):
        self.extractor = None
        self.model = MLModel()

        # Threshold for URLs
        self.url_threshold = 0.50

        # Threshold for emails
        self.email_threshold = 0.55

        self.alert = AlertSystem(threshold=self.url_threshold)
        if model_path and vectorizer_path:
            self.model.load(model_path, vectorizer_path)

    def analyze(self, input_data: BaseInput) -> ThreatReport:
        if not input_data.validate():
            raise ValueError("Invalid input. Please check your email or URL.")

        self.extractor = FeatureExtractor(input_data)
        features = self.extractor.extract()
        X = pd.DataFrame([features])
        score = self.model.predict(X)

        # Use different threshold depending on input type
        if isinstance(input_data, EmailInput):
            threshold = self.email_threshold
        else:
            threshold = self.url_threshold

        reasons = self._get_reasons(features, score, input_data, threshold)
        report = ThreatReport(score=score, reasons=reasons, threshold=threshold)
        self.alert.threshold = threshold
        self.alert.send_alert(report)

        return report

    def _get_reasons(self, features: dict, score: float, input_data: BaseInput, threshold: float) -> list:
        reasons = []

        # URL-specific checks
        if isinstance(input_data, URLInput):
            url = input_data.content

            if features.get("has_at_symbol"):
                reasons.append("URL contains @ symbol")

            if features.get("has_ip"):
                reasons.append("URL uses IP address instead of domain")

            # Version "Alerte de Sécurité Systématique"
            if not features.get("is_https"):
                reasons.append("SECURITY WARNING: This site does not use an encrypted connection (No HTTPS)")
            if features.get("url_length", 0) > 75:
                reasons.append("URL is unusually long")

            if features.get("subdomain_count", 0) > 2:
                reasons.append("URL has too many subdomains")

            # Check for suspicious TLDs commonly used in phishing
            suspicious_tlds = ['.support', '.click', '.top', '.xyz', '.online', '.site', '.tk']
            if any(url.lower().endswith(tld) or tld + '/' in url.lower() for tld in suspicious_tlds):
                reasons.append("URL uses a suspicious domain extension")

            # Check for brand impersonation in URL
            brands = ['paypal', 'google', 'facebook', 'apple', 'amazon', 'microsoft', 'netflix']
            domain = input_data.domain.lower()
            for brand in brands:
                if brand in url.lower() and brand not in domain:
                    reasons.append(f"URL impersonates {brand} in the path")
                    break

            # Check for hyphens in domain (common phishing trick)
            if features.get("domain_length", 0) > 0:
                import tldextract
                result = tldextract.extract(url)
                if result.domain.count('-') >= 2:
                    reasons.append("Domain contains multiple hyphens")

            # Check for 'secure', 'login', 'verify' keywords in domain
            phishing_keywords = ['secure', 'login', 'verify', 'account', 'update', 'confirm']
            import tldextract
            result = tldextract.extract(url)
            full_domain = f"{result.subdomain}.{result.domain}".lower()
            matched = [kw for kw in phishing_keywords if kw in full_domain]
            if len(matched) >= 2:
                reasons.append(f"Domain contains suspicious keywords: {', '.join(matched)}")


        # Email-specific checks
        if isinstance(input_data, EmailInput):
            # 1. Vérifier si des mots-clés d'urgence sont présents
            urgent_keywords = ['urgent', 'suspension', 'supprimé', 'vérifier', 'sécurité']
            content_lower = input_data.content.lower()
            found_urgent = [word for word in urgent_keywords if word in content_lower]
            if len(found_urgent) >= 2:
                reasons.append(f"Email uses urgent language: {', '.join(found_urgent)}")

            # 2. Vérifier si l'expéditeur a une extension suspecte
            if any(ext in input_data.sender for ext in ['.xyz', '.online', '.top']):
                reasons.append("Sender address uses a suspicious domain extension")

            # 3. Vérifier si le score est élevé (même sans raisons techniques)
            if score > 0.60:
                reasons.append("ML model detected high-risk patterns in text")

    def load_model(self, model_path: str, vectorizer_path: str) -> None:
        self.model.load(model_path, vectorizer_path)

def main_cli():
    from config import MODEL_PATH, VECTORIZER_PATH
    from src.inputs.email_input import EmailInput
    from src.inputs.url_input import URLInput
    import os, sys

    # Change to package directory so paths work correctly
    package_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    os.chdir(package_dir)
    sys.path.insert(0, package_dir)

    detector = PhishingDetector(
        model_path=MODEL_PATH,
        vectorizer_path=VECTORIZER_PATH
    )

    print("=" * 50)
    print("      PHISHING DETECTOR - by f3d4yn")
    print("=" * 50)
    print("1. Analyze a URL")
    print("2. Analyze an Email")
    print("=" * 50)

    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == "1":
        url = input("Enter the URL to analyze: ").strip()
        report = detector.analyze(URLInput(url))
        print(report)
    elif choice == "2":
        sender = input("Enter sender email: ").strip()
        subject = input("Enter email subject: ").strip()
        body = input("Enter email body: ").strip()
        report = detector.analyze(EmailInput(body, subject, sender))
        print(report)
    else:
        print("Invalid choice.")
