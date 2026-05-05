import re
import pandas as pd
import tldextract
from isphishing.inputs.base_input import BaseInput
from isphishing.inputs.email_input import EmailInput
from isphishing.inputs.url_input import URLInput
from isphishing.features.feature_extractor import FeatureExtractor
from isphishing.model.ml_model import MLModel
from isphishing.detector.threat_report import ThreatReport
from isphishing.alert.alert_system import AlertSystem

TRUSTED_DOMAINS = [
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "tiktok.com", "snapchat.com", "pinterest.com", "reddit.com", "tumblr.com",
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "docker.com", "npmjs.com", "pypi.org", "anaconda.com", "jupyter.org",
    "microsoft.com", "office.com", "outlook.com", "live.com", "hotmail.com",
    "azure.com", "onedrive.com", "sharepoint.com", "xbox.com",
    "gmail.com", "youtube.com", "maps.google.com", "play.google.com", "cloud.google.com",
    "apple.com", "icloud.com", "itunes.com",
    "amazon.com", "amazon.fr", "amazon.co.uk", "aws.amazon.com", "aws.com",
    "netflix.com", "spotify.com", "twitch.tv", "hulu.com", "disneyplus.com",
    "primevideo.com", "soundcloud.com",
    "claude.ai", "anthropic.com", "openai.com", "chatgpt.com",
    "huggingface.co", "kaggle.com",
    "paypal.com", "stripe.com", "visa.com", "mastercard.com",
    "bbc.com", "cnn.com", "reuters.com", "nytimes.com", "theguardian.com",
    "lemonde.fr", "lefigaro.fr",
    "wikipedia.org", "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    "mit.edu", "harvard.edu", "stanford.edu",
    "cloudflare.com", "digitalocean.com", "heroku.com", "netlify.com",
    "vercel.com",
    "dropbox.com", "notion.so", "slack.com", "zoom.us", "discord.com",
    "trello.com", "atlassian.com", "wordpress.com", "medium.com", "substack.com"
]

TRUSTED_SENDERS = [
    "google.com", "bing.com", "yahoo.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "tiktok.com", "pinterest.com", "reddit.com",
    "github.com", "gitlab.com", "stackoverflow.com", "docker.com",
    "npmjs.com", "pypi.org",
    "microsoft.com", "outlook.com", "live.com", "hotmail.com",
    "office.com", "azure.com",
    "google.com", "gmail.com", "youtube.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.fr", "amazon.co.uk", "aws.amazon.com",
    "netflix.com", "spotify.com", "twitch.tv", "disneyplus.com",
    "anthropic.com", "openai.com", "claude.ai",
    "paypal.com", "stripe.com",
    "bbc.com", "cnn.com", "nytimes.com",
    "coursera.org", "udemy.com", "edx.org",
    "cloudflare.com", "digitalocean.com", "heroku.com",
    "dropbox.com", "notion.so", "slack.com", "zoom.us", "discord.com",
    "wordpress.com", "medium.com"
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
        if isinstance(input_data, EmailInput):
            threshold = self.email_threshold
        else:
            threshold = self.url_threshold

        reasons = self._get_reasons(features, score, input_data, threshold)
        report  = ThreatReport(score=score, reasons=reasons, threshold=threshold)
        self.alert.threshold = threshold
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