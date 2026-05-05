import re
import math
from urllib.parse import urlparse
from src.inputs.base_input import BaseInput
from src.inputs.email_input import EmailInput
from src.inputs.url_input import URLInput
from src.features.text_cleaner import TextCleaner
import tldextract


class FeatureExtractor:

    def __init__(self, input_data: BaseInput):
        self.input_data = input_data
        self.cleaner = TextCleaner()
        self.features = {}

    def _entropy(self, s: str) -> float:
        if not s:
            return 0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        return -sum(
            (f / len(s)) * math.log2(f / len(s))
            for f in freq.values()
        )

    def get_url_features(self) -> dict:
        url = self.input_data.content
        result = tldextract.extract(url)

        # ── features existantes ──────────────────────────────
        url_length      = len(url)
        has_at_symbol   = 1 if "@" in url else 0
        has_ip          = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
        is_https        = 1 if url.startswith("https://") else 0
        subdomain_count = len(result.subdomain.split('.')) if result.subdomain else 0
        special_chars   = len(re.findall(r'[-_=&?%]', url))
        domain_length   = len(result.domain)
        digit_count     = len(re.findall(r'\d', url))
        digit_ratio     = digit_count / url_length if url_length > 0 else 0

        url_suspicious_words = [
            "login", "secure", "verify", "account", "update",
            "banking", "confirm", "paypal", "ebay", "amazon",
            "apple", "microsoft", "password", "credential", "signin"
        ]
        url_suspicious_count = sum(
            1 for word in url_suspicious_words if word in url.lower()
        )

        path_length       = len(url.split('/', 3)[-1]) if '/' in url else 0
        dot_count         = url.count('.')
        has_double_slash  = 1 if '//' in url[7:] else 0
        has_hyphen_domain = 1 if '-' in result.domain else 0
        tld_length        = len(result.suffix)
        has_url_encoding  = 1 if '%' in url else 0

        # ── nouvelles features ───────────────────────────────
        slash_count        = url.count('/')
        query_params_count = len(re.findall(r'&', url))
        has_port           = 1 if re.search(r':\d+', url) else 0
        subdomain_length   = len(result.subdomain) if result.subdomain else 0

        consonants      = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]', result.domain.lower()))
        consonant_ratio = consonants / len(result.domain) if len(result.domain) > 0 else 0

        brand_words = [
            "paypal", "google", "apple", "microsoft", "amazon",
            "facebook", "netflix", "instagram", "twitter", "bank",
            "ebay", "linkedin", "dropbox", "yahoo", "outlook"
        ]
        has_brand_in_domain    = 1 if any(b in result.domain.lower()    for b in brand_words) else 0
        has_brand_in_subdomain = 1 if any(b in result.subdomain.lower() for b in brand_words) else 0

        try:
            parsed       = urlparse(url)
            path_depth   = parsed.path.count('/')
            query_length = len(parsed.query)
        except Exception:
            path_depth   = 0
            query_length = 0

        domain_entropy    = self._entropy(result.domain)
        subdomain_entropy = self._entropy(result.subdomain)

        suspicious_tlds = [
            "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club",
            "online", "site", "website", "space", "fun", "icu"
        ]
        has_suspicious_tld = 1 if result.suffix in suspicious_tlds else 0

        return {
            "url_length":             url_length,
            "has_at_symbol":          has_at_symbol,
            "has_ip":                 has_ip,
            "is_https":               is_https,
            "subdomain_count":        subdomain_count,
            "special_chars":          special_chars,
            "domain_length":          domain_length,
            "digit_count":            digit_count,
            "digit_ratio":            digit_ratio,
            "url_suspicious_count":   url_suspicious_count,
            "path_length":            path_length,
            "dot_count":              dot_count,
            "has_double_slash":       has_double_slash,
            "has_hyphen_domain":      has_hyphen_domain,
            "tld_length":             tld_length,
            "has_url_encoding":       has_url_encoding,
            "slash_count":            slash_count,
            "query_params_count":     query_params_count,
            "has_port":               has_port,
            "subdomain_length":       subdomain_length,
            "consonant_ratio":        consonant_ratio,
            "has_brand_in_domain":    has_brand_in_domain,
            "has_brand_in_subdomain": has_brand_in_subdomain,
            "path_depth":             path_depth,
            "query_length":           query_length,
            "domain_entropy":         domain_entropy,
            "subdomain_entropy":      subdomain_entropy,
            "has_suspicious_tld":     has_suspicious_tld,
        }

    def get_text_features(self) -> dict:
        if isinstance(self.input_data, EmailInput):
            raw_text = self.input_data.get_combined_text()
        else:
            raw_text = self.input_data.content

        cleaned_text = self.cleaner.clean(raw_text)

        # ── features existantes ──────────────────────────────
        word_count = len(cleaned_text.split())

        suspicious_words = [
            "verify", "account", "password", "login", "urgent",
            "click", "confirm", "update", "secure", "bank",
            "suspend", "limited", "access", "credential"
        ]
        suspicious_count = sum(
            1 for word in suspicious_words if word in cleaned_text
        )
        has_url_in_text = 1 if re.search(r'http[s]?://', raw_text) else 0
        has_phone       = 1 if re.search(r'\d{10}|\d{3}[-.\s]\d{3}[-.\s]\d{4}', raw_text) else 0

        # ── nouvelles features ───────────────────────────────
        uppercase_count   = sum(1 for c in raw_text if c.isupper())
        uppercase_ratio   = uppercase_count / len(raw_text) if len(raw_text) > 0 else 0
        html_link_count   = len(re.findall(r'<a\s+href=', raw_text, re.IGNORECASE))

        urgency_words = [
            "urgent", "immediately", "now", "expire", "suspend",
            "limited", "warning", "alert", "critical", "action required"
        ]
        urgency_count = sum(
            1 for word in urgency_words if word in cleaned_text.lower()
        )

        financial_words = [
            "bank", "credit", "debit", "card", "payment", "transfer",
            "wire", "fund", "invoice", "transaction", "billing"
        ]
        financial_count   = sum(
            1 for word in financial_words if word in cleaned_text.lower()
        )
        exclamation_count = raw_text.count('!')
        digit_count_text  = len(re.findall(r'\d', raw_text))
        digit_ratio_text  = digit_count_text / len(raw_text) if len(raw_text) > 0 else 0

        return {
            "word_count":        word_count,
            "suspicious_count":  suspicious_count,
            "has_url_in_text":   has_url_in_text,
            "has_phone":         has_phone,
            "uppercase_ratio":   uppercase_ratio,
            "html_link_count":   html_link_count,
            "urgency_count":     urgency_count,
            "financial_count":   financial_count,
            "exclamation_count": exclamation_count,
            "digit_ratio_text":  digit_ratio_text,
            "cleaned_text":      cleaned_text
        }

    def extract(self) -> dict:
        url_features  = self.get_url_features()
        text_features = self.get_text_features()
        self.features = {**url_features, **text_features}
        return self.features