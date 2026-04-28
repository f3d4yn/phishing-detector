import json

class ThreatReport:

    def __init__(self, score: float, reasons: list, threshold: float = 0.5):
        self.score = score
        self.threshold = threshold

        # Use the provided threshold to determine the label
        self.label = "PHISHING" if score > threshold else "LEGITIMATE"
        self.reasons = reasons

    def is_phishing(self) -> bool:
        return self.label == "PHISHING"

    def to_json(self) -> str:
        report_dict = {
            "score": round(self.score, 4),
            "label": self.label,
            "is_phishing": self.is_phishing(),
            "reasons": self.reasons
        }
        return json.dumps(report_dict, indent=2)

    def __str__(self) -> str:
        return self.to_json()
