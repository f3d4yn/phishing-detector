# os is used to create directories and handle file paths
import os

# json is used to format the alert logs nicely
import json

# datetime is used to timestamp each alert
from datetime import datetime

class AlertSystem:

    def __init__(self, threshold: float = 0.7, log_file: str = "logs/alerts.log"):
        # threshold is the minimum phishing score to trigger an alert
        # Example: if score=0.85 and threshold=0.7 -> alert is triggered
        self.threshold = threshold
        
        # Path to the log file where alerts are saved
        self.log_file = log_file
        
        # Create the logs directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

    def should_alert(self, score: float) -> bool:
        # Returns True if the phishing score exceeds the threshold
        return score >= self.threshold

    def send_alert(self, report) -> None:
        # Only send alert if score is above threshold
        if not self.should_alert(report.score):
            return
        
        # Print the alert to the terminal in a clear format
        print("=" * 50)
        print("          PHISHING ALERT DETECTED")
        print("=" * 50)
        print(f"Score     : {report.score:.2%}")
        print(f"Label     : {report.label}")
        print(f"Reasons   : {', '.join(report.reasons)}")
        print(f"Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        # Also save the alert to the log file
        self.log_event(report)

    def log_event(self, report) -> None:
        # Create a dictionary with all alert information
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score": report.score,
            "label": report.label,
            "reasons": report.reasons,
            "is_phishing": report.is_phishing()
        }
        
        # Append the log entry to the log file as JSON
        # 'a' mode means we add to the file without overwriting previous logs
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')