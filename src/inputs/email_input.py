from datetime import datetime

# Import the abstract parent class
from src.inputs.base_input import BaseInput

# EmailInput represents an email to be analyzed for phishing
# It inherits content and timestamp from BaseInput
class EmailInput(BaseInput):

    def __init__(self, raw_text: str, subject: str, sender: str):
        # Call BaseInput's __init__ to set self.content and self.timestamp
        # We pass raw_text as the main content of this input
        super().__init__(raw_text)
        
        # Store the full body of the email
        self.raw_text = raw_text
        
        # Store the subject line of the email
        self.subject = subject
        
        # Store the sender's email address
        self.sender = sender

    def validate(self) -> bool:
        # Check that the email body is not empty
        if not self.content:
            return False
        
        # Check that the sender looks like a real email address
        if "@" not in self.sender:
            return False
        
        # All checks passed, the input is valid
        return True

    def get_combined_text(self) -> str:
        # Merge subject and body into one string
        # This will be used later by FeatureExtractor to analyze the full email
        return f"{self.subject} {self.raw_text}"