# Import the abstract base class we created
from src.inputs.base_input import BaseInput

# tldextract is used to properly split a URL into its parts
# Example: "http://paypal-secure.login-now.com" -> domain="login-now", suffix="com"
import tldextract

class URLInput(BaseInput):
    
    def __init__(self, url: str):
        # Call the parent class __init__ to set self.content and self.timestamp
        super().__init__(url)
        
        # Store the original URL
        self.url = url
        
        # Automatically extract the domain when the object is created
        # Example: "http://paypal-secure.login-now.com" -> "login-now.com"
        self.domain = self.extract_domain()
        
        # Check if the URL uses HTTPS (more secure) or HTTP (suspicious)
        self.is_https = url.startswith("https://")

    def extract_domain(self) -> str:
        # Use tldextract to split the URL into parts
        result = tldextract.extract(self.content)
        
        # Combine domain + suffix to get the real domain
        # Example: domain="login-now", suffix="com" -> "login-now.com"
        return f"{result.domain}.{result.suffix}"

    def validate(self) -> bool:
        # Check that the URL starts with http:// or https://
        if not self.content.startswith(("http://", "https://")):
            return False
        
        # Check that we were able to extract a valid domain
        if not self.domain:
            return False
        
        # If all checks pass, the URL is valid
        return True