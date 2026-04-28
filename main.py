import sys
from src.detector.phishing_detector import PhishingDetector
from src.inputs.email_input import EmailInput
from src.inputs.url_input import URLInput
from config import MODEL_PATH, VECTORIZER_PATH

# Couleurs pour le terminal Kali
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BOLD = '\033[1m'
ENDC = '\033[0m'
def display_header():
    banner = rf"""{BLUE}{BOLD}
    _                  __    _      __    _            
   (_)____      ____  / /_  (_)____/ /_  (_)___  ____ _
  / / ___/     / __ \/ __ \/ / ___/ __ \/ / __ \/ __ `/
 / (__  )     / /_/ / / / / (__  ) / / / / / / / /_/ / 
/_/____/_____/ .___/_/ /_/_/____/_/ /_/_/_/ /_/\__, /  
      /_____/_/                               /____/   
       by : Habib Ilyas & Boukyod Abdessamad    
{ENDC}"""
    print(banner)
    print(f"{RED}{'='*55}{ENDC}")
    print(f"{BOLD}Choose what to analyze:{ENDC}")
    print(f"  1.{ENDC} Analyze a URL")
    print(f"  2.{ENDC} Analyze an Email")
    print(f"{RED}{'='*55}{ENDC}")

def analyze_url(url: str):
    print(f"\n{BLUE}[*]{ENDC} Processing URL: {url}...")
    input_data = URLInput(url)
    detector = PhishingDetector(model_path=MODEL_PATH, vectorizer_path=VECTORIZER_PATH)
    report = detector.analyze(input_data)
    print(f"\n{BOLD}--- ANALYSIS REPORT ---{ENDC}")
    print(report)

def analyze_email(subject: str, body: str, sender: str):
    print(f"\n{BLUE}[*]{ENDC} Processing Email from: {sender}...")
    input_data = EmailInput(raw_text=body, subject=subject, sender=sender)
    detector = PhishingDetector(model_path=MODEL_PATH, vectorizer_path=VECTORIZER_PATH)
    report = detector.analyze(input_data)
    print(f"\n{BOLD}--- ANALYSIS REPORT ---{ENDC}")
    print(report)

def main():
    try:
        display_header()
        
        choice = input(f"{BOLD}Enter your choice (1 or 2): {ENDC}").strip()
        
        if choice == "1":
            url = input(f"{BLUE}»{ENDC} Enter the URL to analyze: ").strip()
            if url:
                analyze_url(url)
            else:
                print(f"{RED}[!] Error: URL cannot be empty.{ENDC}")
        
        elif choice == "2":
            sender = input(f"{BLUE}»{ENDC} Enter sender email: ").strip()
            subject = input(f"{BLUE}»{ENDC} Enter email subject: ").strip()
            body = input(f"{BLUE}»{ENDC} Enter email body: ").strip()
            analyze_email(subject, body, sender)
        
        else:
            print(f"{RED}[!] Invalid choice. Please enter 1 or 2.{ENDC}")

    except KeyboardInterrupt:
        print(f"\n\n{RED}[-] Interrupted by user. Exiting...{ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}[!] An error occurred: {e}{ENDC}")

if __name__ == "__main__":
    main()