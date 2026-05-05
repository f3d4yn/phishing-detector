import os
import sys
import nltk

BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BOLD = '\033[1m'
ENDC = '\033[0m'

def download_nltk_data():
    packages = ['stopwords', 'punkt', 'punkt_tab']
    for package in packages:
        try:
            nltk.data.find(f'corpora/{package}')
        except LookupError:
            try:
                nltk.data.find(f'tokenizers/{package}')
            except LookupError:
                nltk.download(package, quiet=True)

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
    print(f"  1. Analyze a URL")
    print(f"  2. Analyze an Email")
    print(f"{RED}{'='*55}{ENDC}")

def get_model_path():
    # Look for model in ~/.isphishing/models/ first (PyPI install)
    home_models = os.path.join(os.path.expanduser("~"), ".isphishing", "models")
    model_path = os.path.join(home_models, "model.pkl")
    vectorizer_path = os.path.join(home_models, "vectorizer.pkl")

    if os.path.exists(model_path):
        return model_path, vectorizer_path

    # Fallback: look in current directory (GitHub install)
    local_model = os.path.join(os.getcwd(), "models", "model.pkl")
    local_vectorizer = os.path.join(os.getcwd(), "models", "vectorizer.pkl")

    if os.path.exists(local_model):
        return local_model, local_vectorizer

    return None, None

def main_cli():
    download_nltk_data()

    MODEL_PATH, VECTORIZER_PATH = get_model_path()

    sys.path.insert(0, os.getcwd())

    from src.detector.phishing_detector import PhishingDetector
    from src.inputs.email_input import EmailInput
    from src.inputs.url_input import URLInput

    if not MODEL_PATH:
        display_header()
        print(f"{RED}  Model not found!{ENDC}")
        print(f"  Please run: {BOLD}isphishing-setup{ENDC}")
        print(f"  Or visit: https://github.com/f3d4yn/phishing-detector")
        print(f"{RED}{'='*55}{ENDC}")
        return

    detector = PhishingDetector(
        model_path=MODEL_PATH,
        vectorizer_path=VECTORIZER_PATH
    )

    display_header()

    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == "1":
        url = input("» Enter the URL to analyze: ").strip()
        print(f"{YELLOW}[*] Processing URL: {url}...{ENDC}")
        try:
            report = detector.analyze(URLInput(url))
            print(f"\n{BOLD}--- ANALYSIS REPORT ---{ENDC}")
            print(report)
        except Exception as e:
            print(f"{RED}[!] An error occurred: {e}{ENDC}")

    elif choice == "2":
        sender = input("» Enter sender email: ").strip()
        subject = input("» Enter email subject: ").strip()
        body = input("» Enter email body: ").strip()
        print(f"{YELLOW}[*] Processing Email from: {sender}...{ENDC}")
        try:
            report = detector.analyze(EmailInput(body, subject, sender))
            print(f"\n{BOLD}--- ANALYSIS REPORT ---{ENDC}")
            print(report)
        except Exception as e:
            print(f"{RED}[!] An error occurred: {e}{ENDC}")
    else:
        print(f"{RED}Invalid choice. Please enter 1 or 2.{ENDC}")
