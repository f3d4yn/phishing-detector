import os
import sys
import urllib.request

def setup_cli():
    print("=" * 50)
    print("  Phishing Detector - Setup")
    print("=" * 50)

    models_dir = os.path.join(os.path.expanduser("~"), ".isphishing", "models")
    os.makedirs(models_dir, exist_ok=True)

    base_url = "https://github.com/f3d4yn/isphishing/raw/main/models"

    files = [
        "model_url.pkl",
        "model_email.pkl",
        "vectorizer_url.pkl",
        "vectorizer_email.pkl"
    ]

    for filename in files:
        filepath = os.path.join(models_dir, filename)
        if not os.path.exists(filepath):
            print(f"Downloading {filename}...")
            try:
                urllib.request.urlretrieve(
                    f"{base_url}/{filename}",
                    filepath,
                    reporthook=lambda b, bs, t: print(
                        f"  {min(100, int(b*bs*100/t if t>0 else 0))}%", end="\r"
                    )
                )
                print(f"\n  {filename} downloaded ✅")
            except Exception as e:
                print(f"  Error downloading {filename}: {e}")
                print("  Please download manually from GitHub")
                return
        else:
            print(f"  {filename} already exists ✅")

    print("")
    print("Setup complete! Run: isphishing")
    print("=" * 50)