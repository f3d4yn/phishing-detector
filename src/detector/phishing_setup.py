import os
import sys
import urllib.request
import subprocess

def fix_path():
    # Detect the local bin directory
    local_bin = os.path.expanduser("~/.local/bin")
    
    # Detect shell config file
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        rc_file = os.path.expanduser("~/.zshrc")
    else:
        rc_file = os.path.expanduser("~/.bashrc")
    
    # Check if already in PATH
    if local_bin in os.environ.get("PATH", ""):
        return
    
    # Add to shell config if not already there
    export_line = f'\nexport PATH="$PATH:{local_bin}"\n'
    try:
        with open(rc_file, 'r') as f:
            content = f.read()
        if local_bin not in content:
            with open(rc_file, 'a') as f:
                f.write(export_line)
            print(f"[+] Added {local_bin} to PATH in {rc_file}")
            print(f"[!] Run: source {rc_file}")
            print(f"[!] Then run: isphishing-setup again")
            sys.exit(0)
    except Exception:
        pass

def setup_cli():
    # Fix PATH first
    fix_path()
    
    print("=" * 50)
    print("  Phishing Detector - Setup")
    print("=" * 50)

    models_dir = os.path.join(os.path.expanduser("~"), ".isphishing", "models")
    os.makedirs(models_dir, exist_ok=True)

    model_path = os.path.join(models_dir, "model.pkl")
    vectorizer_path = os.path.join(models_dir, "vectorizer.pkl")

    base_url = "https://github.com/f3d4yn/phishing-detector/raw/main/models"

    if not os.path.exists(model_path):
        print("Downloading model.pkl (85MB)...")
        try:
            urllib.request.urlretrieve(
                f"{base_url}/model.pkl",
                model_path,
                reporthook=lambda b, bs, t: print(f"  {min(100, int(b*bs*100/t if t>0 else 0))}%", end="\r")
            )
            print("\n  model.pkl downloaded ✅")
        except Exception as e:
            print(f"  Error: {e}")
            print("  Please download manually from GitHub")
            return
    else:
        print("  model.pkl already exists ✅")

    if not os.path.exists(vectorizer_path):
        print("Downloading vectorizer.pkl...")
        try:
            urllib.request.urlretrieve(
                f"{base_url}/vectorizer.pkl",
                vectorizer_path
            )
            print("  vectorizer.pkl downloaded ✅")
        except Exception as e:
            print(f"  Error: {e}")
            return
    else:
        print("  vectorizer.pkl already exists ✅")

    print("")
    print("Setup complete! Run: isphishing")
    print("=" * 50)
