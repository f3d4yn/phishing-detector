import os
import urllib.request

def setup_cli():
    print("=" * 50)
    print("  Phishing Detector - Setup")
    print("=" * 50)
    
    # Create models directory
    models_dir = os.path.join(os.getcwd(), "models")
    os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, "model.pkl")
    vectorizer_path = os.path.join(models_dir, "vectorizer.pkl")
    
    base_url = "https://github.com/f3d4yn/phishing-detector/raw/main/models"
    
    # Download model.pkl
    if not os.path.exists(model_path):
        print("Downloading model.pkl (85MB)...")
        urllib.request.urlretrieve(
            f"{base_url}/model.pkl",
            model_path,
            reporthook=lambda b, bs, t: print(f"  {min(100, int(b*bs*100/t))}%", end="\r")
        )
        print("  model.pkl downloaded ✅")
    else:
        print("  model.pkl already exists ✅")
    
    # Download vectorizer.pkl
    if not os.path.exists(vectorizer_path):
        print("Downloading vectorizer.pkl...")
        urllib.request.urlretrieve(
            f"{base_url}/vectorizer.pkl",
            vectorizer_path
        )
        print("  vectorizer.pkl downloaded ✅")
    else:
        print("  vectorizer.pkl already exists ✅")
    
    print("")
    print("Setup complete! Run: isphishing")
    print("=" * 50)
