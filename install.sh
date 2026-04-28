#!/bin/bash
echo "Installing Phishing Detector..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download NLTK data
python3 -c "import nltk; nltk.download('stopwords'); nltk.download('punkt')"

# Make isphishing executable
chmod +x isphishing

# Add isphishing to PATH (Linux/Mac)
INSTALL_DIR=$(pwd)
SHELL_RC="$HOME/.bashrc"

# Detect shell
if [ -n "$ZSH_VERSION" ]; then
    SHELL_RC="$HOME/.zshrc"
fi

# Add alias if not already there
if ! grep -q "alias isphishing" "$SHELL_RC"; then
    echo "" >> "$SHELL_RC"
    echo "# Phishing Detector" >> "$SHELL_RC"
    echo "alias isphishing='$INSTALL_DIR/isphishing'" >> "$SHELL_RC"
    echo "Added isphishing to $SHELL_RC"
fi

echo ""
echo "Installation complete!"
echo "Run: source ~/.bashrc (or restart terminal)"
echo "Then type: isphishing"
