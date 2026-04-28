@echo off
echo Installing Phishing Detector...

:: Create virtual environment
python -m venv venv

:: Activate and install dependencies
call venv\Scripts\activate.bat
pip install -r requirements.txt

:: Download NLTK data
python -c "import nltk; nltk.download('stopwords'); nltk.download('punkt')"

:: Add isphishing to PATH permanently
setx PATH "%PATH%;%CD%"

echo.
echo Installation complete!
echo Restart your terminal then type: isphishing
pause
