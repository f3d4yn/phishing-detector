from setuptools import setup, find_packages

setup(
    name="isphishing",
    version="1.0.0",
    author="Habib Ilyas & Boukyod Abdessamad",
    description="AI-powered phishing detector for URLs and emails",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/f3d4yn/phishing-detector",
    packages=find_packages(),
    install_requires=[
        "scikit-learn",
        "pandas",
        "nltk",
        "tldextract",
        "requests",
        "joblib",
        "numpy",
    ],
    entry_points={
        "console_scripts": [
            "isphishing=src.detector.phishing_detector:main_cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
