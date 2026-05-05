# Phishing Detector

Detecteur de phishing base sur le Machine Learning et la Programmation Orientee Objet en Python.
Detecte les URLs et emails de phishing en temps reel depuis nimporte ou dans le terminal.

## Installation via PyPI (recommande)

    pip install isphishing
    isphishing-setup
    isphishing

## Installation via GitHub

### Linux / Mac

    git clone https://github.com/f3d4yn/phishing-detector.git
    cd phishing-detector
    chmod +x install.sh
    ./install.sh
    source ~/.bashrc

### Windows

    git clone https://github.com/f3d4yn/phishing-detector.git
    cd phishing-detector
    install.bat

Redemarre le terminal apres installation puis tape : isphishing

## Performance des modeles

Deux modeles specialises sont utilises : un pour les URLs et un pour les emails.

### Modele URL

| Metrique   | Score  |
|------------|--------|
| Exactitude | 92.33% |
| Precision  | 93.87% |
| Rappel     | 90.57% |
| F1 Score   | 92.19% |
| ROC AUC    | 97.85% |

### Modele Email

| Metrique   | Score  |
|------------|--------|
| Exactitude | 98.17% |
| Precision  | 97.69% |
| Rappel     | 98.67% |
| F1 Score   | 98.18% |
| ROC AUC    | 99.82% |

Entraine sur 663 766 echantillons (564 970 URLs + 98 796 Emails)

## Architecture POO

- BaseInput         : Classe abstraite (ABC)
- EmailInput        : Heritage + validate()
- URLInput          : Heritage + extract_domain()
- FeatureExtractor  : Extraction de 38 features (URL + texte)
- MLModel           : XGBoost (2000 arbres, early stopping)
- PhishingDetector  : Orchestrateur principal + whitelist
- ThreatReport      : Score + Label + Raisons
- AlertSystem       : Alertes colorees + Logs JSON

## Fonctionnalites

- Detection d URLs et emails de phishing en temps reel
- Deux modeles XGBoost specialises (URL et Email)
- 38 features extraites par analyse (longueur URL, entropie domaine, mots suspects, etc.)
- Whitelist de domaines et expéditeurs de confiance
- Logs JSON automatiques des alertes detectees
- Interface terminal coloree

## Lancer les tests

    source venv/bin/activate
    python -m unittest discover tests/

## Reentrainer le modele

Les datasets ne sont pas inclus dans le depot.

1. Telecharge les datasets sur Kaggle :
   - URLs  : Web Page Phishing Detection Dataset
   - Emails: Phishing Email Dataset

2. Place-les dans data/ :
   - data/all_urls.csv
   - data/all_emails.csv

3. Lance l entrainement :

       python train.py

   Deux modeles seront generes :
   - models/model_url.pkl
   - models/model_email.pkl

## Auteurs

Habib Ilyas et Boukyod Abdessamad
Module : Programmation Avancee (Python POO)

## PyPI

https://pypi.org/project/isphishing/