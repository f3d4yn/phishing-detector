# 🛡️ Phishing Detector

Détecteur de phishing basé sur le Machine Learning et la Programmation Orientée Objet en Python.

## Fonctionnalités
- Détecte les URLs et emails de phishing en temps réel
- Score de confiance entre 0 et 1
- Raisons détaillées de la détection
- Commande `isphishing` utilisable depuis n'importe où

## Performance
| Métrique | Score |
|---|---|
| Exactitude | 95.52% |
| F1 Score | 95.66% |
| ROC AUC | 98.76% |

## Dataset
- 11 430 URLs (PhishTank)
- 82 486 Emails
- **93 916 échantillons au total**

## Installation
```bash
git clone https://github.com/f3d4yn/phishing-detector.git
cd phishing-detector
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
python main.py
```

## Architecture POO
- `BaseInput` — Classe abstraite (ABC)
- `EmailInput` / `URLInput` — Héritage
- `FeatureExtractor` — Extraction de features
- `MLModel` — Random Forest
- `PhishingDetector` — Orchestrateur principal
- `ThreatReport` — Rapport de menace
- `AlertSystem` — Système d'alertes

## Auteurs
Habib Ilyas & Boukyod Abdessamad — Module Programmation Avancée (Python POO)
