![image](https://github.com/user-attachments/assets/5a5c5eb6-bbed-4430-8aaa-4187be7c1530)


# 🧠 IRIS – Incident Response Intelligent System

## 🚨 Objectif

IRIS est un outil CLI (Command Line Interface) avancé conçu pour automatiser et standardiser le processus de réponse aux incidents de sécurité informatique. Il permet de :

- Collecte automatisée de preuves
- Containment dynamique
- Analyse mémoire intelligente
- Corrélation IOCs multi-sources
- Reporting conforme NIST

## 📁 Structure du projet

```
iris/
├── core/
│   ├── analyze.py
│   ├── collect.py
│   ├── contain.py
│   ├── intel.py
│   ├── report.py
│   └── utils.py
├── iris.py
├── requirements.txt
├── install.sh
└── README.md
```

## 🛠️ Installation

```bash
chmod +x install.sh
./install.sh
```

## 🧪 Exécution

```bash
python3 iris.py --mode full --output case_2024
```

## 🔐 Fonctions

* **Analyse mémoire** : Utilisation d'algorithmes de machine learning pour détecter les anomalies dans les processus en cours d'exécution
* **Collecte de preuves** : Capture automatisée des fichiers système critiques avec génération d'empreintes cryptographiques
* **Isolation Firewall auto** : Blocage automatique des adresses IP malveillantes identifiées
* **Journalisation horodatée et hachée** : Création d'une chaîne de preuves sécurisée et vérifiable
* **Threat Intelligence** : Vérification des indicateurs de compromission (IOCs) contre des sources externes comme AlienVault et MISP
* **Compatible Linux/Windows** : Conçu pour fonctionner sur les plateformes les plus courantes

## 📋 Modes d'exécution

IRIS propose trois modes d'exécution :

* **quick** : Analyse rapide pour une première évaluation
* **full** : Investigation complète (recommandé)
* **forensic** : Analyse approfondie pour les enquêtes criminalistiques

## 📊 Reporting

Le système génère automatiquement des rapports conformes aux standards du NIST (National Institute of Standards and Technology), facilitant la documentation des incidents et le partage d'informations.

## 🔒 Sécurité et conformité

IRIS implémente des mécanismes pour garantir l'intégrité des preuves collectées, avec :
- Hachage SHA-256 de tous les artefacts collectés
- Horodatage précis des actions
- Journalisation immuable des événements

## ⚠️ Avertissement

Cet outil doit être utilisé par des professionnels qualifiés et autorisés. L'utilisation incorrecte peut perturber les opérations système et compromettre des preuves essentielles.

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.
