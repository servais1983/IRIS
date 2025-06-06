# IRIS - Système de Détection et Réponse aux Incidents

[![Coverage](https://img.shields.io/badge/coverage-44%25-yellow.svg)](https://github.com/yourusername/IRIS)

![image](iris.png)


# 🧠 IRIS – Incident Response Intelligent System

## 🚨 Objectif

IRIS est un outil CLI (Command Line Interface) avancé conçu pour automatiser et standardiser le processus de réponse aux incidents de sécurité informatique. Il permet de :

* Collecte automatisée de preuves
* Containment dynamique
* Analyse mémoire intelligente
* Corrélation IOCs multi-sources
* Reporting conforme NIST

## 📁 Structure du projet

```
iris/
├── core/
│   ├── analyze.py      # Analyse mémoire et comportementale
│   ├── collect.py      # Collecte de preuves
│   ├── contain.py      # Containment dynamique
│   ├── intel.py        # Threat Intelligence
│   ├── monitor.py      # Surveillance en temps réel
│   ├── report.py       # Génération de rapports
│   ├── siem.py         # Intégration SIEM
│   └── utils.py        # Utilitaires
├── demo/               # Démonstration
│   ├── demo.py
│   ├── requirements.txt
│   └── README.md
├── iris.py            # Point d'entrée principal
├── requirements.txt
├── install.sh
└── README.md
```

## 🛠️ Installation

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/IRIS.git
cd IRIS

# Installer les dépendances
pip install -r requirements.txt

# Rendre le script d'installation exécutable
chmod +x install.sh
./install.sh
```

## 🧪 Exécution

```bash
# Mode surveillance continue
python iris.py

# Mode analyse rapide
python iris.py --mode quick

# Mode analyse complète
python iris.py --mode full

# Mode forensique
python iris.py --mode forensic
```

## 🔐 Fonctionnalités

### Analyse Mémoire
* Détection des processus malveillants
* Analyse des connexions réseau
* Surveillance des privilèges
* Liste blanche de processus légitimes

### Surveillance en Temps Réel
* Monitoring continu des processus
* Détection des comportements anormaux
* Alertes en temps réel
* Journalisation détaillée

### Collecte de Preuves
* Capture automatisée des fichiers système
* Génération d'empreintes cryptographiques
* Horodatage précis
* Chaîne de preuves sécurisée

### Containment Dynamique
* Isolation automatique des menaces
* Blocage des connexions suspectes
* Quarantaine des processus malveillants
* Règles de pare-feu dynamiques

### Threat Intelligence
* Vérification des IOCs
* Intégration avec AlienVault
* Corrélation multi-sources
* Base de données de menaces

### Reporting
* Rapports HTML/JSON
* Conformité NIST
* Timeline d'événements
* Recommandations d'actions

## 📊 Modes d'Exécution

* **Surveillance** : Monitoring continu (par défaut)
* **Quick** : Analyse rapide pour première évaluation
* **Full** : Investigation complète
* **Forensic** : Analyse approfondie

## 🔒 Sécurité

* Hachage SHA-256 des artefacts
* Horodatage précis
* Journalisation immuable
* Intégrité des preuves

## 📊 Exemple de sortie

```
[+] Démarrage investigation IRIS - ID: case_2024_20240306-123456
[*] Mode: full
[*] Dossier de sortie: evidence/case_2024_20240306-123456/

[*] Analyse mémoire en cours...
[!] 3 processus suspects détectés

[*] Collecte des artefacts...
[+] 4 artefacts récupérés

[*] Containment réseau...
[!] 2 IPs bloquées

[*] Vérification Threat Intelligence...
[*] 3 indicateurs vérifiés

[+] Investigation terminée avec succès!
[+] Rapport HTML: evidence/case_2024_20240306-123456/report.html
[+] Rapport Markdown: evidence/case_2024_20240306-123456/report.md
```

## ⚠️ Avertissement

Cet outil doit être utilisé par des professionnels qualifiés et autorisés. L'utilisation incorrecte peut perturber les opérations système et compromettre des preuves essentielles.

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
1. Fork le projet
2. Créer une branche (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push sur la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📞 Support

Pour toute question ou problème, veuillez ouvrir une issue sur GitHub.
