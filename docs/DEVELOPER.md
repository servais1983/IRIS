# Guide du Développeur IRIS

## Architecture du Projet

### Structure des Répertoires
```
iris/
├── core/               # Code source principal
│   ├── analyze/       # Modules d'analyse
│   ├── collect/       # Modules de collecte
│   ├── intel/         # Modules d'intelligence
│   └── utils/         # Utilitaires
├── config/            # Fichiers de configuration
├── tests/             # Tests unitaires et d'intégration
├── docs/              # Documentation
└── scripts/           # Scripts utilitaires
```

### Composants Principaux

1. **Analyse Mémoire** (`core/analyze/`)
   - Analyse forensique de la mémoire
   - Détection de malware
   - Analyse des processus

2. **Collecte d'Artefacts** (`core/collect/`)
   - Collecte de logs système
   - Capture de trafic réseau
   - Extraction de métadonnées

3. **Intelligence des Menaces** (`core/intel/`)
   - Intégration avec VirusTotal
   - Analyse AlienVault
   - Vérification AbuseIPDB

## Guide de Développement

### Configuration de l'Environnement

1. **Prérequis**
   ```bash
   # Installation des dépendances système
   sudo apt-get update
   sudo apt-get install -y volatility volatility-tools yara

   # Installation des dépendances Python
   pip install -r requirements.txt
   ```

2. **Configuration de l'Environnement de Développement**
   ```bash
   # Création d'un environnement virtuel
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   .\venv\Scripts\activate   # Windows
   ```

### Standards de Code

1. **Style de Code**
   - Suivre PEP 8
   - Utiliser des docstrings Google style
   - Maximum 79 caractères par ligne

2. **Nommage**
   - Classes : PascalCase
   - Fonctions/Variables : snake_case
   - Constantes : UPPER_CASE

3. **Documentation**
   - Docstrings pour toutes les fonctions
   - Commentaires pour le code complexe
   - README à jour

### Tests

1. **Types de Tests**
   - Tests unitaires
   - Tests d'intégration
   - Tests de performance

2. **Exécution des Tests**
   ```bash
   # Tous les tests
   pytest

   # Tests spécifiques
   pytest tests/test_memory_analysis.py
   ```

3. **Couverture de Code**
   ```bash
   pytest --cov=core
   ```

### Workflow Git

1. **Branches**
   - `main` : Production
   - `develop` : Développement
   - `feature/*` : Nouvelles fonctionnalités
   - `bugfix/*` : Corrections de bugs

2. **Commits**
   - Format : `type(scope): description`
   - Types : feat, fix, docs, style, refactor, test, chore

3. **Pull Requests**
   - Description détaillée
   - Tests passés
   - Revue de code requise

## Monitoring et Logging

### Métriques

1. **Performance**
   - Temps d'exécution
   - Utilisation mémoire
   - CPU usage

2. **Sécurité**
   - Tentatives d'accès
   - Alertes de sécurité
   - Détections de malware

3. **Ressources**
   - Espace disque
   - Bande passante
   - Connexions actives

### Logging

1. **Niveaux de Log**
   ```python
   import logging

   logging.debug("Détails de débogage")
   logging.info("Information générale")
   logging.warning("Avertissement")
   logging.error("Erreur")
   logging.critical("Erreur critique")
   ```

2. **Format des Logs**
   ```python
   logging.basicConfig(
       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
       level=logging.INFO
   )
   ```

## Déploiement

### Préparation

1. **Vérifications**
   - Tests passés
   - Documentation à jour
   - Version mise à jour

2. **Build**
   ```bash
   python setup.py build
   ```

### Installation

1. **Système**
   ```bash
   sudo ./install.sh
   ```

2. **Configuration**
   ```bash
   iris config init
   ```

## Support et Maintenance

### Débogage

1. **Logs**
   - `/var/log/iris/`
   - Niveau DEBUG pour plus de détails

2. **Outils**
   - `iris debug`
   - `iris status`

### Mises à Jour

1. **Vérification**
   ```bash
   iris update check
   ```

2. **Application**
   ```bash
   iris update apply
   ``` 