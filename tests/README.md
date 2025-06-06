# Tests IRIS

Ce répertoire contient les tests unitaires et d'intégration pour le projet IRIS.

## Structure des tests

- `test_memory_analysis.py` : Tests pour l'analyse mémoire
- `test_artifact_collection.py` : Tests pour la collecte d'artefacts
- `test_threat_intel.py` : Tests pour l'intelligence des menaces
- `run_tests.py` : Script principal pour exécuter tous les tests

## Exécution des tests

### Installation des dépendances

```bash
pip install -r requirements.txt
```

### Exécution de tous les tests

```bash
python tests/run_tests.py
```

### Exécution avec pytest

```bash
# Exécuter tous les tests
pytest

# Exécuter un fichier de test spécifique
pytest tests/test_memory_analysis.py

# Exécuter avec couverture de code
pytest --cov=core

# Exécuter les tests marqués
pytest -m "memory"  # Tests d'analyse mémoire
pytest -m "network"  # Tests réseau
pytest -m "security"  # Tests de sécurité
```

## Rapports de test

Les rapports de test sont générés dans les formats suivants :

- `coverage_report/` : Rapport HTML de couverture de code
- `coverage.xml` : Rapport XML de couverture pour CI
- `test-results.xml` : Résultats des tests au format JUnit

## Marqueurs de test

Les tests sont marqués avec les catégories suivantes :

- `@pytest.mark.slow` : Tests qui prennent plus de temps
- `@pytest.mark.integration` : Tests d'intégration
- `@pytest.mark.unit` : Tests unitaires
- `@pytest.mark.memory` : Tests liés à l'analyse mémoire
- `@pytest.mark.network` : Tests liés au réseau
- `@pytest.mark.security` : Tests de sécurité

## Intégration continue

Les tests sont exécutés automatiquement via GitHub Actions sur :
- Push vers les branches `main` et `develop`
- Pull requests vers les branches `main` et `develop`

## Bonnes pratiques

1. Écrire des tests pour chaque nouvelle fonctionnalité
2. Maintenir une couverture de code élevée
3. Utiliser les marqueurs appropriés
4. Documenter les cas de test complexes
5. Nettoyer les ressources après les tests
6. Utiliser des fixtures pour la configuration commune
7. Éviter les tests interdépendants
8. Simuler les dépendances externes 