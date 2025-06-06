# Démonstration de l'Analyseur de Mémoire et de Sécurité

Cette démonstration montre les capacités de l'outil d'analyse de mémoire et de sécurité.

## Prérequis

- Python 3.8 ou supérieur
- Les dépendances listées dans `requirements.txt`

## Installation

1. Cloner le dépôt :
```bash
git clone <url-du-repo>
cd <nom-du-repo>
```

2. Installer les dépendances :
```bash
pip install -r requirements.txt
```

## Structure des Dossiers

```
demo/
├── README.md           # Ce fichier
├── demo.py            # Script de démonstration
├── reports/           # Dossier pour les rapports générés
├── logs/              # Dossier pour les logs
└── alerts/            # Dossier pour les alertes
```

## Exécution de la Démo

Pour lancer la démonstration :

```bash
python demo.py
```

La démo va :
1. Initialiser l'analyseur
2. Analyser les processus en cours
3. Analyser les connexions réseau
4. Démarrer la surveillance en temps réel
5. Simuler des événements suspects
6. Générer un rapport de sécurité
7. Effectuer une analyse comportementale
8. Tenter d'envoyer les événements au SIEM
9. Arrêter la surveillance

## Résultats

Les résultats seront disponibles dans :
- `demo/reports/rapport_securite.html` : Rapport de sécurité
- `demo/logs/demo.log` : Logs de la démonstration
- `demo/alerts/` : Alertes générées

## Notes

- La démo utilise des données simulées pour la démonstration
- Les erreurs de connexion au SIEM sont normales (le SIEM est simulé)
- Les avertissements sur les processus sont normaux (accès limités)

## Personnalisation

Vous pouvez modifier les paramètres dans `demo.py` pour :
- Changer l'intervalle de surveillance
- Modifier les seuils d'alerte
- Ajouter des tests supplémentaires

## Support

Pour toute question ou problème, veuillez ouvrir une issue sur le dépôt. 