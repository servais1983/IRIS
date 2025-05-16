#!/usr/bin/env python3

# Créer un fichier __init__.py pour indiquer que le répertoire 'core' est un package Python
# Ce fichier permet d'importer les modules du dossier core en utilisant:
# from core import analyze, collect, contain, intel, report, utils

__version__ = '1.0.0'

# Exporter les modules principaux
__all__ = ['analyze', 'collect', 'contain', 'intel', 'report', 'utils']
