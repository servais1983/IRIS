#!/usr/bin/env python3

# Créer un fichier __init__.py pour indiquer que le répertoire 'core' est un package Python
# Ce fichier permet d'importer les modules du dossier core en utilisant:
# from core import analyze, collect, contain, intel, report, utils

__version__ = '1.0.0'

# Importer les modules
from . import analyze
from . import collect
from . import contain
from . import intel
from . import report
from . import utils
from . import security
from . import monitor
from . import secrets_manager
from . import session_manager
from . import key_rotation
from . import auth_2fa
from . import input_validation
from . import siem

# Exporter les modules principaux
__all__ = [
    'analyze',
    'collect',
    'contain',
    'intel',
    'report',
    'utils',
    'security',
    'monitor',
    'secrets_manager',
    'session_manager',
    'key_rotation',
    'auth_2fa',
    'input_validation',
    'siem'
]

"""
Package core - Fonctionnalités principales de l'outil IRIS
"""

from .analyze import MemoryAnalyzer
from .monitor import SecurityMonitor
from .report import ReportGenerator
from .siem import SIEMConnector
from .intel import ThreatIntelligence

__all__ = [
    'MemoryAnalyzer',
    'SecurityMonitor',
    'ReportGenerator',
    'SIEMConnector',
    'ThreatIntelligence'
]
