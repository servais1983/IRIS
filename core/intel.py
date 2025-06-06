#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de renseignement sur les menaces pour IRIS.
Fournit des fonctionnalités de vérification des indicateurs de compromission.
"""

import os
import sys
import logging
import requests
from typing import Dict, List, Optional, Union, Any
from abc import ABC, abstractmethod
import json
from datetime import datetime

# Configuration du logging
log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'intel.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class ThreatIntelAPI(ABC):
    """Classe de base pour les APIs de renseignement sur les menaces."""
    
    @abstractmethod
    def check_indicator(self, indicator: str) -> Dict:
        """Vérifie un indicateur de compromission.
        
        Args:
            indicator: L'indicateur à vérifier (IP, domaine, hash).
            
        Returns:
            Dict contenant les résultats de la vérification.
            
        Raises:
            NotImplementedError: Si la méthode n'est pas implémentée.
        """
        raise NotImplementedError("La méthode check_indicator doit être implémentée par les classes dérivées")

class AlienVaultOTX(ThreatIntelAPI):
    """Classe pour l'API AlienVault OTX."""
    
    def __init__(self):
        """Initialise l'API AlienVault OTX."""
        self.api_key = os.getenv('OTX_API_KEY')
        self.base_url = 'https://otx.alienvault.com/api/v1'
    
    def check_indicator(self, indicator: str) -> Dict:
        """Vérifie un indicateur avec AlienVault OTX.
        
        Args:
            indicator: L'indicateur à vérifier.
            
        Returns:
            Dict contenant les résultats de la vérification.
        """
        try:
            if not self.api_key:
                return {'error': 'API key not configured', 'source': 'AlienVault OTX', 'found': False}
            
            headers = {'X-OTX-API-KEY': self.api_key}
            response = requests.get(
                f'{self.base_url}/indicators/domain/{indicator}/general',
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            pulse_count = data.get('pulse_info', {}).get('count', 0)
            found = data.get('found', False) or pulse_count > 0
            
            return {
                'found': found,
                'source': 'AlienVault OTX',
                'pulse_count': pulse_count
            }
        except Exception as e:
            logger.error(f"Erreur lors de la vérification avec AlienVault OTX: {str(e)}")
            return {'error': str(e), 'source': 'AlienVault OTX', 'found': False}

class MISP(ThreatIntelAPI):
    """Classe pour l'API MISP."""
    
    def __init__(self):
        """Initialise l'API MISP."""
        self.api_key = os.getenv('MISP_API_KEY')
        self.base_url = os.getenv('MISP_URL', 'https://misp.example.com')
    
    def check_indicator(self, indicator: str) -> Dict:
        """Vérifie un indicateur avec MISP.
        
        Args:
            indicator: L'indicateur à vérifier.
            
        Returns:
            Dict contenant les résultats de la vérification.
        """
        try:
            if not self.api_key:
                return {'error': 'API key not configured', 'source': 'MISP', 'found': False}
            
            headers = {
                'Authorization': self.api_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            data = {
                'value': indicator,
                'type': 'domain'
            }
            response = requests.post(
                f'{self.base_url}/events/restSearch',
                headers=headers,
                json=data,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            events = data.get('response', [])
            found = len(events) > 0
            
            return {
                'found': found,
                'source': 'MISP',
                'events': events
            }
        except Exception as e:
            logger.error(f"Erreur lors de la vérification avec MISP: {str(e)}")
            return {'error': str(e), 'source': 'MISP', 'found': False}

class VirusTotal(ThreatIntelAPI):
    """Classe pour l'API VirusTotal."""
    
    def __init__(self):
        """Initialise l'API VirusTotal."""
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/vtapi/v2'
    
    def check_indicator(self, indicator: str) -> Dict:
        """Vérifie un indicateur avec VirusTotal.
        
        Args:
            indicator: L'indicateur à vérifier.
            
        Returns:
            Dict contenant les résultats de la vérification.
        """
        try:
            if not self.api_key:
                return {'error': 'API key not configured', 'source': 'VirusTotal', 'found': False}
            
            params = {
                'apikey': self.api_key,
                'domain': indicator
            }
            response = requests.get(
                f'{self.base_url}/domain/report',
                params=params,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            positives = data.get('positives', 0)
            total = data.get('total', 0)
            found = positives > 0
            
            return {
                'found': found,
                'source': 'VirusTotal',
                'positives': positives,
                'total': total
            }
        except Exception as e:
            logger.error(f"Erreur lors de la vérification avec VirusTotal: {str(e)}")
            return {'error': str(e), 'source': 'VirusTotal', 'found': False}

class ThreatIntelCheck:
    """Classe pour la vérification des indicateurs de compromission."""
    
    def __init__(self):
        """Initialise le vérificateur d'indicateurs."""
        self.sources = [
            VirusTotal(),
            MISP(),
            AlienVaultOTX()
        ]
    
    def check_indicator(self, indicator: str) -> Dict:
        """Vérifie un indicateur avec toutes les sources disponibles.
        
        Args:
            indicator: L'indicateur à vérifier.
            
        Returns:
            Dict contenant les résultats de la vérification.
        """
        if not indicator or not isinstance(indicator, str):
            return {'error': 'Invalid indicator', 'found': False}
        
        results = []
        errors = []
        found = False
        
        for source in self.sources:
            result = source.check_indicator(indicator)
            if 'error' in result:
                errors.append(result)
            else:
                results.append(result)
                found = found or result.get('found', False)
        
        if errors and not results:
            return {
                'error': 'All sources failed',
                'found': False,
                'errors': errors
            }
        
        return {
            'found': found,
            'sources': results,
            'errors': errors if errors else None
        }

class ThreatIntelligence:
    """Classe pour l'intelligence sur les menaces."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyse les données pour détecter des menaces.
        
        Args:
            data: Données à analyser
            
        Returns:
            Liste des menaces détectées
        """
        self.logger.info("Analyse des menaces en cours...")
        # Simulation d'analyse
        return [{"threat": "simulated_threat", "severity": "low"}]

def main():
    """Fonction principale."""
    try:
        checker = ThreatIntelCheck()
        result = checker.check_indicator("example.com")
        print(json.dumps(result, indent=2))
    except Exception as e:
        logger.error(f"Erreur dans la fonction principale: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
