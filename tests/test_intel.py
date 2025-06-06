#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests unitaires pour le module de renseignement sur les menaces d'IRIS.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.intel import ThreatIntelAPI, AlienVaultOTX, MISP, VirusTotal, ThreatIntelCheck
from typing import Dict

class ConcreteThreatIntelAPI(ThreatIntelAPI):
    """Classe concrète temporaire pour les tests."""
    def check_indicator(self, indicator: str) -> Dict:
        return {'found': False, 'source': 'Test'}

class TestThreatIntelAPI(unittest.TestCase):
    def setUp(self):
        self.api = ConcreteThreatIntelAPI()
    
    def test_check_indicator_not_implemented(self):
        """Test que la méthode check_indicator n'est pas implémentée dans la classe de base"""
        class TestAPI(ThreatIntelAPI):
            def check_indicator(self, indicator: str) -> Dict:
                raise NotImplementedError("Cette méthode ne devrait pas être appelée")
            
        with self.assertRaises(NotImplementedError):
            api = TestAPI()
            api.check_indicator("test")

class TestAlienVaultOTX(unittest.TestCase):
    def setUp(self):
        self.otx = AlienVaultOTX()
        self.otx.api_key = "dummy_api_key"

    @patch.object(AlienVaultOTX, "check_indicator")
    def test_check_indicator_success(self, mock_check):
        """Test d'une réponse réussie de l'API AlienVault OTX"""
        mock_check.return_value = {
            'found': True,
            'source': 'AlienVault OTX',
            'pulse_count': 2
        }
        result = self.otx.check_indicator("8.8.8.8")
        self.assertTrue(result['found'])

    def test_check_indicator_error(self):
        self.otx.api_key = None
        result = self.otx.check_indicator("8.8.8.8")
        self.assertFalse(result['found'])
        self.assertIn('error', result)

class TestMISP(unittest.TestCase):
    def setUp(self):
        self.misp = MISP()
        self.misp.api_key = "dummy_api_key"

    @patch.object(MISP, "check_indicator")
    def test_check_indicator_success(self, mock_check):
        """Test d'une réponse réussie de l'API MISP"""
        mock_check.return_value = {
            'found': True,
            'source': 'MISP',
            'events': [{'Event': {'info': 'Malicious IP'}}]
        }
        result = self.misp.check_indicator("8.8.8.8")
        self.assertTrue(result['found'])

    def test_check_indicator_error(self):
        self.misp.api_key = None
        result = self.misp.check_indicator("8.8.8.8")
        self.assertFalse(result['found'])
        self.assertIn('error', result)

class TestVirusTotal(unittest.TestCase):
    def setUp(self):
        self.vt = VirusTotal()
        self.vt.api_key = "dummy_api_key"

    @patch.object(VirusTotal, "check_indicator")
    def test_check_indicator_success(self, mock_check):
        """Test d'une réponse réussie de l'API VirusTotal"""
        mock_check.return_value = {
            'found': True,
            'source': 'VirusTotal',
            'positives': 5,
            'total': 70
        }
        result = self.vt.check_indicator("8.8.8.8")
        self.assertTrue(result['found'])

    def test_check_indicator_error(self):
        self.vt.api_key = None
        result = self.vt.check_indicator("8.8.8.8")
        self.assertFalse(result['found'])
        self.assertIn('error', result)

class TestThreatIntelCheck(unittest.TestCase):
    def setUp(self):
        self.checker = ThreatIntelCheck()
        for source in self.checker.sources:
            if isinstance(source, VirusTotal):
                source.api_key = "dummy_vt_key"
            elif isinstance(source, MISP):
                source.api_key = "dummy_misp_key"
            elif isinstance(source, AlienVaultOTX):
                source.api_key = "dummy_otx_key"

    @patch.object(VirusTotal, "check_indicator")
    @patch.object(MISP, "check_indicator")
    @patch.object(AlienVaultOTX, "check_indicator")
    def test_threat_intel_check_success(self, mock_otx, mock_misp, mock_vt):
        mock_vt.return_value = {'found': True, 'source': 'VirusTotal', 'positives': 5}
        mock_misp.return_value = {'found': True, 'source': 'MISP'}
        mock_otx.return_value = {'found': True, 'source': 'AlienVault OTX'}
        result = self.checker.check_indicator("8.8.8.8")
        self.assertTrue(result['found'])
        self.assertEqual(len(result['sources']), 3)
    
    @patch('core.intel.VirusTotal')
    @patch('core.intel.MISP')
    @patch('core.intel.AlienVaultOTX')
    def test_threat_intel_check_all_errors(self, mock_otx, mock_misp, mock_vt):
        """Test de la gestion des erreurs de toutes les sources"""
        # Configurer les mocks pour retourner des erreurs
        mock_vt.return_value.check_indicator.return_value = {
            'error': 'API Error',
            'source': 'VirusTotal'
        }
        mock_misp.return_value.check_indicator.return_value = {
            'error': 'API Error',
            'source': 'MISP'
        }
        mock_otx.return_value.check_indicator.return_value = {
            'error': 'API Error',
            'source': 'AlienVault OTX'
        }
        
        result = self.checker.check_indicator("8.8.8.8")
        self.assertFalse(result['found'])
        self.assertEqual(len(result['errors']), 3)
    
    def test_threat_intel_check_invalid_indicator(self):
        """Test avec un indicateur invalide"""
        result = self.checker.check_indicator("invalid")
        self.assertFalse(result['found'])
        self.assertIn('error', result)

if __name__ == '__main__':
    unittest.main() 