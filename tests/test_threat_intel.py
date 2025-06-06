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

class TestAlienVaultOTX(unittest.TestCase):
    def setUp(self):
        """Configuration initiale pour chaque test."""
        self.otx = AlienVaultOTX()
        self.otx.api_key = "dummy_api_key"
        self.test_indicator = "8.8.8.8"
        self.expected_success_response = {
            'found': True,
            'source': 'AlienVault OTX',
            'pulse_count': 2,
            'details': {
                'pulse_info': {'count': 2},
                'found': True
            }
        }

    @patch.object(AlienVaultOTX, "check_indicator")
    def test_check_indicator_success(self, mock_check):
        """Test d'une réponse réussie de l'API AlienVault OTX."""
        mock_check.return_value = self.expected_success_response
        
        result = self.otx.check_indicator(self.test_indicator)
        
        # Vérifications détaillées
        self.assertTrue(result['found'])
        self.assertEqual(result['source'], 'AlienVault OTX')
        self.assertEqual(result['pulse_count'], 2)
        mock_check.assert_called_once_with(self.test_indicator)

    def test_check_indicator_error(self):
        """Test de la gestion des erreurs de l'API AlienVault OTX."""
        self.otx.api_key = None
        result = self.otx.check_indicator(self.test_indicator)
        
        self.assertFalse(result['found'])
        self.assertIn('error', result)
        self.assertEqual(result['source'], 'AlienVault OTX')

class TestMISP(unittest.TestCase):
    def setUp(self):
        """Configuration initiale pour chaque test."""
        self.misp = MISP()
        self.misp.api_key = "dummy_api_key"
        self.test_indicator = "8.8.8.8"
        self.expected_success_response = {
            'found': True,
            'source': 'MISP',
            'events': [{'Event': {'info': 'Malicious IP'}}],
            'details': {
                'response': [{'Event': {'info': 'Malicious IP'}}]
            }
        }

    @patch.object(MISP, "check_indicator")
    def test_check_indicator_success(self, mock_check):
        """Test d'une réponse réussie de l'API MISP."""
        mock_check.return_value = self.expected_success_response
        
        result = self.misp.check_indicator(self.test_indicator)
        
        # Vérifications détaillées
        self.assertTrue(result['found'])
        self.assertEqual(result['source'], 'MISP')
        self.assertIn('events', result)
        mock_check.assert_called_once_with(self.test_indicator)

    def test_check_indicator_error(self):
        """Test de la gestion des erreurs de l'API MISP."""
        self.misp.api_key = None
        result = self.misp.check_indicator(self.test_indicator)
        
        self.assertFalse(result['found'])
        self.assertIn('error', result)
        self.assertEqual(result['source'], 'MISP')

class TestVirusTotal(unittest.TestCase):
    def setUp(self):
        """Configuration initiale pour chaque test."""
        self.vt = VirusTotal()
        self.vt.api_key = "dummy_api_key"
        self.test_indicator = "8.8.8.8"
        self.expected_success_response = {
            'found': True,
            'source': 'VirusTotal',
            'positives': 5,
            'total': 70,
            'details': {
                'positives': 5,
                'total': 70
            }
        }

    @patch.object(VirusTotal, "check_indicator")
    def test_check_indicator_success(self, mock_check):
        """Test d'une réponse réussie de l'API VirusTotal."""
        mock_check.return_value = self.expected_success_response
        
        result = self.vt.check_indicator(self.test_indicator)
        
        # Vérifications détaillées
        self.assertTrue(result['found'])
        self.assertEqual(result['source'], 'VirusTotal')
        self.assertEqual(result['positives'], 5)
        self.assertEqual(result['total'], 70)
        mock_check.assert_called_once_with(self.test_indicator)

    def test_check_indicator_error(self):
        """Test de la gestion des erreurs de l'API VirusTotal."""
        self.vt.api_key = None
        result = self.vt.check_indicator(self.test_indicator)
        
        self.assertFalse(result['found'])
        self.assertIn('error', result)
        self.assertEqual(result['source'], 'VirusTotal')

class TestThreatIntelCheck(unittest.TestCase):
    def setUp(self):
        """Configuration initiale pour chaque test."""
        self.checker = ThreatIntelCheck()
        self.test_indicator = "8.8.8.8"
        # Configuration des clés API pour toutes les sources
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
        """Test d'une vérification réussie avec toutes les sources."""
        # Configuration des mocks avec des réponses détaillées
        mock_vt.return_value = {
            'found': True,
            'source': 'VirusTotal',
            'positives': 5,
            'total': 70
        }
        mock_misp.return_value = {
            'found': True,
            'source': 'MISP',
            'events': [{'Event': {'info': 'Malicious IP'}}]
        }
        mock_otx.return_value = {
            'found': True,
            'source': 'AlienVault OTX',
            'pulse_count': 2
        }

        result = self.checker.check_indicator(self.test_indicator)
        
        # Vérifications détaillées
        self.assertTrue(result['found'])
        self.assertEqual(len(result['sources']), 3)
        self.assertIn('VirusTotal', [s['source'] for s in result['sources']])
        self.assertIn('MISP', [s['source'] for s in result['sources']])
        self.assertIn('AlienVault OTX', [s['source'] for s in result['sources']])
        
        # Vérification des appels
        mock_vt.assert_called_once_with(self.test_indicator)
        mock_misp.assert_called_once_with(self.test_indicator)
        mock_otx.assert_called_once_with(self.test_indicator)

    @patch.object(VirusTotal, "check_indicator")
    @patch.object(MISP, "check_indicator")
    @patch.object(AlienVaultOTX, "check_indicator")
    def test_threat_intel_check_all_errors(self, mock_otx, mock_misp, mock_vt):
        """Test de la gestion des erreurs de toutes les sources."""
        # Configuration des mocks pour retourner des erreurs
        error_response = {
            'error': 'API Error',
            'source': None,
            'found': False
        }
        mock_vt.return_value = {**error_response, 'source': 'VirusTotal'}
        mock_misp.return_value = {**error_response, 'source': 'MISP'}
        mock_otx.return_value = {**error_response, 'source': 'AlienVault OTX'}
        
        result = self.checker.check_indicator(self.test_indicator)
        
        # Vérifications détaillées
        self.assertFalse(result['found'])
        self.assertEqual(len(result['errors']), 3)
        self.assertIn('VirusTotal', [e['source'] for e in result['errors']])
        self.assertIn('MISP', [e['source'] for e in result['errors']])
        self.assertIn('AlienVault OTX', [e['source'] for e in result['errors']])
        
        # Vérification des appels
        mock_vt.assert_called_once_with(self.test_indicator)
        mock_misp.assert_called_once_with(self.test_indicator)
        mock_otx.assert_called_once_with(self.test_indicator)

    def test_threat_intel_check_invalid_indicator(self):
        """Test avec un indicateur invalide."""
        result = self.checker.check_indicator("invalid")
        
        self.assertFalse(result['found'])
        self.assertIn('error', result)
        self.assertEqual('All sources failed', result['error'])
        self.assertIn('errors', result)
        self.assertTrue(len(result['errors']) > 0)

if __name__ == '__main__':
    unittest.main() 