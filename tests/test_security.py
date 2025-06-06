#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests unitaires pour le module de sécurité d'IRIS.
"""

import unittest
import os
import sys
import json
import tempfile
import ipaddress
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import yaml
import jwt
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.security import SecurityManager, SecurityLevel, SecurityAlert

class TestSecurityManager(unittest.TestCase):
    def setUp(self):
        # Créer un dossier temporaire pour les tests
        self.test_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.test_dir, 'security_config.yaml')
        
        # Créer une configuration de test
        self.test_config = {
            'crypto': {
                'master_key': 'test_key_123',
                'key_size': 32
            },
            'auth': {
                'jwt_secret': 'test_secret',
                'token_expiry': 3600
            },
            'firewall': {
                'allowed_ips': ['127.0.0.1'],
                'blocked_ips': ['192.168.1.1']
            }
        }
        
        # Écrire la configuration dans un fichier YAML
        with open(self.config_file, 'w') as f:
            yaml.dump(self.test_config, f)
        
        self.security = SecurityManager(self.config_file)
    
    def tearDown(self):
        # Nettoyer le dossier temporaire après les tests
        import shutil
        shutil.rmtree(self.test_dir)
        if os.path.exists(self.config_file):
            os.remove(self.config_file)
    
    def test_encryption_decryption(self):
        # Tester le chiffrement et déchiffrement
        test_data = "Données sensibles à chiffrer"
        encrypted = self.security.encrypt_data(test_data)
        decrypted = self.security.decrypt_data(encrypted).decode('utf-8')
        self.assertEqual(test_data, decrypted)
    
    def test_password_hashing(self):
        # Tester le hachage des mots de passe
        password = "mot_de_passe_test"
        hashed = self.security.hash_password(password)
        self.assertTrue(self.security.verify_password(password, hashed))
        self.assertFalse(self.security.verify_password("mauvais_mot_de_passe", hashed))
    
    def test_jwt_token(self):
        """Test de génération et vérification de token JWT"""
        with patch('jwt.encode') as mock_encode, \
             patch('jwt.decode') as mock_decode:
            mock_encode.return_value = 'test_token'
            mock_decode.return_value = {'user_id': '1'}

            token = self.security.generate_token({'user_id': '1'})
            self.assertEqual(token, 'test_token')

            data = self.security.verify_token(token)
            self.assertEqual(data['user_id'], '1')
    
    def test_ip_validation(self):
        """Test de la validation des adresses IP"""
        # Test d'une IP valide
        self.assertTrue(self.security.validate_input('127.0.0.1', 'ip'))
        
        # Test d'une IP invalide
        self.assertFalse(self.security.validate_input('256.256.256.256', 'ip'))
        
        # Test d'une chaîne non-IP
        self.assertFalse(self.security.validate_input('not_an_ip', 'ip'))
    
    def test_rate_limiting(self):
        """Test de la limitation de taux"""
        key = 'login_127.0.0.1'
        
        # Simuler plusieurs tentatives
        for _ in range(4):
            self.assertTrue(self.security.check_rate_limit(key))
        
        # La 5ème tentative devrait être bloquée
        self.assertFalse(self.security.check_rate_limit(key))
        
        # Attendre que le délai expire
        self.security._rate_limit[key]['last_attempt'] = 0
        self.assertTrue(self.security.check_rate_limit(key))
    
    def test_sanitize_output(self):
        # Tester la sanitization des sorties
        dangerous_input = "<script>alert('xss')</script>"
        sanitized = self.security.sanitize_output(dangerous_input)
        self.assertNotIn("<", sanitized)
        self.assertNotIn(">", sanitized)
    
    def test_invalid_config(self):
        # Tester avec une configuration invalide
        invalid_config = {
            'crypto': {
                'master_key': '',  # Clé vide
            }
        }
        
        with open(self.config_file, 'w') as f:
            yaml.dump(invalid_config, f)
        
        with self.assertRaises(ValueError):
            SecurityManager(self.config_file)
    
    def test_missing_config_file(self):
        # Tester avec un fichier de configuration manquant
        with self.assertRaises(FileNotFoundError):
            SecurityManager("fichier_inexistant.yaml")
    
    def test_token_expiration(self):
        """Test d'expiration de token"""
        with patch('jwt.encode') as mock_encode, \
             patch('jwt.decode') as mock_decode:
            mock_encode.return_value = 'test_token'
            mock_decode.side_effect = jwt.ExpiredSignatureError()

            token = self.security.generate_token({'user_id': '1'})
            with self.assertRaises(ValueError):
                self.security.verify_token(token)
    
    def test_token_tampering(self):
        """Test de modification de token"""
        with patch('jwt.encode') as mock_encode, \
             patch('jwt.decode') as mock_decode:
            mock_encode.return_value = 'test_token'
            mock_decode.side_effect = jwt.InvalidTokenError()

            token = self.security.generate_token({'user_id': '1'})
            with self.assertRaises(ValueError):
                self.security.verify_token(token)
    
    def test_empty_token(self):
        """Test de token vide"""
        with self.assertRaises(ValueError):
            self.security.verify_token('')

if __name__ == '__main__':
    unittest.main() 