#!/usr/bin/env python3

import unittest
import sys
import os
import coverage

def run_tests():
    # Démarrer la couverture de code
    cov = coverage.Coverage(
        branch=True,
        source=['core'],
        omit=['tests/*', '*/__init__.py']
    )
    cov.start()

    # Découvrir et exécuter tous les tests
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(os.path.abspath(__file__))
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    # Exécuter les tests avec un runner personnalisé
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Arrêter la couverture et générer le rapport
    cov.stop()
    cov.save()
    
    # Générer les rapports
    print("\nCouverture de code:")
    cov.report()
    
    # Générer le rapport HTML
    cov.html_report(directory='coverage_report')
    
    # Générer le rapport XML pour CI
    cov.xml_report(outfile='coverage.xml')

    # Retourner le code de sortie approprié
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    sys.exit(run_tests()) 