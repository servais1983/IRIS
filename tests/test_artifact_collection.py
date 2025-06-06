import os
import pytest
import sys
from unittest.mock import patch, MagicMock
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.collect import artifact_collection, ArtifactCollector

@pytest.fixture
def test_output_dir(tmp_path):
    """Crée un répertoire temporaire pour les tests"""
    return str(tmp_path / "test_artifacts")

@patch('core.collect.ArtifactCollector._copy_file_with_retry')
def test_artifact_collection(mock_copy, test_output_dir):
    """Test de la collecte d'artefacts"""
    # Configurer le mock pour simuler des copies réussies
    mock_copy.return_value = True
    
    # Créer un ID d'investigation de test
    investigation_id = "test_investigation"
    
    # Exécuter la collecte
    results = artifact_collection(investigation_id, test_output_dir)
    
    # Vérifier que les résultats sont un dictionnaire
    assert isinstance(results, dict)
    
    # Vérifier la présence des clés attendues
    assert "collected" in results
    assert "failed" in results
    assert "details" in results
    assert "collection_time" in results
    
    # Vérifier que le nombre d'artefacts collectés est un entier positif
    assert isinstance(results["collected"], int)
    assert results["collected"] >= 0
    
    # Vérifier que le nombre d'échecs est un entier positif
    assert isinstance(results["failed"], int)
    assert results["failed"] >= 0
    
    # Vérifier que les détails contiennent les listes attendues
    assert "collected" in results["details"]
    assert "failed" in results["details"]
    
    # Vérifier que le répertoire de sortie existe
    assert os.path.exists(test_output_dir)
    
    # Vérifier que les sous-répertoires ont été créés
    expected_dirs = ["logs", "config", "recent", "prefetch", "startup"]
    for dir_name in expected_dirs:
        dir_path = os.path.join(test_output_dir, dir_name)
        assert os.path.exists(dir_path), f"Le répertoire {dir_name} n'a pas été créé" 