import os
import hashlib
import json
from datetime import datetime

def init_session(prefix):
    """
    Initialise une nouvelle session d'investigation avec un identifiant unique basé sur la date et l'heure.
    Crée le dossier de destination pour les preuves.
    
    Args:
        prefix (str): Préfixe pour le nom du dossier
        
    Returns:
        str: Identifiant unique de la session
    """
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = f"{prefix}_{ts}"
    os.makedirs(f"evidence/{folder}", exist_ok=True)
    return folder

def log_event(session, event_type, data):
    """
    Enregistre un événement dans le journal de l'investigation avec horodatage et hachage.
    
    Args:
        session (str): Identifiant de la session d'investigation
        event_type (str): Type d'événement à enregistrer
        data (dict): Données associées à l'événement
    """
    log_path = f"evidence/{session}/iris_log.json"
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": event_type,
        "data": data,
        "hash": hashlib.sha3_256(str(data).encode()).hexdigest()
    }
    
    # S'assurer que le dossier existe
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    
    # Écrire l'entrée dans le journal
    with open(log_path, 'a') as f:
        f.write(json.dumps(entry) + "\n")

def calculate_file_hash(file_path, algorithms=None):
    """
    Calcule les hachages d'un fichier selon plusieurs algorithmes.
    
    Args:
        file_path (str): Chemin vers le fichier à hacher
        algorithms (list): Liste des algorithmes à utiliser (défaut: MD5, SHA1, SHA256)
        
    Returns:
        dict: Dictionnaire des hachages par algorithme
    """
    if algorithms is None:
        algorithms = ['md5', 'sha1', 'sha256']
    
    hashes = {}
    
    try:
        for algorithm in algorithms:
            if algorithm == 'md5':
                hash_obj = hashlib.md5()
            elif algorithm == 'sha1':
                hash_obj = hashlib.sha1()
            elif algorithm == 'sha256':
                hash_obj = hashlib.sha256()
            else:
                continue
                
            with open(file_path, 'rb') as f:
                # Lire le fichier par blocs pour gérer les fichiers volumineux
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
                    
            hashes[algorithm] = hash_obj.hexdigest()
    except Exception as e:
        print(f"[!] Erreur lors du calcul du hachage pour {file_path}: {e}")
    
    return hashes

def create_chain_of_custody(session, artifact_path, source_path, collector):
    """
    Crée une entrée de chaîne de possession pour un artefact collecté.
    
    Args:
        session (str): Identifiant de la session d'investigation
        artifact_path (str): Chemin de l'artefact collecté
        source_path (str): Chemin source original
        collector (str): Identifiant de la personne ou du système ayant collecté l'artefact
    """
    # Calculer les hachages
    hashes = calculate_file_hash(artifact_path)
    
    # Créer l'entrée de chaîne de possession
    custody_entry = {
        "artifact": artifact_path,
        "source": source_path,
        "collected_by": collector,
        "collected_at": datetime.utcnow().isoformat() + "Z",
        "hashes": hashes
    }
    
    # Enregistrer dans le journal
    log_event(session, "CHAIN_OF_CUSTODY", custody_entry)
    
    return custody_entry
