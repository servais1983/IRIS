import psutil
import numpy as np
from sklearn.ensemble import IsolationForest
from core.utils import log_event

def memory_forensics(session):
    """
    Effectue une analyse forensique de la mémoire en utilisant l'algorithme Isolation Forest
    pour détecter les processus anormaux en fonction de leurs caractéristiques.
    
    Args:
        session (str): Identifiant de la session d'investigation
    """
    print("[*] Analyse mémoire en cours...")
    
    # Initialiser le modèle d'anomalie
    # Le paramètre contamination représente la proportion attendue d'anomalies
    model = IsolationForest(contamination=0.01)
    
    # Collecter les informations sur les processus
    procs = []
    proc_features = []  # Pour stocker les caractéristiques à analyser
    
    # Extraction des caractéristiques pertinentes pour chaque processus
    for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent', 'username']):
        try:
            # Récupérer les informations de base sur le processus
            info = proc.info
            
            # Ajouter des caractéristiques pour l'analyse d'anomalie
            # Utilisation mémoire, pourcentage CPU, etc.
            memory_usage = info['memory_info'].rss if info['memory_info'] else 0
            cpu_usage = proc.cpu_percent(interval=0.1)
            
            # Stocker les features pour l'analyse
            features = [memory_usage, cpu_usage]
            proc_features.append(features)
            
            # Stocker les informations complètes sur le processus
            info['features'] = features
            procs.append(info)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            # Gérer les erreurs liées aux processus
            continue
    
    # Si nous avons des processus à analyser
    if proc_features:
        # Normaliser les caractéristiques pour un meilleur résultat
        proc_features = np.array(proc_features)
        if len(proc_features) > 1:  # S'assurer qu'il y a au moins 2 échantillons
            # Entraîner le modèle et prédire les anomalies
            predictions = model.fit_predict(proc_features)
            
            # Attribuer les résultats aux processus
            for i, pred in enumerate(predictions):
                # -1 signifie une anomalie, 1 signifie normal
                procs[i]['suspicious'] = (pred == -1)
        else:
            # Si un seul processus, il ne peut pas être considéré comme anormal
            procs[0]['suspicious'] = False
    
    # Filtrer les processus suspects pour l'affichage
    suspicious_procs = [p for p in procs if p.get('suspicious', False)]
    
    # Afficher les résultats
    if suspicious_procs:
        print(f"[!] {len(suspicious_procs)} processus suspects détectés:")
        for proc in suspicious_procs:
            print(f"    - PID {proc['pid']}: {proc['name']} ({proc['username']})")
    else:
        print("[+] Aucun processus suspect détecté")
    
    # Enregistrer tous les résultats dans le journal
    log_event(session, "MEMORY_ANALYSIS", {
        "total_processes": len(procs),
        "suspicious_processes": len(suspicious_procs),
        "details": procs
    })
    
    return suspicious_procs
