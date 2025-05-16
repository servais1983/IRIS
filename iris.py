#!/usr/bin/env python3

import argparse
from core import analyze, collect, contain, intel, report, utils

def main():
    parser = argparse.ArgumentParser(description="IRIS - Incident Response Intelligent System")
    parser.add_argument("--mode", choices=["quick", "full", "forensic"], default="full", 
                        help="Mode d'exécution: rapide, complet ou forensique")
    parser.add_argument("--output", default="investigation", 
                        help="Préfixe du dossier de sortie pour les preuves collectées")
    args = parser.parse_args()

    # Initialiser la session et créer le dossier d'investigation
    investigation_id = utils.init_session(args.output)
    utils.log_event(investigation_id, "INVESTIGATION_START", {"mode": args.mode})
    
    print(f"[+] Démarrage investigation IRIS - ID: {investigation_id}, Mode: {args.mode}")

    if args.mode in ["full", "forensic"]:
        # Analyse mémoire pour détecter les processus suspects
        analyze.memory_forensics(investigation_id)
        
        # Collecte des artefacts système
        collect.artifact_collection(investigation_id)
        
        # Contenir les adresses IP suspectes
        contain.network_containment(investigation_id, ["192.168.1.100", "10.0.0.5"])
        
        # Vérification des indicateurs avec les systèmes de threat intelligence
        intel.threat_intel_check(investigation_id, ["malware.exe", "bad-domain.com"])
        
        # Génération du rapport final
        report.generate_report(investigation_id)
    elif args.mode == "quick":
        # Mode rapide: uniquement analyse mémoire et collecte basique
        analyze.memory_forensics(investigation_id)
        collect.artifact_collection(investigation_id, quick=True)
        report.generate_report(investigation_id, quick=True)

    utils.log_event(investigation_id, "INVESTIGATION_END", {"status": "completed"})
    print(f"[+] Investigation terminée. Résultats dans: evidence/{investigation_id}/")

if __name__ == "__main__":
    main()
