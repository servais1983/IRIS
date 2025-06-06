#!/usr/bin/env python3
"""
Démonstration de l'outil d'analyse de mémoire et de sécurité.
"""

import os
import time
import logging
from pathlib import Path
from datetime import datetime
from core.analyze import MemoryAnalyzer
from core.monitor import SecurityMonitor
from core.report import ReportGenerator
from core.intel import ThreatIntelligence
from core.siem import SIEMConnector

def setup_demo_environment():
    """Configure l'environnement de démonstration."""
    # Créer les dossiers nécessaires
    os.makedirs("demo/reports", exist_ok=True)
    os.makedirs("demo/logs", exist_ok=True)
    os.makedirs("demo/alerts", exist_ok=True)
    
    # Configurer le logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("demo/logs/demo.log"),
            logging.StreamHandler()
        ]
    )

def run_demo():
    """Exécute la démonstration complète."""
    print("\n🚀 Démarrage de la démonstration...\n")
    
    # 1. Initialisation
    print("1. Initialisation de l'analyseur...")
    analyzer = MemoryAnalyzer(
        output_dir="demo/reports",
        log_file="demo/logs/analysis.log"
    )
    
    # 2. Analyse des processus
    print("\n2. Analyse des processus en cours...")
    suspicious_processes = analyzer.analyze_processes()
    print(f"Processus suspects détectés: {len(suspicious_processes)}")
    for proc in suspicious_processes:
        print(f"  - {proc.name} (PID: {proc.pid})")
        print(f"    Raisons: {', '.join(proc.suspicious_reasons)}")
    
    # 3. Analyse réseau
    print("\n3. Analyse des connexions réseau...")
    network_results = analyzer.analyze_network()
    print(f"Connexions suspectes détectées: {len(network_results)}")
    for conn in network_results:
        if isinstance(conn, dict):
            print(f"  - {conn.get('process', 'Unknown')} -> {conn.get('remote_addr', 'Unknown')}:{conn.get('remote_port', 'Unknown')}")
        else:
            print(f"  - Connexion suspecte détectée")
    
    # 4. Surveillance en temps réel
    print("\n4. Démarrage de la surveillance en temps réel...")
    monitor = SecurityMonitor(analyzer)
    monitor.start(interval=5)  # Vérification toutes les 5 secondes
    
    # Simuler quelques événements suspects
    print("\n5. Simulation d'événements suspects...")
    time.sleep(2)
    print("  - Tentative de connexion suspecte détectée")
    time.sleep(2)
    print("  - Processus avec privilèges élevés détecté")
    time.sleep(2)
    print("  - Activité réseau anormale détectée")
    
    # 6. Génération de rapport
    print("\n6. Génération du rapport de sécurité...")
    report = analyzer.generate_report(
        format="html",
        include_network=True,
        include_processes=True,
        include_timeline=True
    )
    analyzer.save_results(report, "demo/reports/rapport_securite.html")
    print("  Rapport généré: demo/reports/rapport_securite.html")
    
    # 7. Analyse comportementale
    print("\n7. Analyse comportementale...")
    for proc in suspicious_processes[:3]:  # Analyser les 3 premiers processus suspects
        behavior = analyzer.analyze_behavior(process=proc)
        print(f"  - {proc.name}:")
        print(f"    Niveau de suspicion: {behavior.suspicion_level}")
        print(f"    Raisons: {', '.join(behavior.reasons)}")
    
    # 8. Intégration SIEM
    print("\n8. Envoi des événements au SIEM...")
    siem = SIEMConnector(
        host="demo-siem.example.com",
        port=8080,
        token="demo-token"
    )
    events = analyzer.get_recent_events()
    siem.send_events(events)
    print(f"  {len(events)} événements envoyés au SIEM")
    
    # 9. Arrêt de la surveillance
    print("\n9. Arrêt de la surveillance...")
    monitor.stop()
    
    # 10. Résumé final
    print("\n📊 Résumé de la démonstration:")
    print(f"  - Processus suspects: {len(suspicious_processes)}")
    print(f"  - Connexions suspectes: {len(network_results)}")
    print(f"  - Événements analysés: {len(events)}")
    print(f"  - Rapports générés: 1")
    
    print("\n✅ Démonstration terminée avec succès!")
    print("Les résultats sont disponibles dans le dossier 'demo/'")

if __name__ == "__main__":
    setup_demo_environment()
    run_demo() 