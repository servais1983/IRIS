#!/usr/bin/env python3
"""
IRIS - Outil d'Analyse de Mémoire et de Sécurité
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime
from core.analyze import MemoryAnalyzer
from core.monitor import SecurityMonitor
from core.report import ReportGenerator

def setup_logging():
    """Configure le système de logging."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / f"iris_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
            logging.StreamHandler()
        ]
    )

def main():
    """Fonction principale."""
    # Configuration
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Création des dossiers nécessaires
    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)
    
    try:
        # Initialisation de l'analyseur
        logger.info("Initialisation de l'analyseur...")
        analyzer = MemoryAnalyzer(
            output_dir=output_dir,
            log_file=output_dir / "analysis.log"
        )
        
        # Analyse des processus
        logger.info("Analyse des processus en cours...")
        suspicious_processes = analyzer.analyze_processes()
        logger.info(f"Processus suspects détectés: {len(suspicious_processes)}")
        for proc in suspicious_processes:
            logger.warning(f"Processus suspect: {proc.name} (PID: {proc.pid})")
            logger.warning(f"Raisons: {', '.join(proc.suspicious_reasons)}")
        
        # Analyse réseau
        logger.info("Analyse des connexions réseau...")
        network_results = analyzer.analyze_network()
        logger.info(f"Connexions suspectes détectées: {len(network_results)}")
        for conn in network_results:
            if isinstance(conn, dict):
                logger.warning(
                    f"Connexion suspecte: {conn.get('process', 'Unknown')} -> "
                    f"{conn.get('remote_addr', 'Unknown')}:{conn.get('remote_port', 'Unknown')}"
                )
        
        # Démarrage de la surveillance
        logger.info("Démarrage de la surveillance en temps réel...")
        monitor = SecurityMonitor(analyzer)
        monitor.start(interval=60)  # Vérification toutes les minutes
        
        # Génération du rapport
        logger.info("Génération du rapport de sécurité...")
        report = analyzer.generate_report(
            format="html",
            include_network=True,
            include_processes=True,
            include_timeline=True
        )
        report_file = output_dir / f"rapport_securite_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        analyzer.save_results(report, str(report_file))
        logger.info(f"Rapport généré: {report_file}")
        
        # Attente de l'utilisateur pour arrêter
        print("\nSurveillance en cours... Appuyez sur Ctrl+C pour arrêter.")
        try:
            while True:
                pass
        except KeyboardInterrupt:
            logger.info("Arrêt de la surveillance...")
            monitor.stop()
            
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
