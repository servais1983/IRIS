"""
Module de génération de rapports de sécurité.
"""

import os
import json
import time
import datetime
import markdown
import platform
import matplotlib.pyplot as plt
from contextlib import contextmanager
from core.utils import log_event
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import logging

# Constantes pour les types d'événements
EVENT_TYPES = {
    "INVESTIGATION_START": "Début de l'investigation",
    "MEMORY_ANALYSIS": "Analyse mémoire",
    "ARTIFACT_COLLECTION_SUMMARY": "Collecte d'artefacts",
    "NETWORK_CONTAINMENT": "Containment réseau",
    "THREAT_INTEL": "Threat Intelligence",
    "INVESTIGATION_END": "Fin de l'investigation"
}

# Constantes pour les chemins
EVIDENCE_DIR = "evidence"
LOG_FILE = "iris_log.json"
REPORT_MD = "report.md"
REPORT_HTML = "report.html"
TIMELINE_IMAGE = "timeline.png"

# Format de date standard
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

@dataclass
class ReportSection:
    """Section d'un rapport."""
    title: str
    content: Dict[str, Any]

class ReportGenerator:
    """Générateur de rapports de sécurité."""
    
    def __init__(self, output_dir: Path):
        """Initialise le générateur de rapports.
        
        Args:
            output_dir: Dossier de sortie pour les rapports
        """
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
        
    def generate_report(
        self,
        format: str = "html",
        include_network: bool = True,
        include_processes: bool = True,
        include_timeline: bool = True
    ) -> str:
        """Génère un rapport de sécurité.
        
        Args:
            format: Format du rapport (html, pdf, json)
            include_network: Inclure l'analyse réseau
            include_processes: Inclure l'analyse des processus
            include_timeline: Inclure la timeline des événements
            
        Returns:
            Rapport généré au format demandé
        """
        report = {
            "timestamp": datetime.datetime.now().isoformat(),
            "sections": []
        }
        
        # Ajouter les sections demandées
        if include_processes:
            report["sections"].append(
                ReportSection(
                    title="Analyse des Processus",
                    content=self._generate_process_section()
                )
            )
            
        if include_network:
            report["sections"].append(
                ReportSection(
                    title="Analyse Réseau",
                    content=self._generate_network_section()
                )
            )
            
        if include_timeline:
            report["sections"].append(
                ReportSection(
                    title="Timeline des Événements",
                    content=self._generate_timeline_section()
                )
            )
            
        # Générer le rapport dans le format demandé
        if format == "html":
            return self._generate_html_report(report)
        elif format == "json":
            return self._generate_json_report(report)
        else:
            raise ValueError(f"Format de rapport non supporté: {format}")
            
    def _generate_process_section(self) -> Dict[str, Any]:
        """Génère la section d'analyse des processus.
        
        Returns:
            Contenu de la section
        """
        return {
            "suspicious_processes": [],
            "elevated_privileges": [],
            "anomalies": []
        }
        
    def _generate_network_section(self) -> Dict[str, Any]:
        """Génère la section d'analyse réseau.
        
        Returns:
            Contenu de la section
        """
        return {
            "suspicious_connections": [],
            "open_ports": [],
            "network_anomalies": []
        }
        
    def _generate_timeline_section(self) -> Dict[str, Any]:
        """Génère la section timeline.
        
        Returns:
            Contenu de la section
        """
        return {
            "events": [],
            "alerts": [],
            "incidents": []
        }
        
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Génère un rapport au format HTML.
        
        Args:
            report: Données du rapport
            
        Returns:
            Rapport au format HTML
        """
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rapport de Sécurité - {report['timestamp']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2c3e50; }}
                .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ddd; }}
                .alert {{ color: #e74c3c; }}
                .warning {{ color: #f39c12; }}
                .info {{ color: #3498db; }}
            </style>
        </head>
        <body>
            <h1>Rapport de Sécurité</h1>
            <p>Généré le: {report['timestamp']}</p>
        """
        
        for section in report["sections"]:
            html += f"""
            <div class="section">
                <h2>{section.title}</h2>
                <pre>{json.dumps(section.content, indent=2)}</pre>
            </div>
            """
            
        html += """
        </body>
        </html>
        """
        
        return html
        
    def _generate_json_report(self, report: Dict[str, Any]) -> str:
        """Génère un rapport au format JSON.
        
        Args:
            report: Données du rapport
            
        Returns:
            Rapport au format JSON
        """
        return json.dumps(report, indent=2)

@contextmanager
def figure_context():
    """Contexte pour gérer les figures matplotlib."""
    try:
        yield
    finally:
        plt.close('all')

def cleanup():
    """Nettoie les ressources utilisées par le module de rapport."""
    plt.close('all')  # Ferme toutes les figures matplotlib

def _format_datetime(dt_str: str) -> str:
    """Formate une date ISO en format lisible.
    
    Args:
        dt_str: Date au format ISO
        
    Returns:
        Date formatée
    """
    try:
        dt = datetime.datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        return dt.strftime(DATE_FORMAT)
    except Exception:
        return dt_str

def _validate_paths(session: str) -> Tuple[Path, Path, Path, Path]:
    """Valide et crée les chemins nécessaires pour le rapport.
    
    Args:
        session: ID de la session d'investigation
        
    Returns:
        Tuple contenant les chemins validés (log_path, report_md_path, report_html_path, timeline_path)
        
    Raises:
        RuntimeError: Si la création des chemins échoue
    """
    try:
        # Créer le dossier evidence s'il n'existe pas
        evidence_dir = Path(EVIDENCE_DIR) / session
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Définir les chemins
        log_path = evidence_dir / LOG_FILE
        report_md_path = evidence_dir / REPORT_MD
        report_html_path = evidence_dir / REPORT_HTML
        timeline_path = evidence_dir / TIMELINE_IMAGE
        
        return log_path, report_md_path, report_html_path, timeline_path
    except Exception as e:
        raise RuntimeError(f"Erreur lors de la validation des chemins: {str(e)}")

def _read_events(log_path: Path, session: str) -> List[Dict[str, Any]]:
    """Lit les événements depuis le fichier journal.
    
    Args:
        log_path: Chemin vers le fichier journal
        session: ID de la session d'investigation
        
    Returns:
        Liste des événements lus
        
    Raises:
        RuntimeError: Si la lecture du journal échoue
    """
    events = []
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    event = json.loads(line.strip())
                    events.append(event)
                except json.JSONDecodeError as e:
                    error_msg = f"Ligne JSON invalide dans le journal (ligne {line_num}): {line.strip()}"
                    print(f"[!] {error_msg}")
                    log_event(session, "REPORT_WARNING", {
                        "error": str(e),
                        "line": line.strip(),
                        "line_number": line_num
                    })
    except Exception as e:
        raise RuntimeError(f"Erreur lors de la lecture du journal: {str(e)}")
    
    return events

def _generate_timeline(events: List[Dict[str, Any]], timeline_path: Path, quick: bool = False) -> Optional[Path]:
    """Génère la timeline des événements.
    
    Args:
        events: Liste des événements
        timeline_path: Chemin pour sauvegarder l'image
        quick: Si True, génère une timeline simplifiée
        
    Returns:
        Chemin de l'image générée ou None en cas d'échec
    """
    try:
        with figure_context():
            # Extraire les événements significatifs pour la timeline
            timeline_events = []
            for event in events:
                if event['type'] in EVENT_TYPES:
                    event_time = datetime.datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    timeline_events.append((event_time, EVENT_TYPES[event['type']]))
            
            if timeline_events and not quick:
                # Créer un graphique de chronologie
                fig, ax = plt.figure(figsize=(10, 6)), plt.gca()
                
                # Préparer les données pour le graphique
                times = [e[0] for e in timeline_events]
                types = [e[1] for e in timeline_events]
                
                # Créer le graphique
                ax.scatter(times, types, s=100, alpha=0.7)
                ax.grid(True)
                
                # Formatage
                plt.title("Chronologie de l'investigation")
                plt.xlabel("Temps")
                plt.ylabel("Événement")
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                # Sauvegarder le graphique
                plt.savefig(timeline_path)
                return timeline_path
    except Exception as e:
        print(f"[!] Erreur lors de la création de la chronologie: {e}")
        return None

def generate_report(session: str, quick: bool = False) -> bool:
    """
    Génère un rapport complet de l'investigation.
    
    Args:
        session: Identifiant de la session d'investigation
        quick: Si True, génère un rapport simplifié
        
    Returns:
        bool: True si le rapport a été généré avec succès
    """
    print("[*] Génération de rapport...")
    
    try:
        # Valider les chemins
        log_path, report_md_path, report_html_path, timeline_path = _validate_paths(session)
        
        # Vérifier que le journal existe
        if not log_path.exists():
            error_msg = f"Fichier journal introuvable: {log_path}"
            print(f"[!] {error_msg}")
            log_event(session, "REPORT_ERROR", {"error": error_msg})
            return False
        
        # Lire les événements
        try:
            events = _read_events(log_path, session)
        except RuntimeError as e:
            log_event(session, "REPORT_ERROR", {"error": str(e)})
            return False
        
        # Afficher un message d'erreur si aucun événement n'a été trouvé
        if not events:
            error_msg = "Aucun événement trouvé dans le journal"
            print(f"[!] {error_msg}")
            log_event(session, "REPORT_ERROR", {"error": error_msg})
            return False
        
        # Générer la timeline
        timeline_path = _generate_timeline(events, timeline_path, quick)
        
        # Préparer le contenu du rapport
        report_content = []
        
        # --- En-tête du rapport ---
        report_content.append("# Rapport d'Investigation IRIS\n")
        
        # Horodatage et informations générales
        start_time = None
        end_time = None
        investigation_mode = None
        
        for event in events:
            if event['type'] == "INVESTIGATION_START":
                start_time = _format_datetime(event['timestamp'])
                investigation_mode = event['data'].get('mode', 'unknown')
            elif event['type'] == "INVESTIGATION_END":
                end_time = _format_datetime(event['timestamp'])
        
        report_content.append(f"## Informations générales\n")
        report_content.append(f"- **ID d'investigation:** {session}")
        report_content.append(f"- **Mode d'investigation:** {investigation_mode}")
        report_content.append(f"- **Début:** {start_time}")
        report_content.append(f"- **Fin:** {end_time or 'En cours'}")
        report_content.append(f"- **Système:** {platform.system()} {platform.release()}")
        report_content.append(f"- **Rapport généré le:** {datetime.datetime.now().strftime(DATE_FORMAT)}")
        report_content.append("\n")
        
        # --- Résumé des résultats ---
        report_content.append("## Résumé des résultats\n")
        
        # Résumé de l'analyse mémoire
        for event in events:
            if event['type'] == "MEMORY_ANALYSIS":
                total_procs = event['data'].get('total_processes', 0)
                suspicious_procs = event['data'].get('suspicious_processes', 0)
                report_content.append(f"- **Processus analysés:** {total_procs}")
                report_content.append(f"- **Processus suspects:** {suspicious_procs}")
                
                if suspicious_procs > 0 and not quick:
                    report_content.append("\n### Processus suspects détectés\n")
                    report_content.append("| PID | Nom | Utilisateur |")
                    report_content.append("|-----|-----|------------|")
                    
                    for proc in event['data'].get('details', []):
                        if proc.get('suspicious', False):
                            pid = proc.get('pid', 'N/A')
                            name = proc.get('name', 'N/A')
                            user = proc.get('username', 'N/A')
                            report_content.append(f"| {pid} | {name} | {user} |")
        
        # Résumé de la collecte d'artefacts
        for event in events:
            if event['type'] == "ARTIFACT_COLLECTION_SUMMARY":
                collected = event['data'].get('collected', 0)
                failed = event['data'].get('failed', 0)
                system = event['data'].get('system', 'unknown')
                report_content.append(f"- **Artefacts collectés:** {collected}")
                report_content.append(f"- **Échecs de collecte:** {failed}")
        
        # Résumé des containments réseau
        for event in events:
            if event['type'] == "NETWORK_CONTAINMENT":
                blocked = len(event['data'].get('blocked_ips', []))
                failed = len(event['data'].get('failed_ips', []))
                report_content.append(f"- **IPs bloquées:** {blocked}")
                
                if blocked > 0:
                    ips = ", ".join(event['data'].get('blocked_ips', []))
                    report_content.append(f"  - {ips}")
        
        # Résumé des vérifications Threat Intel
        intel_hits = {}
        for event in events:
            if event['type'] == "THREAT_INTEL":
                for indicator, results in event['data'].items():
                    for source, result in results.items():
                        if result.get('found', False):
                            intel_hits[indicator] = intel_hits.get(indicator, []) + [source]
        
        if intel_hits:
            report_content.append("- **Indicateurs malveillants confirmés:**")
            for indicator, sources in intel_hits.items():
                report_content.append(f"  - {indicator} (Sources: {', '.join(sources)})")
        
        report_content.append("\n")
        
        # --- Timeline des événements ---
        try:
            with figure_context():
                # Extraire les événements significatifs pour la timeline
                timeline_events = []
                for event in events:
                    if event['type'] in ["INVESTIGATION_START", "MEMORY_ANALYSIS", 
                                        "ARTIFACT_COLLECTION_SUMMARY", "NETWORK_CONTAINMENT", 
                                        "THREAT_INTEL", "INVESTIGATION_END"]:
                        event_time = datetime.datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                        timeline_events.append((event_time, event['type']))
                
                if timeline_events and not quick:
                    # Créer un graphique de chronologie
                    fig, ax = plt.figure(figsize=(10, 6)), plt.gca()
                    
                    # Préparer les données pour le graphique
                    times = [e[0] for e in timeline_events]
                    types = [e[1] for e in timeline_events]
                    
                    # Créer le graphique
                    ax.scatter(times, types, s=100, alpha=0.7)
                    ax.grid(True)
                    
                    # Formatage
                    plt.title("Chronologie de l'investigation")
                    plt.xlabel("Temps")
                    plt.ylabel("Événement")
                    plt.xticks(rotation=45)
                    plt.tight_layout()
                    
                    # Sauvegarder le graphique
                    plt.savefig(timeline_path)
        except Exception as e:
            print(f"[!] Erreur lors de la création de la chronologie: {e}")
            timeline_path = None
        
        # --- Section détaillée ---
        if not quick:
            report_content.append("## Détails de l'investigation\n")
            
            # Ajouter des sections détaillées pour chaque type d'analyse
            # Cette partie pourrait être étendue avec plus de détails dans une implémentation complète
            
            # Threat Intelligence détaillée
            report_content.append("### Résultats Threat Intelligence\n")
            for event in events:
                if event['type'] == "THREAT_INTEL":
                    for indicator, results in event['data'].items():
                        report_content.append(f"#### Indicateur: {indicator}\n")
                        
                        for source, result in results.items():
                            report_content.append(f"**Source: {source}**\n")
                            
                            if "error" in result:
                                report_content.append(f"- Erreur: {result['error']}")
                            elif result.get('found', False):
                                # Détails spécifiques selon la source
                                if source == "AlienVault OTX":
                                    report_content.append(f"- Premiers signalements: {result.get('first_seen', 'N/A')}")
                                    report_content.append(f"- Derniers signalements: {result.get('last_seen', 'N/A')}")
                                    report_content.append(f"- Score de menace: {result.get('threat_score', 'N/A')}")
                                    
                                    if 'categories' in result:
                                        cats = ', '.join(result['categories']) if result['categories'] else 'Aucune'
                                        report_content.append(f"- Catégories: {cats}")
                                
                                elif source == "MISP":
                                    report_content.append(f"- Nombre d'événements: {result.get('events_count', 0)}")
                                    report_content.append(f"- Niveau de menace: {result.get('threat_level', 'N/A')}")
                            else:
                                report_content.append("- Non trouvé dans cette source")
                            
                            report_content.append("\n")
        
        # --- Recommandations ---
        report_content.append("## Recommandations\n")
        
        # Générer des recommandations automatiques basées sur les résultats
        if intel_hits:
            report_content.append("- **Haute priorité:** Des indicateurs malveillants confirmés ont été détectés. Une investigation approfondie est nécessaire.")
        
        suspicious_procs_found = False
        for event in events:
            if event['type'] == "MEMORY_ANALYSIS" and event['data'].get('suspicious_processes', 0) > 0:
                suspicious_procs_found = True
        
        if suspicious_procs_found:
            report_content.append("- **Moyenne priorité:** Des processus suspects ont été identifiés. Analyser manuellement ces processus pour confirmer leur légitimité.")
        
        report_content.append("- **Générale:** Effectuer une analyse anti-malware complète du système.")
        report_content.append("- **Générale:** Vérifier les journaux d'authentification pour détecter d'éventuelles activités suspectes.")
        report_content.append("\n")
        
        # --- Écrire le rapport ---
        with open(report_md_path, 'w') as f:
            f.write('\n'.join(report_content))
        
        # Générer le HTML si la bibliothèque markdown est disponible
        try:
            with open(report_md_path, 'r') as f:
                md_content = f.read()
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Rapport d'Investigation IRIS - {session}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; max-width: 1200px; margin: 0 auto; }}
                    h1, h2, h3 {{ color: #2c3e50; }}
                    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    img {{ max-width: 100%; }}
                    .header {{ background-color: #34495e; color: white; padding: 10px; text-align: center; }}
                    .footer {{ margin-top: 30px; text-align: center; font-size: 0.8em; color: #7f8c8d; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>IRIS - Rapport d'Investigation</h1>
                    <p>ID: {session}</p>
                </div>
                
                {markdown.markdown(md_content)}
                
                <div class="footer">
                    <p>Généré par IRIS - Incident Response Intelligent System</p>
                </div>
            </body>
            </html>
            """
            
            with open(report_html_path, 'w') as f:
                f.write(html_content)
            
            print(f"[+] Rapport HTML généré: {report_html_path}")
            
        except Exception as e:
            print(f"[!] Erreur lors de la génération du rapport HTML: {e}")
        
        # Enregistrer l'action
        log_event(session, "REPORT_GENERATED", {
            "markdown_path": str(report_md_path),
            "html_path": str(report_html_path),
            "timeline_path": str(timeline_path) if timeline_path and timeline_path.exists() else None
        })
        
        print(f"[+] Rapport généré: {report_md_path}")
        return True

    except Exception as e:
        error_msg = f"Erreur lors de la génération du rapport: {str(e)}"
        print(f"[!] {error_msg}")
        log_event(session, "REPORT_ERROR", {"error": error_msg})
        return False
    finally:
        cleanup()  # S'assurer que toutes les figures sont fermées
