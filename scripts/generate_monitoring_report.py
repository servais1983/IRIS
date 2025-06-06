#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de génération de rapports de monitoring pour IRIS.
"""

import os
import sys
import yaml
import json
import logging
from datetime import datetime, timedelta
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/iris/report_generator.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class MonitoringReport:
    """Classe pour la génération de rapports de monitoring."""

    def __init__(self, config_path: str = '/etc/iris/monitoring.yaml'):
        """Initialise le générateur de rapports.

        Args:
            config_path: Chemin vers le fichier de configuration.
        """
        self.config_path = config_path
        self.config = self._load_config()
        self.metrics_dir = '/var/log/iris/metrics'
        self.report_dir = '/var/log/iris/reports'

    def _load_config(self) -> dict:
        """Charge la configuration depuis le fichier YAML.

        Returns:
            Dictionnaire de configuration.
        """
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                if not isinstance(config, dict):
                    raise ValueError("La configuration doit être un dictionnaire")
                return config
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la configuration: {str(e)}")
            raise

    def _load_metrics(self, days: int = 1) -> pd.DataFrame:
        """Charge les métriques des derniers jours.

        Args:
            days: Nombre de jours à charger.

        Returns:
            DataFrame contenant les métriques.
        """
        try:
            metrics = []
            start_date = datetime.now() - timedelta(days=days)
            
            for filename in os.listdir(self.metrics_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.metrics_dir, filename)
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        if datetime.fromisoformat(data['timestamp']) >= start_date:
                            metrics.append(data['metrics'])

            return pd.DataFrame(metrics)
        except Exception as e:
            logger.error(f"Erreur lors du chargement des métriques: {str(e)}")
            raise

    def _generate_plots(self, df: pd.DataFrame) -> list:
        """Génère les graphiques pour le rapport.

        Args:
            df: DataFrame contenant les métriques.

        Returns:
            Liste des chemins des fichiers graphiques.
        """
        try:
            plots = []
            plt.style.use('seaborn')

            # CPU Usage
            plt.figure(figsize=(10, 6))
            sns.lineplot(data=df, x=df.index, y='cpu_usage')
            plt.title('CPU Usage Over Time')
            plt.xlabel('Time')
            plt.ylabel('Usage (%)')
            cpu_plot = os.path.join(self.report_dir, 'cpu_usage.png')
            plt.savefig(cpu_plot)
            plt.close()
            plots.append(cpu_plot)

            # Memory Usage
            plt.figure(figsize=(10, 6))
            sns.lineplot(data=df, x=df.index, y='memory_percent')
            plt.title('Memory Usage Over Time')
            plt.xlabel('Time')
            plt.ylabel('Usage (%)')
            mem_plot = os.path.join(self.report_dir, 'memory_usage.png')
            plt.savefig(mem_plot)
            plt.close()
            plots.append(mem_plot)

            # Disk Usage
            plt.figure(figsize=(10, 6))
            sns.lineplot(data=df, x=df.index, y='disk_percent')
            plt.title('Disk Usage Over Time')
            plt.xlabel('Time')
            plt.ylabel('Usage (%)')
            disk_plot = os.path.join(self.report_dir, 'disk_usage.png')
            plt.savefig(disk_plot)
            plt.close()
            plots.append(disk_plot)

            return plots
        except Exception as e:
            logger.error(f"Erreur lors de la génération des graphiques: {str(e)}")
            raise

    def _generate_pdf(self, df: pd.DataFrame, plots: list) -> str:
        """Génère le rapport PDF.

        Args:
            df: DataFrame contenant les métriques.
            plots: Liste des chemins des fichiers graphiques.

        Returns:
            Chemin du fichier PDF généré.
        """
        try:
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30
            )

            # Création du document
            report_path = os.path.join(self.report_dir, f'report_{datetime.now().strftime("%Y%m%d")}.pdf')
            doc = SimpleDocTemplate(report_path, pagesize=letter)
            elements = []

            # Titre
            elements.append(Paragraph('IRIS Monitoring Report', title_style))
            elements.append(Spacer(1, 12))

            # Résumé
            summary = [
                ['Metric', 'Min', 'Max', 'Average'],
                ['CPU Usage (%)', f"{df['cpu_usage'].min():.1f}", f"{df['cpu_usage'].max():.1f}", f"{df['cpu_usage'].mean():.1f}"],
                ['Memory Usage (%)', f"{df['memory_percent'].min():.1f}", f"{df['memory_percent'].max():.1f}", f"{df['memory_percent'].mean():.1f}"],
                ['Disk Usage (%)', f"{df['disk_percent'].min():.1f}", f"{df['disk_percent'].max():.1f}", f"{df['disk_percent'].mean():.1f}"]
            ]

            table = Table(summary)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
            elements.append(Spacer(1, 20))

            # Graphiques
            for plot in plots:
                elements.append(Paragraph(os.path.basename(plot).replace('_', ' ').title(), styles['Heading2']))
                elements.append(Spacer(1, 12))
                elements.append(Image(plot, width=6*inch, height=4*inch))
                elements.append(Spacer(1, 20))

            # Génération du PDF
            doc.build(elements)
            return report_path
        except Exception as e:
            logger.error(f"Erreur lors de la génération du PDF: {str(e)}")
            raise

    def _send_report(self, report_path: str) -> None:
        """Envoie le rapport par email.

        Args:
            report_path: Chemin du fichier rapport.
        """
        try:
            msg = MIMEMultipart()
            msg['Subject'] = f'IRIS Monitoring Report - {datetime.now().strftime("%Y-%m-%d")}'
            msg['From'] = self.config['alerts']['email']['from_address']
            msg['To'] = ', '.join(self.config['alerts']['email']['to_addresses'])

            # Corps du message
            body = "Veuillez trouver ci-joint le rapport de monitoring IRIS."
            msg.attach(MIMEText(body, 'plain'))

            # Pièce jointe
            with open(report_path, 'rb') as f:
                part = MIMEApplication(f.read(), Name=os.path.basename(report_path))
            part['Content-Disposition'] = f'attachment; filename="{os.path.basename(report_path)}"'
            msg.attach(part)

            # Envoi
            with smtplib.SMTP(self.config['alerts']['email']['smtp_server'], self.config['alerts']['email']['smtp_port']) as server:
                server.starttls()
                server.send_message(msg)

            logger.info(f"Rapport envoyé à {msg['To']}")
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi du rapport: {str(e)}")
            raise

    def generate_report(self, days: int = 1) -> None:
        """Génère et envoie le rapport de monitoring.

        Args:
            days: Nombre de jours à inclure dans le rapport.
        """
        try:
            # Création des répertoires si nécessaire
            os.makedirs(self.report_dir, exist_ok=True)

            # Chargement des métriques
            df = self._load_metrics(days)

            # Génération des graphiques
            plots = self._generate_plots(df)

            # Génération du PDF
            report_path = self._generate_pdf(df, plots)

            # Envoi du rapport
            if self.config['reports']['daily']['enabled']:
                self._send_report(report_path)

            logger.info(f"Rapport généré avec succès: {report_path}")
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport: {str(e)}")
            raise

def main():
    """Fonction principale."""
    try:
        report_generator = MonitoringReport()
        report_generator.generate_report()
    except Exception as e:
        logger.error(f"Erreur dans la fonction principale: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 