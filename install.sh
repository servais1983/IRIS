#!/bin/bash

# Couleurs pour une meilleure lisibilité
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[*] Installation IRIS - Incident Response Intelligent System${NC}"

# Vérifier si on est sur Kali Linux
if [ ! -f /etc/os-release ] || ! grep -q "Kali" /etc/os-release; then
    echo -e "${RED}[!] ERREUR: Cet outil est conçu spécifiquement pour Kali Linux${NC}"
    echo -e "${YELLOW}[!] Installation impossible sur ce système${NC}"
    exit 1
fi

# Vérifier les privilèges d'administration
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Merci d'exécuter ce script en tant qu'administrateur (sudo)${NC}"
    exit 1
fi

# Mise à jour du système
echo -e "${GREEN}[*] Mise à jour du système...${NC}"
apt update && apt upgrade -y

# Installation des dépendances système
echo -e "${GREEN}[*] Installation des dépendances système...${NC}"
apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    volatility3 \
    yara \
    clamav \
    tcpdump \
    wireshark \
    nmap \
    netcat \
    htop \
    iotop \
    lsof \
    strace \
    ltrace \
    gdb \
    radare2 \
    binwalk \
    foremost \
    testdisk \
    autopsy \
    sleuthkit \
    libpff-tools \
    libewf-tools \
    libvshadow-tools \
    libvmdk-tools \
    libvhdi-tools \
    libvslvm-tools \
    libvhd-tools \
    libqcow-tools \
    libvmdk-tools \
    libvshadow-tools \
    libvslvm-tools \
    libvhdi-tools \
    libvhd-tools \
    libqcow-tools \
    libvmdk-tools \
    libvshadow-tools \
    libvslvm-tools \
    libvhdi-tools \
    libvhd-tools \
    libqcow-tools

# Création de l'environnement virtuel Python
echo -e "${GREEN}[*] Configuration de l'environnement Python...${NC}"
python3 -m venv /opt/iris/venv
source /opt/iris/venv/bin/activate

# Installation des dépendances Python
echo -e "${GREEN}[*] Installation des packages Python...${NC}"
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Création des dossiers nécessaires
echo -e "${GREEN}[*] Configuration des dossiers...${NC}"
mkdir -p /opt/iris/{evidence,logs,config,plugins}
chmod -R 750 /opt/iris
chown -R root:root /opt/iris

# Configuration des permissions
echo -e "${GREEN}[*] Configuration des permissions...${NC}"
chmod +x iris.py
chmod +x core/*.py

# Configuration du service systemd
echo -e "${GREEN}[*] Configuration du service systemd...${NC}"
cat > /etc/systemd/system/iris.service << EOL
[Unit]
Description=IRIS Incident Response Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/iris
ExecStart=/opt/iris/venv/bin/python3 /opt/iris/iris.py --daemon
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOL

# Activation du service
systemctl daemon-reload
systemctl enable iris.service

# Configuration des règles de pare-feu
echo -e "${GREEN}[*] Configuration du pare-feu...${NC}"
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp

# Création de l'utilisateur iris
echo -e "${GREEN}[*] Configuration de l'utilisateur iris...${NC}"
useradd -m -s /bin/bash iris
usermod -aG sudo iris
echo "iris ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/iris

# Configuration des logs
echo -e "${GREEN}[*] Configuration des logs...${NC}"
cat > /etc/logrotate.d/iris << EOL
/opt/iris/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
EOL

echo -e "${GREEN}[+] Installation terminée avec succès!${NC}"
echo -e "${YELLOW}[*] Pour démarrer IRIS:${NC}"
echo -e "    - Service: systemctl start iris"
echo -e "    - CLI: /opt/iris/venv/bin/python3 /opt/iris/iris.py"
echo -e "${YELLOW}[*] Documentation: /opt/iris/README.md${NC}"
