#!/bin/bash
echo "[*] Installation IRIS..."

# Vérifier les privilèges d'administration
if [ "$EUID" -ne 0 ]; then
    echo "[!] Merci d'exécuter ce script en tant qu'administrateur (sudo)"
    exit 1
fi

# Détecter le système d'exploitation
OS="$(uname -s)"
echo "[*] Système détecté: $OS"

if [ "$OS" = "Linux" ]; then
    # Installation des dépendances Linux
    echo "[*] Installation des dépendances Linux..."
    apt update
    apt install -y python3 python3-pip python3-dev build-essential
elif [ "$OS" = "Darwin" ]; then
    # Installation des dépendances macOS
    echo "[*] Installation des dépendances macOS..."
    if ! command -v brew &> /dev/null; then
        echo "[!] Homebrew non trouvé. Installation..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install python3
else
    # Instructions pour Windows (via WSL) ou autre
    echo "[!] OS non géré directement. Merci d'installer manuellement Python 3 et pip."
    echo "    Visitez https://www.python.org/downloads/ pour télécharger Python."
fi

# Installation des dépendances Python
echo "[*] Installation des packages Python..."
pip3 install -r requirements.txt

# Création des dossiers nécessaires
echo "[*] Création des dossiers pour les preuves..."
mkdir -p evidence

# Rendre l'exécutable principal exécutable
chmod +x iris.py

echo "[+] IRIS prêt à l'emploi. Lancez :"
echo "python3 iris.py --mode full --output investigation"
