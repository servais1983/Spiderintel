#!/bin/bash

# SpiderIntel v2.0.0 - Script d'installation pour Kali Linux
# Sécurité renforcée et auditée

set -euo pipefail
IFS=$'\n\t'

# Couleurs pour l'affichage
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Vérification de Kali Linux
check_kali_linux() {
    if [ ! -f "/etc/os-release" ]; then
        echo -e "${RED}ERREUR: Système d'exploitation non supporté${NC}"
        exit 1
    fi

    local os_id
    os_id=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
    local os_name
    os_name=$(grep "^NAME=" /etc/os-release | cut -d= -f2 | tr -d '"')

    if [[ "$os_id" != "kali" ]] || [[ ! "$os_name" =~ "Kali" ]]; then
        echo -e "${RED}ERREUR: Cet outil est exclusivement compatible avec Kali Linux${NC}"
        echo "Système détecté: $os_name"
        exit 1
    fi
}

# Installation des outils Kali requis
install_kali_tools() {
    echo -e "${BLUE}Installation des outils Kali requis...${NC}"
    
    local tools=(
        "nmap"
        "whatweb"
        "theharvester"
        "dnsrecon"
        "dirb"
        "nikto"
        "sqlmap"
        "metasploit-framework"
    )
    
    for tool in "${tools[@]}"; do
        if ! dpkg -l | grep -q "^ii  $tool "; then
            echo -e "${YELLOW}Installation de $tool...${NC}"
            sudo apt install -y "$tool"
        else
            echo -e "${GREEN}$tool déjà installé${NC}"
        fi
    done
}

# Configuration des répertoires
setup_directories() {
    echo -e "${BLUE}Configuration des répertoires...${NC}"
    
    local directories=("reports" "logs" "temp")
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            chmod 700 "$dir"
            echo -e "${GREEN}Répertoire $dir créé${NC}"
        fi
    done
}

# Configuration du script principal
setup_main_script() {
    echo -e "${BLUE}Configuration du script principal...${NC}"
    
    if [ -f "spiderintel.sh" ]; then
        chmod +x spiderintel.sh
        echo -e "${GREEN}Script principal configuré${NC}"
    else
        echo -e "${RED}ERREUR: Script principal non trouvé${NC}"
        exit 1
    fi
}

# Installation principale
main() {
    echo -e "${BLUE}SpiderIntel v2.0.0 - Installation${NC}"
    
    # Vérification de Kali Linux
    check_kali_linux
    
    # Installation des outils
    install_kali_tools
    
    # Configuration
    setup_directories
    setup_main_script
    
    echo -e "\n${GREEN}Installation terminée!${NC}"
    echo -e "\nUtilisation:"
    echo -e "${YELLOW}./spiderintel.sh example.com${NC}"
}

# Gestion des signaux
trap 'echo -e "${RED}Installation interrompue${NC}"; exit 1' INT TERM

# Lancement
main "$@" 