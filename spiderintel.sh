#!/bin/bash

# SpiderIntel v2.0.0 - Script de lancement pour Kali Linux
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

# Vérification des outils Kali
check_kali_tools() {
    echo -e "${BLUE}Vérification des outils Kali...${NC}"
    
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
    
    local missing_tools=()
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}Outils manquants: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}Installez-les avec: sudo apt install ${missing_tools[*]}${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Tous les outils requis sont installés${NC}"
}

# Installation
install() {
    echo -e "${BLUE}Installation de SpiderIntel...${NC}"
    chmod +x install.sh
    ./install.sh
}

# Test
test() {
    echo -e "${BLUE}Test de SpiderIntel...${NC}"
    python3 spiderintel.py --test
}

# Mise à jour
update() {
    echo -e "${BLUE}Mise à jour de SpiderIntel...${NC}"
    git pull
    pip install --upgrade -r requirements.txt
    chmod +x install.sh
    ./install.sh
}

# Vérification des dépendances
check_deps() {
    check_kali_linux
    check_kali_tools
}

# Statut
status() {
    echo -e "${BLUE}Statut de SpiderIntel:${NC}"
    echo -e "Version: ${GREEN}2.0.0${NC}"
    echo -e "Système: ${GREEN}Kali Linux${NC}"
    check_kali_tools
}

# Nettoyage
clean() {
    echo -e "${BLUE}Nettoyage...${NC}"
    rm -rf logs/* reports/* temp/*
    echo -e "${GREEN}Nettoyage terminé${NC}"
}

# Fonction principale
main() {
    # Vérification de Kali Linux
    check_kali_linux
    
    # Traitement des commandes
    case "$1" in
        install)
            install
            ;;
        test)
            test
            ;;
        update)
            update
            ;;
        check-deps)
            check_deps
            ;;
        status)
            status
            ;;
        clean)
            clean
            ;;
        *)
            # Si aucun argument n'est fourni, exécuter l'analyse
            if [ -z "$1" ]; then
                echo -e "${RED}ERREUR: Domaine requis${NC}"
                echo -e "Usage: $0 <domaine>"
                exit 1
            fi
            
            # Vérification des outils
            check_kali_tools
            
            # Exécution de l'analyse
            echo -e "${BLUE}Lancement de l'analyse sur $1...${NC}"
            python3 spiderintel.py "$@"
            ;;
    esac
}

# Gestion des signaux
trap 'echo -e "${RED}Opération interrompue${NC}"; exit 1' INT TERM

# Lancement
main "$@" 