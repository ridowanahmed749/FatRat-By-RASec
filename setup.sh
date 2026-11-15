#!/bin/bash
set -e

echo "[*] installing build dependencies"

if command -v apt &>/dev/null; then
    sudo apt update
    sudo apt install -y \
        mingw-w64 \
        upx-ucl \
        python3 \
        python3-pip \
        default-jdk \
        android-sdk-build-tools \
        apksigner \
        zipalign
elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm \
        mingw-w64-gcc \
        upx \
        python \
        jdk-openjdk \
        android-tools
elif command -v dnf &>/dev/null; then
    sudo dnf install -y \
        mingw64-gcc \
        mingw32-gcc \
        upx \
        python3 \
        java-17-openjdk \
        android-tools
fi

if ! command -v msfvenom &>/dev/null; then
    echo "[*] installing metasploit-framework"
    curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o /tmp/msfinstall
    chmod +x /tmp/msfinstall
    sudo /tmp/msfinstall
fi

echo "[+] done. run: python3 ratgen.py"