#!/bin/bash

# Check if the script is run as root
[ $(id -u) -eq 0 ] || { echo "Please run as root"; exit 1; }

# Variables
FIRST_RUN_FILE="/opt/pimpmykali/.firstrun"
PIMPMYKALI_DIR="/opt/pimpmykali"
PIMPMYKALI_REPO="https://github.com/Dewalt-arch/pimpmykali"
XFCE_CONFIG_URL="https://raw.githubusercontent.com/Dewalt-arch/pimpmyi3-config/main/xfce4/xfce4-power-manager.xml"
XFCE_CONFIG_DEST="/root/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml"

# First run actions
if [ ! -f "$FIRST_RUN_FILE" ]; then
    git clone "$PIMPMYKALI_REPO" "$PIMPMYKALI_DIR" && cd "$PIMPMYKALI_DIR"
    for opt in k t; do echo "$opt" | ./pimpmykali.sh; done
    ./pimpmykali.sh --mirrors --upgrade --root
    touch "$FIRST_RUN_FILE"
    echo "Reboot the machine and log in as root, then execute this script again."
else
    wget -q "$XFCE_CONFIG_URL" -O "$XFCE_CONFIG_DEST"
    for DIR in /root/Music /root/Public /root/Templates /root/Videos; do rmdir "$DIR"; done
fi
