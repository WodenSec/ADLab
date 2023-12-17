#!/bin/bash

if [ $(id -u) -ne 0 ]; then
	echo "Please run as root"
	exit
fi

if [ ! -f /opt/pimpmykali/.firstrun ]; then
    
    # Get pimpmykali
    cd /opt
    git clone https://github.com/Dewalt-arch/pimpmykali
    cd pimpmykali

    # Execute pimpmykali several times with different functions
    echo "k" | ./pimpmykali.sh
    echo "t" | ./pimpmykali.sh
    ./pimpmykali.sh --mirrors
    ./pimpmykali.sh --upgrade
    ./pimpmykali.sh --root

    # Create file
    touch /opt/pimpmykali/.firstrun
    echo "Reboot the machine and log in as root, then execute this script again."
    
else
    # XFCE Power manager: prevent session locking, etc...
    wget "https://raw.githubusercontent.com/Dewalt-arch/pimpmyi3-config/main/xfce4/xfce4-power-manager.xml" -O /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml
    
    # Remove useless directories in /root
    rmdir /root/Music ; rmdir /root/Public ; rmdir /root/Templates ; rmdir /root/Videos
fi
