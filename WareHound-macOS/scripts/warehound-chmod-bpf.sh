#!/bin/sh
#
# Grant the access_bpf group read/write on the BPF devices so an unsigned
# WareHound (pcap-local) build can capture packets without running as root.
#
# macOS resets /dev/bpf* to root:wheel 0600 on every boot, so this runs once
# at boot (launchd RunAtLoad) and fixes the group + mode. You must be a member
# of the access_bpf group (you already are).
#
# Installed as a launchd daemon — see org.warehound.ChmodBPF.plist.

syslog -s -l notice "WareHound ChmodBPF: applying access_bpf permissions to /dev/bpf*"

if [ -e /dev/bpf0 ] ; then
    /usr/bin/chgrp access_bpf /dev/bpf*
    /bin/chmod g+rw /dev/bpf*
fi
