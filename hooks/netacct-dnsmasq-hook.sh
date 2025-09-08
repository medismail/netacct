#!/bin/sh
# /etc/dnsmasq.d/netacct-hook.sh

SOCK="/var/run/netacct.sock"

case "$1" in
  add|old)
    echo "{\"action\":\"add\",\"ip\":\"$3\"}" | socat - UNIX-CONNECT:$SOCK
    ;;
  del)
    echo "{\"action\":\"del\",\"ip\":\"$3\"}" | socat - UNIX-CONNECT:$SOCK
    ;;
esac
