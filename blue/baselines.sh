#!/bin/bash
mkdir -R $HOME/.config/tools
cd $HOME/.config/tools
cat /etc/passwd > usr.txt
ps aux > ps.txt
ss -tulpn > ss.txt
systemctl list-unit-files --type=service > service.txt
"Done taking baselines -- find them in $HOME/.config/tools"
