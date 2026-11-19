#!/bin/bash
cd $HOME/.config/tools
echo "\n----------------CHECKING USERS----------------"
diff /etc/passwd usr.txt
echo "\n----------------CHECKING PROCESSES----------------"
ps aux > _ps.txt;
diff _ps.txt ps.txt
echo "\n----------------CHECKING CONNECTIONS----------------"
ss -tulpn > _ss.txt;
diff _ss.txt ss.txt
echo "\n----------------CHECKING SERVICES----------------"
systemctl list-unit-files --type=service >_service.txt
diff _service.txt service.txt
