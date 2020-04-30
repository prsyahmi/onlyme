# onlyme
Allow iptables rules by dynamic ip address defined by a text files.
This allow you to open port only for your IP address.

# Compile
gcc -o onlyme onlyme.c -lmnl -lnetfilter_queue

# Usage
1) set iptables rules action to QUEUE
2) run this software with `./onlyme 0 /home/myhome/authorized_ip.txt`
3) Add ip address to authorized_ip.txt

Changes to authorized_ip.txt will reflect immediately.

# Limitation
Only one ip address and only ipv4 support
