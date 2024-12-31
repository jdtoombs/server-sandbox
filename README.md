Random notes 

### ssh commands
- `ssh-keygen` to generate key for ssh auth 
- use `sshfs` to mount remote repo and use local text editor to write scripts

### tcpdump commands
You can exclude traffic from a specific ip address source by doing the following.
- `tcpdump not src host ip.addr.here and not src host ip.addr2.here`
- `-n` to avoid resolving host names (just show numbers)
- `tcpdump -n dst host ip.addr.here` for only seeing incoming traffic.

### digital ocean default
- `eth0` and `eth1` are the only public facing network interfaces on default digital ocean setup

### use iptables to blacklist connections
- `iptables -L INPUT --line-numbers` to list the current rules (ips banned etc.)
- `iptables -A INPUT -s ip.address.here -j DROP` to add someone to the blacklist
- `iptables -F` to flush out the rules

### debugging / useful commands
- `hostname -I` list all the hostnames the server uses
- `echo $SSH_CLIENT` shows who you are connected as
- check who is currently connect with `who`

### auth logs
`/var/log/auth.log` contains authorization logs for things like login attempts. 
- `cat /var/log/auth.log | grep "Invalid user"` to see attempts to ssh into server

### cron jobs
- `crontab -e` to edit cron jobs 
- `crontab -l` to list the current cron jobs

### ports
Ports that were most targeted in ssh attempts... 
- `80` - http
- `22` - ssh
- `443/8443` https

