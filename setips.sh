#!/bin/bash
############################################################################
# Shellscript:	"setips.sh" Generates randoms ips within the user
#	user provided network range. This script automatically assigns
#	each ip to a new sub-interface starting with the sub-int number
#	provided. It does not set gateway nor dns nameservers.
#
#	Changelog:
#	- v2 Uses fping for speed (failover to ping).
#	- v3 Modifies to the ips-saved output to include the root ip ands
#		adds global variables for executables
#	- v4 Added Teamserver output
#	- v5 Added Archive of all Teamserver logs\menue item to clean them.
#		- Also added menu option to set the gateway/DNS
#	- v6 Mod'd the method for asking for MTU
#	- v7 Major overhaul of script
#		- Added "Export" menu for (Cobaltstrike, Proxychains, List)
#		- Added "Startup Scripts" menu for restoring subinterface
#		  IPs  on system restart and (auto)starting a local SOCKS
#		  proxy for use by proxychains
#		- Consolidated menu items
#	- v8 Mod'd menu; add various pivot/setup methods to setup menu
#	- v9 Added "Initial Setup" script under "Utilities"
#
# Author : spatiald
# Date : 12 May 2015
# Version : 9
############################################################################
#uncomment to debug
#set -x

# Setup some path variables
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Variables - change them if you want to
default_mtu=1500 # Normal is 1500
ips_saved="$HOME/ips-saved.txt" # Save file for restoring IPs
ips_archive="$HOME/ips-archive.txt" # IP archive listed by date/time for reference during exercises
cobaltstrikedir="$HOME/cobaltstrike"
c2profilesdir="$HOME/c2profiles"
veildir="$HOME/veil"
powersploitdir="$HOME/powersploit"

# Fix backspace
stty erase ^?

# Do not change this - sets counter to 0
counter=0
ifconfig=`which ifconfig`
fping=`which fping`
ping=`which ping`
iptables=`which iptables`

#in case you wish to kill it
trap 'exit 3' 1 2 3 15

# Find the eth port in use
function listips {
	echo; echo "[-] Ethernet ports that have assigned addresses:"
	$ifconfig |grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' |awk -F:: '{ print $1 " " $NF }' | sed "/lo/d"
}

# List the interfaces without addresses assigned
function listints {
	echo; echo "[-] Ethernet ports:"
	$ifconfig |grep "eth" | awk '{ print $1 " " }' | sed "/lo/d" | sed "/:/d"
}

# Ask which ethernet port you want to create subinterfaces for
function whatport {
while :; do
	echo; echo "[?] What ethernet port do you want to work with (choose a root port, ie eth0 or eth1)?"; read ethport
	if [[ "$ethport" =~ ^[A-Za-z]{3}+[0-9]{1}$ ]]; then
		break
	else
		echo; echo "[!] Please enter the root ethernet port (for example, enter eth0 not eth0:1)"
	fi
done
}

# List IPs, single line, comma-seperated
function listips-oneline {
	# List IPs for use in Armitage/Cobalt Strike "Teamserver"
	$ifconfig | grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g'| awk -F:: '{ print $NF }' | head -n -1 | awk '{printf "%s,",$0} END {print ""}' | sed 's/.$//'
}

# Tests IP for connectivity
function pingtest {
	if [ `which fping` ]
	then
		$fping -c 1 $unusedip || echo $unusedip/$subnet >> /tmp/ips.txt
	else
		$ping -c 1 -w 0.5 $unusedip || echo "Available IP: "$unusedip; echo $unusedip/$subnet mtu $mtu >> /tmp/ips.txt
	fi
}

# What MTU
function whatmtu {
	# MTU
	echo; echo "[?] What is your desired MTU setting (current default is $default_mtu)?"; read mtu || return
	if [ -z ${mtu:+x} ]; then
		echo "[+] Setting mtu of $default_mtu."
		mtu=$default_mtu
	else
		echo "[+] Setting your desired mtu of $mtu"
	fi
}

# Remove all subinterfaces
function removesubints {
	$ifconfig | grep $ethport |cut -d" " -f1 |tail -n +2 >> /tmp/sub.txt
	while IFS= read sub; do
	$ifconfig $sub down > /dev/null 2>&1
	done < "/tmp/sub.txt"

	if [ -s /tmp/sub.txt ];
	then
		echo; echo "[-]Removed subinterface(s):"
		cat /tmp/sub.txt
		rm /tmp/sub.txt > /dev/null 2>&1
		rm /tmp/ips.txt > /dev/null 2>&1
	else
		echo; read -p "[?] No subinterfaces exist...would you like to create some? (y/n)" -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			addsubints
		fi
	fi
}

# Add subinterfaces
function addsubints {
	{ rm /tmp/ips.txt; touch /tmp/ips.txt; } > /dev/null 2>&1
	# MTU
	whatmtu

	# SUBNET
	echo; echo "[?] What subnet class are you creating IPs for?"
	select class in "A" "B" "C"; do
		case $class in
		A)
		# Find out the range that we are setting
		echo; echo "[?] What is the IP's first octet (number)?"; read octet1
		echo "[?] What is the IP's second octet (range; ie 1-255)?"; read octet2
		echo "[?] What is the IP's third octet (range; ie 1-255)?"; read octet3
		echo "[?] What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		echo; echo "[?] What subnet (ie 8 for a 255.0.0.0)?"; read subnet

		#Ask how many subinterface ips the user would like
		echo; echo "[?] How many virtual ips (subinterfaces) would you like?"; read numberips

		until [[ $numberips = $(wc -l < /tmp/ips.txt) ]]; do
			unusedip=$octet1"."$(shuf -i $octet2 -n 1)"."$(shuf -i $octet3 -n 1)"."$(shuf -i $octet4 -n 1)
			pingtest
		sort -u /tmp/ips.txt > /tmp/ips2.txt; mv /tmp/ips2.txt /tmp/ips.txt
		done

		echo; echo "[+] Identified $numberips available IPs; setting subinterface IPs!"
		break
		;;

		B)
		# Find out the range that we are setting
		echo; echo "[?] What is the IP's first octet (number)?"; read octet1
		echo "[?] What is the IP's second octet (number)?"; read octet2
		echo "[?] What is the IP's third octet (range; ie 1-255)?"; read octet3
		echo "[?] What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		echo; echo "[?] What subnet (ie 16 for a 255.255.0.0)?"; read subnet

		#Ask how many subinterface ips the user would like
		echo; echo "[?] How many virtual ips (subinterfaces) would you like?"; read numberips

		until [[ $numberips = $(wc -l < /tmp/ips.txt) ]]; do
			unusedip=$octet1"."$octet2"."$(shuf -i $octet3 -n 1)"."$(shuf -i $octet4 -n 1)
			pingtest
		sort -u /tmp/ips.txt > /tmp/ips2.txt; mv /tmp/ips2.txt /tmp/ips.txt
		done
		echo; echo "[+] Identified $numberips available IPs; setting subinterface IPs!"
		break
		;;

		C)
		# Find out the range that we are setting
		echo; echo "[?] What is the IP's first octet (number)?"; read octet1
		echo "[?] What is the IP's second octet (number)?"; read octet2
		echo "[?] What is the IP's third octet (number)?"; read octet3
		echo "[?] What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		echo; echo "[?] What subnet (ie 24 for a 255.255.255.0)?"; read subnet

		#Ask how many subinterface ips the user would like
		echo; echo "[?] How many virtual ips (subinterfaces) would you like?"; read numberips

		until [[ $numberips = $(wc -l < /tmp/ips.txt) ]]; do
			unusedip=$octet1"."$octet2"."$octet3"."$(shuf -i $octet4 -n 1)
			pingtest
		sort -u /tmp/ips.txt > /tmp/ips2.txt; mv /tmp/ips2.txt /tmp/ips.txt
		done
		echo; echo "[+] Identified $numberips available IPs; setting subinterface IPs!"
		break
		;;
		esac
	done

	echo; echo "[?] What subinterface number would you like to start assigning ips to?"; read num; num=$((num-1))
	while IFS= read ip; do
		num=$((num+1))
		$ifconfig $ethport:$num $ip mtu $mtu
	done < "/tmp/ips.txt"
	echo "[+] Done."; echo
	cp -f /tmp/ips.txt $ips_saved

	# Save ips set for future restore by this script
	$ifconfig |grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print $1 " " $NF }' | sed -e "s/$/\/$subnet/" | sed "/lo/d" > $ips_saved

	# Append ips to running log
	echo $(date) >> $ips_archive
	listips-oneline >> $ips_archive

	echo "[+] Your IP settings were saved to three files:";
	echo "   - $ips_saved -> restore them with this program";
	echo "   - $ips_archive -> running log of all IPs used during an exercise/event";
	rm -rf /tmp/ips*.txt
}

# Restore subinterface IPs from file
function restoresubintsfile {
	# Identify the subinterfaces save file
	echo; echo "[?] What is the full path to the setips save file (default is $ips_saved)?"; read savefile || return
	if [ -z ${savefile:+x} ]; then
		echo "[+] Restoring from $ips_saved.";
		savefile=$ips_saved
	else
		echo "[+] Restoring from $savefile";
	fi
	while IFS= read intip; do
		$ifconfig $intip
	done < "$savefile"
}

# Set the IP
function initialsetup {
	listints
	whatport
	whatmtu
	echo; echo "[?] What IP do you want to set?"; read ip
	echo; echo "[?] What subnet (ie 8 for a 255.0.0.0)?"; read subnet
	$ifconfig $ethport $ip/$subnet mtu $mtu
	echo; echo "[+] Your $ethport IP is setup:"
	echo; ifconfig $ethport
	setgateway
	setdns
	sed -i '/iface eth0 inet dhcp/d' /etc/network/interfaces
	echo "address $ip" >> /etc/network/interfaces
	if ! which ipcalc > /dev/null; then
		echo; echo "[!] The program ipcalc is not installed...what is the actual netmask (ie 255.255.0.0)?"; read netmask
		echo "netmask $netmask" >> /etc/network/interfaces
	else
		netmask=`ipcalc -c 13 | grep Address | awk '{ print $2 }'`
		echo "netmask $netmask" >> /etc/network/interfaces
        fi
	gatewayip=`route -n|grep eth0| head -n 1|cut -d"." -f4-7|cut -d" " -f10`
	echo "gateway $gatewayip" >> /etc/network/interfaces
	dns=`cat /etc/resolv.conf | grep nameserver | awk '{ print $2}' | awk '{printf "%s ",$0} END {print ""}'`
	echo "dns-nameserers $dns" >> /etc/network/interfaces
	# Startup Cobaltstrike requirements
	#update-java-alternatives --jre -s java-1.7.0-openjdk-i386 # For x86
	echo; echo "[+] Setting up initial services for Cobalt Strike support."
	update-java-alternatives --jre -s java-1.7.0-openjdk-amd64 # For x64
	service postgresql start
	service metasploit start
	service metasploit stop
	echo; echo "[+] Setup complete."
	echo; echo "[+] Starting Cobalt Strike client."
	cd cobaltstrike; ./cobaltstrike
}

# Set default gateway
function setgateway {
	currentgw=`route -n|grep eth0| head -n 1|cut -d"." -f4-7|cut -d" " -f10`
	gatewayip=$currentgw
	if [ -z ${currentgw:+x} ]; then
		echo; echo "[!] You do not have a default gateway set.";
	else
		echo; echo "[-] Your current gateway is:  $gatewayip";
	fi
	echo; read -p "[?] Do you want to change your gateway? (y/n)" -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; echo "[?] What is the IP of the gateway?"; read gatewayip || return
		# Remove current gw
		route del default gw $currentgw
		# Add new gw
		route add default gw $gatewayip
		newgw=`route -n|grep eth0| head -n 1|cut -d"." -f4-7|cut -d" " -f10`
		if [ -z ${newgw:+x} ]; then
			echo; echo "[!] Something went wrong...check your desired gateway.";
		else
			echo; echo "[+] Your gateway was updated to:  $newgw"; echo
			# Print current routing table
			route -n; echo
			echo; echo "[+] Your gateway was set.";
		fi
	else
		echo; echo "[!] Gateway not changed.";
	fi
}

# Set DNS
function setdns {
	echo; echo "[-] Your current DNS settings:";
	cat /etc/resolv.conf
	echo; read -p "[?] Do you want to change your DNS servers? (y/n)" -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; echo "[?] What are the DNS server IPs (space separated)?"; read dnsips || return
		rm /etc/resolv.conf
		IFS=' '; set -f
		eval "array=(\$dnsips)"
		for x in "${array[@]}"; do echo "nameserver $x" >> /etc/resolv.conf; echo; done
		echo; echo "[+] Your DNS settings were updated as follows:"
		cat /etc/resolv.conf; echo;
	else
		echo; echo "[!] DNS not changed.";
	fi
}

# Auto set subinterface IPs on system start/reboot
function autosetipsonstart {
	echo
	removesetipsonstart
	cat > /root/setips-atstart.sh << 'EOF'
#!/bin/bash
#Auto-set IPs on startup - restores ips
#	saved by the setips script
#
ifconfig=`which ifconfig`
while IFS= read intip; do
	$ifconfig $intip
done < /root/ips-saved.txt
EOF
	chmod +x /root/setips-atstart.sh
	sed -i '$e echo "#setips - Auto-set IPs on startup"' /etc/rc.local
	sed -i '$e echo "/root/setips-atboot.sh&"' /etc/rc.local
	echo; echo "[+] Added script to setup subinterface IPs on system startup."
	echo "[!] The setips save file must be located at /root/ips-saved.txt"
}

# Remove setips script from /etc/rc.local
function removesetipsonstart {
	sed -i '/setips/d' /etc/rc.local
	rm -f /root/setips-atstart.sh
}

# Add ssh socks proxy to /etc/rc.local
function autostartsocksproxy {
	sed -i '/screen/d' /etc/rc.local
	sed -i '$e echo "#SOCKS - Auto-start SOCKS proxy on startup using screen"' /etc/rc.local
	sed -i '$e cat /tmp/ssh.tmp' /etc/rc.local
	rm -rf /tmp/ssh.tmp
	echo; echo "[+] Added SOCKS proxy auto-start script to /etc/rc.local";
}

# Setup SOCKS proxy
function setupSOCKS {
	# Check for dependencies
	if ! which socat > /dev/null; then
		echo; echo "[!] The program socat is not installed...downloading now."
		apt-get -y install socat
	fi
	echo "[-] Killing previous setips SSH SOCKS proxies."
	screen -X -S ssh kill > /dev/null
	echo; echo "[+] Starting up SOCKS proxy..."
	echo "[-] The startup process will take ~5 secs."
	echo "    You will be returned to the setips menu when setup is complete."
	echo; echo "[?] What port do you want to use for your proxy?"; read proxyport
	echo
	while :; do
		if netstat -antp |grep 0.0.0.0:$proxyport
		then
			echo; echo "[!] Something is already listening on that port, please try a different port."
			echo; echo "[?] What port do you want to use for your proxy?"; read proxyport
		else
			break
		fi
	done
	echo "[?] What is root's password?"; read password > /dev/null
	echo; echo "[-] Checking if the SSH server is running..."
	if ps aux | grep -v grep | grep /usr/sbin/sshd > /dev/null
	then
		echo "[+] SSH server *is* running; let's rock."
	else
		echo "[!] SSH server *is not* running; starting it up."
		service ssh start
	fi
	echo "[+] Setting up the SSH SOCKS proxy...please wait..."
	(sleep 2; echo $password; sleep 2; echo ""; sleep 1) | socat - EXEC:"screen -S ssh ssh -o StrictHostKeyChecking=no -gD$proxyport -l root localhost",pty,setsid,ctty > /dev/null
	echo "(sleep 2; echo $password; sleep 2; echo ""; sleep 1) | socat - EXEC:'screen -S ssh ssh -o StrictHostKeyChecking=no -gD"$proxyport" -l root localhost',pty,setsid,ctty" > /tmp/ssh.tmp
	echo; echo "[+] SUCCESS...SOCKS proxy started on Port $proxyport."
	echo; echo "To use, copy the following to the end of your local /etc/proxychains.conf file (replace any other proxies in the file):"
	$ifconfig | grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print "socks4 " $NF }' | awk '{ print $0 "'" $proxyport"'"}' | head -n -1

	# Ask if you want to start the SOCKS proxy automatically on boot (careful, this will put your root password in the /etc/rc.local file)
        echo; read -p "[?] Would you like the SOCKS proxy to start on reboot? (y/n)" -n 1 -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
		autostartsocksproxy
	else
		rm -rf /tmp/ssh.tmp;
	fi
}

# Stop SOCKS proxy
function stopSOCKS {
	screen -X -S ssh kill
	sed -i '/screen/d' /etc/rc.local
}

# Flush all current IPTable rules
function flushiptables {
	# Flushing all rules
	$iptables -F
	$iptables -X
	$iptables -F -t nat
	$iptables -X -t nat

	# Setting default filter policy
	$iptables -P INPUT ACCEPT
	$iptables -P OUTPUT ACCEPT
	$iptables -P FORWARD ACCEPT
}

# Add iptables script to /etc/rc.local
function autostartiptables {
        iptables-save > /root/iptables-pivot.rules
        sed -i '/iptable/d' /etc/rc.local
        sed -i '$e echo "#IPTables - Restore iptable rules on reboot"' /etc/rc.local
        sed -i '$e echo "iptables-restore < /root/iptables-pivot.rules"' /etc/rc.local
}

# Remove iptables reinstall script from /etc/rc.local
function removestartiptables {
	sed -i '/iptable/d' /etc/rc.local
}

# Setup IPTables SRC NAT Redirector
function setupiptablespivot {
	echo 1 > /proc/sys/net/ipv4/ip_forward
        # Ask if you want to start the SOCKS proxy automatically on boot (careful, this will put your root password in the /etc/rc.local file)
        echo; read -p "[?] Would you like to flush the current iptable rules? (y/n)" -n 1 -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
		flushiptables
        fi
	echo; echo "[?] Is the traffic TCP or UDP?"; read protocol
	echo; echo "[?] What port should the pivot listen for?"; read incomingport
	echo; echo "[?] What is the attacker *IP* the pivot redirects incoming traffic to?"; read attackerip
	echo; echo "[?] What is the attacker *PORT* the pivot redirects incoming traffic to?"; read attackerport
	$iptables -t nat -A PREROUTING -p $protocol -j DNAT --dport $incomingport --to $attackerip:$attackerport
	$iptables -t nat -A POSTROUTING -j MASQUERADE
	$iptables -t filter -I FORWARD 1 -j ACCEPT
	iptables-save > /root/iptables-pivot.rules
	# Ask if you want to reapply the iptables rules  automatically on boot (/etc/rc.local file)
	echo; read -p "[?] Would you like to apply these rules automatically on reboot? (y/n)" -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		autostartiptables
	fi
}

# Setup Socat Pivot
function setupsocatpivot {
	# Check for dependencies
	if ! which socat > /dev/null; then
		echo; echo "[!] The program socat is not installed...downloading now."
		apt-get -y install socat
	fi
	echo; echo "[?] What port do you want to pivot (i.e. listen for)?"; read socatport
	echo; echo "[?] What is the attacker *IP* the pivot redirects incoming traffic to?"; read attackerip
	echo; echo "[?] What is the attacker *PORT* the pivot redirects incoming traffic to?"; read attackerport
	socat TCP-LISTEN:$socatport,reuseaddr,fork,su=nobody TCP:$attackerip:$attackerport&
	echo; echo "[+] Socat pivot setup."
	netstat -antp | grep $socatport
}

# Setup Cobaltstrike Teamserver
function setupteamserver {
	# Check for dependencies
	if ! which unzip > /dev/null; then
		echo; echo "[!] The program unzip is not installed...downloading now."
		apt-get -y install unzip
	fi
	if [ ! -d "$cobaltstrikedir" ]; then
		echo; echo "[!] Cobaltstrike folder does not exist...download/unzip to /root/cobaltstrike and try again."
		break
	else
		cd /root
		if [ ! -d "$c2profilesdir" ]; then
			echo; read -p "[?] Cobaltstrike c2profiles folder does not exist; download now? (y/n)" -n 1 -r
			if [[ $REPLY =~ ^[Yy]$ ]]; then
				echo; wget https://github.com/rsmudge/Malleable-C2-Profiles/archive/master.zip -O c2.zip; unzip c2.zip; mv Malleable-C2-Profiles-master c2profiles; rm -rf c2.zip
			fi
		else
			echo; echo "[+] Cobalstrike c2profiles folder exists, moving on."
		fi
		if [ ! -d "$veildir" ]; then
			echo; read -p "[?] Veil folder does not exist; download now? (y/n)" -n 1 -r
			if [[ $REPLY =~ ^[Yy]$ ]]; then
				echo; wget https://github.com/Veil-Framework/Veil/archive/master.zip -O veil.zip; unzip veil.zip; mv Veil-master veil; rm -rf veil.zip; /root/veil/Install.sh -c
			fi
		else
			echo; echo "[+] Veil folder exists, moving on."
		fi
		if [ ! -d "$powersploitdir" ]; then
			echo; read -p "[?] PowerSploit folder does not exist; download now? (y/n)" -n 1 -r
			if [[ $REPLY =~ ^[Yy]$ ]]; then
				echo; wget https://github.com/mattifestation/PowerSploit/archive/master.zip -O powersploit.zip; unzip powersploit.zip; mv PowerSploit-master powersploit; rm -rf powersploit.zip
			fi
		else
			echo; echo "[+] PowerSploit folder exists, moving on."
		fi
		# Startup teamserver
		coreip=`$ifconfig $whatport |grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print $2 }' | head -n 1`
		echo; echo "[!] What teamserver password would you like to use?"; read teampass
		# Populate tables in background
		msfrpcdpid=`ps aux|grep msfrpcd|head -n 1|awk '{ print $2 }'`
		kill -9 $msfrpcdpid
		service postgresql start
		service metasploit start
		service metasploit stop
		# Ask if you will use a c2profile with the teamserver
		echo; read -p "[?] Would you like to use a c2profile (if you don't know what that is, type 'n')? (y/n)" -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			cd /root/c2profiles; ls -R *; cd
			echo; echo "[!] What c2profile would you like to use? (enter just the name)"; read c2profile
			c2profile=`find /root/c2profiles/ -name $c2profile`
			cd $cobaltstrikedir; ./teamserver $coreip $teampass $c2profile
			echo "[-] If the teamserver fails to start, correct the issues and then type this command from the cobaltstrike folder:"
			echo "    ./teamserver $coreip $teampass $c2profile"
		fi
	fi
}

# Loop function to redisplay menu
function whattodo {
	echo; echo "[?] What would you like to do next?"
	echo "1)Setup  2)Subinterfaces  3)Utilities  4)Export  5)Quit"
}

# MAIN MENU
echo; echo "[!] Remember to remove your $ips_archive file if you are starting a new exercise."; echo
select ar in "Setup" "Subinterfaces" "Utilities" "Export" "Quit"; do
	case $ar in
		Setup )
		echo
                select au in "SSH-SOCKS-Redirector" "IPTables-SRC-NAT-Pivot" "Socat-Pivot" "Teamserver" "Main-Menu"; do
                        case $au in
				SSH-SOCKS-Redirector )
				listints
				whatport
				echo; read -p "[?] Do you want to use your current subinterface IPs? (y/n)" -n 1 -r
				if [[ $REPLY =~ ^[Nn]$ ]]; then
					removesubints
					addsubints
				fi
				autosetipsonstart
				setupSOCKS
				autostartsocksproxy
				break
				;;

				IPTables-SRC-NAT-Pivot )
				setupiptablespivot
				break
				;;

				Socat-Pivot )
				setupsocatpivot
				break
				;;

				Teamserver )
				listints
				whatport
				removesubints
				setupteamserver
				break
				;;

				Main-Menu )
				break
				;;
			esac
		done
		whattodo
		;;

		Subinterfaces )
		echo
		select su in "Add-Subinterfaces" "Remove-All-Subinterfaces" "Restore-Subinterfaces" "Main-Menu"; do
			case $su in
				Add-Subinterfaces )
				listints
				whatport
				addsubints
				break
				;;

				Remove-All-Subinterfaces )
				listips
				whatport
				removesubints
				break
				;;

				Restore-Subinterfaces )
				restoresubintsfile
				echo "[+] Here are your current settings:";
				listips
				echo "[+] Your settings where restored.";
				break
				;;

				Main-Menu )
				break
				;;
			esac
		done
		whattodo
		;;

		Utilities )
		echo
		select ut in "Initial-Setup" "Set-Gateway" "Set-DNS" "Flush-IPTables" "Auto-set-IPTables-on-startup" "Remove-auto-set-IPTables-on-startup" "Auto-set-IPs-on-startup" "Remove-auto-set-IPs-on-startup" "Startup-SOCKS-Proxy" "Stop-SOCKS-Proxy" "Main-Menu"; do
			case $ut in
				Initial-Setup )
				initialsetup
				break
				;;

				Set-Gateway )
				listips
				setgateway
				break
				;;

				Set-DNS )
				setdns
				break
				;;

				Flush-IPTables )
				flushiptables
				echo; echo "[+] IPTables successfully flushed."
				break
				;;

				Auto-set-IPTables-on-startup )
				autostartiptables
  				echo; echo "[+] Added iptables restore script to /etc/rc.local."
				break
				;;

				Remove-auto-set-IPTables-on-startup )
				removestartiptables
  				echo; echo "[+] Removed iptables auto-set script."
				break
				;;

				Auto-set-IPs-on-startup )
				autosetipsonstart
  				echo; echo "[+] Added setips auto-set script to /etc/rc.local."
				break
				;;

				Remove-auto-set-IPs-on-startup )
				removesetipsonstart
  				echo; echo "[+] Removed setips auto-set script."
				break
				;;

				Startup-SOCKS-Proxy )
				setupSOCKS
  				echo; echo "[+] SSH SOCKS Proxy started."
				break
				;;

				Stop-SOCKS-Proxy )
				stopSOCKS
  				echo; echo "[+] SSH SOCKS Proxy stopped."
				break
				;;

				Main-Menu )
				break
				;;
			esac
		done
		whattodo
		;;

		Export )
		echo; echo "[?] What format do you want to export?"; echo
		select ex in "Cobaltstrike-Teamserver" "Proxychains" "List-IPs" "Main-Menu"; do
 			case $ex in
 				Cobaltstrike-Teamserver )
 				listips-oneline
				break
 				;;

				Proxychains )
				echo; echo "[?] What port do you want to use for your proxy?"; read proxyport
				echo; echo "Copy the following to the end of /etc/proxychains.conf"
				$ifconfig | grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print "socks4 " $NF }' | awk '{ print $0 "'" $proxyport"'"}' | head -n -1
				break
				;;

				List-IPs )
				listips
				break
				;;

				Main-Menu )
				break
				;;
			esac
		done
		whattodo
		;;

		Quit )
		echo; echo "[+] Exiting, nothing to do."; echo
		exit 1
		;;
	esac
done
