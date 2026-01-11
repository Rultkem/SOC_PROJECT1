#!/bin/bash


# MITRE ATT&CK Coverage:	
# T1110     - Brute Force (SSH password guessing)
# T1046     - Network Service Discovery (port scanning / probing)
# T1133     - External Remote Services (SSH access attempts)



#CONFIGURATION

AUTH_LOG="/var/log/auth.log"
NET_LOG="/var/log/kern.log"
ALERT_FILE="./soc_alerts.txt"

SSH_THRESHOLD=5
NET_THRESHOLD=20

> "$ALERT_FILE"

echo "=============================================="
echo "        SOC MINI DASHBOARD - BASH"
echo "=============================================="
echo "%-16s %-10s %-10s %-10s\n" "IP_ADDRESS" "SSH_FAILS" "NET_HITS" "RISK"
echo "----------------------------------------------"


#COLLECT UNIQUE IPs
IPS=$(grep -E "Failed password|IN=" "$AUTH_LOG" "$NET_LOG" 2>/dev/null \
| awk '{for(i=1;i<=NF;i++) if ($i=="from") print $(i+1)}' \
| sort -u)


#Analyze each ip
for ip in $IPS; do
	ssh_fails=$(grep "Failed password" "$AUTH_LOG" | grep "$ip" | wc -l)
	net_hits=$(grep "IN=" "$NET_LOG" | grep "$ip" | wc -l)

	risk="LOW"

	if [[ "$ssh_fails" -ge "SSH_THRESHOLD" && "$net_hits" -ge "$NET_THRESHOLD" ]]; then
		risk="HIGH"
	elif [[ "$ssh_fails" -ge "SSH_THRESHOLD" || "$net_hits" -ge "$NET_THRESHOLD" ]]; then
		risk="MEDIUM"
	fi

	printf "%-16s %-10s %-10s %-10s\n" "$ip" "$ssh_fails" "$net_hits" "$risk"

	if [[ "$risk" != "LOW" ]]; then
		echo "$(date) | IP=$ip | SSH_FAILS=$ssh_fails | NET_HITS=$net_hits | RISK=$risk"  >> "$ALERT_FILE"

	fi
done


#Dynamically assign MITRE technique based on behaviour
mitre=""
mitre="T1133"
if [[ "$ssh_fails" -ge "$SSH_THRESHOLD" ]]; then
        mitre="$mitre,T1110"
fi

if [[ "$net_hits" -ge "$NET_THRESHOLD" ]]; then
        mitre="$mitre, T1046"

MITRE=${mitre#,} 
echo "$MITRE" >> "$ALERT_FILE"


echo "----------------------------------------------"
echo "Analysis complete."
echo "Alerts saved to: $ALERT_FILE"
