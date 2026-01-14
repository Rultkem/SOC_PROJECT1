#!/bin/bash


# MITRE ATT&CK Coverage:	
# T1110     - Brute Force (SSH password guessing)
# T1046     - Network Service Discovery (port scanning / probing)
# T1133     - External Remote Services (SSH access attempts)



#CONFIGURATION

AUTH_LOG="/var/log/auth.log"
NET_LOG="/var/log/kern.log"
ALERT_FILE="./soc_alerts.csv"

SSH_THRESHOLD=5
NET_THRESHOLD=20


> "$ALERT_FILE"

echo "=============================================="
echo "        SOC MINI DASHBOARD - BASH"
echo "=============================================="
#CSV header
echo "IP_ADDRESS,SSH_FAILS,NET_HITS,RISK,MITRE" > "$ALERT_FILE" 
echo "----------------------------------------------"


#Get the current time
current_time=$(date "+%Y-%m-%d %H:%M:%S")
one_hour_ago=$(date -d "1 hour ago" "+%Y-%m-%d %H:%M:%S")


#COLLECT UNIQUE IPs from the last hour, format of date "Mar 14 03:14:15"
IPS=$(grep -E "Failed password|IN=" "$AUTH_LOG" "$NET_LOG" 2>/dev/null \
| awk -v one_hour_ago="$one_hour_ago" -v current_time="$current_time" '{
	log_timestamp = substr($0, 1, 15)
	log_date = substr($0, 1, 6)
	log_time = substr($0, 8, 8)

	formatted_timestamp = sprintf("%s %s, log_date, log_time")

	if (formatted_timestamp >= one_hour_ago && formatted_timestamp <= current_time) {
		for(i=1;i<=NF;i++) if ($i=="from") print$(i+1)
	}
}' | sort -u)


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

	#Dynamically assign MITRE technique based on behaviour
	mitre=""
	mitre="T1133"
	if [[ "$ssh_fails" -ge "$SSH_THRESHOLD" ]]; then
        	mitre="$mitre,T1110"
	fi

	if [[ "$net_hits" -ge "$NET_THRESHOLD" ]]; then
        	mitre="$mitre, T1046"
	fi

	MITRE=${mitre#,}


	#if risk is not low append the result to CSV file
	if [[ "$risk" != "LOW" ]]; then
		echo "$ip,$ssh_fails,$net_hits,$risk,$MITRE"  >> "$ALERT_FILE"

	fi
done



echo "----------------------------------------------"
echo "Analysis complete."
echo "Alerts saved to: $ALERT_FILE"
