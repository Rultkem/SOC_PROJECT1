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

#Local threat intel on this list (one ip per line)
THREAT_FEED="/known_bad_ips.txt"

> "$ALERT_FILE"

echo "=============================================="
echo "        SOC MINI DASHBOARD - BASH"
echo "=============================================="
#CSV header
echo "IP_ADDRESS,COUNTRY,COUNTRY_CODE,SSH_FAILS,NET_HITS,REPUTATION_SCORE,RISK,T1133,T1110,T1046" > "$ALERT_FILE" 
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

	#GEOip enrichment
	GEO_INFO=$(geoiplookup "$ip" 2>/dev/null)
	COUNTRY=$(echo "$GEO_INFO" | awk -F ': ' '{print $2}')
	COUNTRY_CODE=$(echo "GEO_INFO" | awk -F ': ' '{print $1}')

	#Handle missing GEOip
	COUNTRY=${COUNTRY:-"UNKNOWN"}
	COUNTRY_CODE=${COUNTRY_CODE:-"UN"}



	#Reputation score based on: behaviour, country, known threats 
	reputation_score=0
	((reputation_score+=ssh_fails*3 ))
	((reputation_score+=net_hits*1 ))

	case "$COUNTRY_CODE" in
		RU|CN|IR|KP)
			((reputation_score+=20))
			;;
	esac

	if [[ -f "$THREAD_FEED" ]] && grep -q "$ip" "$THREAT_FEED"; then
		((reputation_score+=40))
	fi

	#Highest reputation score 100
	((reputation_score=100)) && reputation_score=100
	

	#Evaluate risk based on reputation score
	risk="LOW"
	if [[ "$reputation_score" -ge 60 ]]; then
		risk="HIGH"
	elif [[ "$reputation_score" -ge 30 ]]; then
		risk="MEDIUM"
	fi




	#MITRE evalutation
	t1133="FALSE"
	t1110="FALSE"
	t1046="FALSE"


	#Dynamically assign MITRE technique based on behaviour
	if [[ "$ssh_fails" -ge "$SSH_THRESHOLD" ]]; then
        	t1133="TRUE"
		t1110="TRUE"
	fi

	if [[ "$net_hits" -ge "$NET_THRESHOLD" ]]; then
        	t1133="TRUE"
		t1046="TRUE"
	fi



	#if risk is not low append the result to CSV file
	if [[ "$risk" != "LOW" ]]; then
		echo "$ip,$COUNTRY,$COUNTRY_CODE,$ssh_fails,$net_hits,$reputation_score,$risk,$t1133,$t1110,$t1046"  >> "$ALERT_FILE"

	fi
done



echo "----------------------------------------------"
echo "Analysis complete."
echo "Alerts saved to: $ALERT_FILE"
