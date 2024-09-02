#!/bin/bash

# Check if Snort is installed
if ! command -v snort &> /dev/null; then
    echo "Snort is not installed. Please install it before running this script."
    exit 1
fi

# Find the Snort configuration file
snort_conf=$(find / -name "snort.conf" 2>/dev/null)
if [ -z "$snort_conf" ]; then
    read -p "Snort configuration file not found automatically. Please enter the full path to the configuration file: " snort_conf
    if [ ! -f "$snort_conf" ]; then
        echo "The specified configuration file does not exist. Exiting."
        exit 1
    fi
fi

# Find the rules directory
rules_dir=$(grep "var RULE_PATH" "$snort_conf" | awk '{print $3}' | sed 's/"//g')

if [ -z "$rules_dir" ]; then
    echo "Rules directory not found in the configuration file."
    exit 1
fi

# Create the customrules.rules file in the rules directory
custom_rules_file="$rules_dir/customrules.rules"
touch "$custom_rules_file"

# Ask if you want to bypass a specific IP
read -p "Do you want to bypass a specific IP? (y/n): " bypass_ip
if [ "$bypass_ip" == "y" ]; then
    read -p "Enter the IP to bypass: " user_ip
    echo "pass ip $user_ip any -> any any (sid:1004200; rev:1;)" >> "$custom_rules_file"
    echo "pass ip any any -> $user_ip any (sid:1003301; rev:1;)" >> "$custom_rules_file"
fi

cat <<EOT >> "$custom_rules_file"
alert tcp $HOME_NET 80 <> $HOME_NET 80 (msg:"LAND ATTACK DETECTED"; sid:10000009; rev:3;)
alert tcp any any -> $HOME_NET 80 (detection_filter:track by_dst, count 20, seconds 60; msg:"Possible TCP SYN Flood attack detected"; sid:10000009; rev:1;)
alert icmp $HOME_NET any -> 192.168.0.255 any (detection_filter:track by_src, count 20, seconds 60; msg:"SMURF FLOODING ATTACK DETECTED"; sid:100000023; rev:1;)
alert udp any any -> $HOME_NET 53 (detection_filter:track by_src, count 10, seconds 60; msg:"UDP FLOODING ATTACK"; sid:10000007; rev:2;)
alert tcp $EXTERNAL_NET 5050 -> $HOME_NET 80 (msg:"TCP FIN Scan Detected"; flags:F; detection_filter:track by_src, count 20, seconds 60; classtype:attempted-recon; sid:10000001; rev:1;)
alert tcp $EXTERNAL_NET 5050 -> $HOME_NET 80 (msg:"Null Scan Detected"; flags:0; detection_filter:track by_src, count 20, seconds 60; classtype:attempted-recon; sid:10000002; rev:1;)
alert tcp $EXTERNAL_NET 5050 -> $HOME_NET 80 (msg:"Xmas Scan Detected"; flags:UPF; detection_filter:track by_src, count 20, seconds 60; classtype:attempted-recon; sid:10000003; rev:1;)
alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"UDP SCAN DETECTED"; detection_filter:track by_dst, count 20, seconds 60; classtype:attempted-recon; sid:10000006; rev:1;)
alert tcp any any -> any any (msg:"DDoS SYN Flood detected"; flags:S; detection_filter:track by_src, count 20, seconds 3; sid:1000001;)
alert udp any any -> any any (msg:"DDoS UDP Flood detected"; detection_filter:track by_src, count 50, seconds 10; sid:1000002;)
alert icmp any any -> any any (msg:"DDoS ICMP Flood detected"; icode:0; itype:8; detection_filter:track by_src, count 30, seconds 5; sid:1000003;)
alert tcp any any -> $HOME_NET 80 (msg:"DDoS HTTP GET Flood detected"; content:"GET"; detection_filter:track by_src, count 20, seconds 10; sid:1000004;)
alert udp any 53 -> any any (msg:"DDoS DNS Amplification Attack detected"; content:"|0000 8400|"; depth:10; detection_filter:track by_src, count 10, seconds 3; sid:1000005;)
alert udp any 123 -> any any (msg:"DDoS NTP Amplification Attack detected"; content:"|17 00 03 2A|"; depth:4; detection_filter:track by_src, count 10, seconds 3; sid:1000006;)
alert udp any 1900 -> any any (msg:"DDoS SSDP Amplification Attack detected"; content:"M-SEARCH"; detection_filter:track by_src, count 10, seconds 3; sid:1000007;)
alert udp any any -> any 53 (msg:"DDoS DNS Query Flood detected"; detection_filter:track by_src, count 20, seconds 10; sid:1000008;)
alert icmp any any -> $HOME_NET any (msg:"DDoS ICMP Smurf Attack detected"; itype:8; detection_filter:track by_src, count 50, seconds 3; sid:1000009;)
alert tcp any any -> any any (msg:"DDoS SYN-ACK Flood detected"; flags:SA; detection_filter:track by_src, count 20, seconds 5; sid:1000010;)
alert tcp any any -> $HOME_NET 80 (msg:"DDoS HTTP POST Flood detected"; content:"POST"; detection_filter:track by_src, count 20, seconds 10; sid:1000011;)
alert icmp any any -> any any (msg:"DDoS Ping of Death detected"; itype:8; dsize:>65500; sid:1000012;)
alert tcp any any -> any any (msg:"DDoS RST Flood detected"; flags:R; detection_filter:track by_src, count 20, seconds 5; sid:1000013;)
alert tcp any any -> any any (msg:"DDoS FIN Flood detected"; flags:F; detection_filter:track by_src, count 20, seconds 5; sid:1000014;)
alert udp any any -> $HOME_NET 7 (msg:"DDoS Fraggle Attack detected"; detection_filter:track by_src, count 30, seconds 5; sid:1000015;)
alert tcp any any -> $HOME_NET 80 (msg:"DDoS Slowloris Attack detected"; flags:S; flow:to_server,established; detection_filter:track by_src, count 100, seconds 60; sid:1000016;)
alert tcp any any -> $HOME_NET 80 (msg:"DDoS HTTP Flood - Suspicious User-Agent"; content:"User-Agent: suspect"; detection_filter:track by_src, count 10, seconds 10; sid:1000017;)
alert udp any any -> $HOME_NET 53 (msg:"DDoS DNS Water Torture Attack detected"; content:"|00 00 01 00 00 00 00 00|"; detection_filter:track by_src, count 50, seconds 10; sid:1000018;)
alert udp any any -> $HOME_NET 53 (msg:"DDoS DNS NXDomain Flood detected"; content:"NXDOMAIN"; detection_filter:track by_src, count 20, seconds 5; sid:1000019;)
alert udp any any -> $HOME_NET 5060 (msg:"DDoS SIP Flood detected"; content:"INVITE"; detection_filter:track by_src, count 30, seconds 10; sid:1000020;)
alert ip any any -> any any (msg:"DDoS Connection Storm detected"; detection_filter:track by_src, count 100, seconds 5; sid:1000021;)
alert tcp any any -> any any (msg:"DDoS RST-FIN Flood detected"; flags:RF; detection_filter:track by_src, count 20, seconds 5; sid:1000022;)
alert tcp any any -> any any (msg:"DDoS ACK Flood detected"; flags:A; detection_filter:track by_src, count 20, seconds 5; sid:1000023;)
alert tcp any any -> $HOME_NET 80 (msg:"DDoS HTTP HEAD Flood detected"; content:"HEAD"; detection_filter:track by_src, count 20, seconds 10; sid:1000024;)
alert tcp any any -> any any (msg:"TCP Port Scan detected"; flags:S; detection_filter:track by_src, count 20, seconds 5; sid:1000026;)
alert udp any any -> any any (msg:"UDP Port Scan detected"; detection_filter:track by_src, count 10, seconds 3; sid:1000027;)
alert icmp any any -> any any (msg:"ICMP Port Scan detected"; itype:8; detection_filter:track by_src, count 10, seconds 3; sid:1000028;)
alert tcp any any -> any any (msg:"Xmas Tree Scan detected"; flags:FPU; sid:1000029;)
alert tcp any any -> any any (msg:"Null Scan detected"; flags:0; sid:1000030;)
alert tcp any any -> any any (msg:"FIN Scan detected"; flags:F; sid:1000031;)
alert tcp any any -> any any (msg:"ACK Scan detected"; flags:A; detection_filter:track by_src, count 10, seconds 3; sid:1000032;)
alert tcp any any -> any any (msg:"Window Scan detected"; flags:A; window:0; sid:1000033;)
alert tcp any any -> any any (msg:"Stealth Scan detected"; flags:S; flow:stateless; detection_filter:track by_src, count 10, seconds 3; sid:1000034;)
alert tcp any any -> any any (msg:"TCP SYN Scan detected"; flags:S; detection_filter:track by_src, count 20, seconds 3; sid:1000035;)
alert tcp any any -> any any (msg:"TCP Connect Scan detected"; flags:SA; detection_filter:track by_src, count 20, seconds 3; sid:1000036;)
alert ip any any -> any any (msg:"IP Protocol Scan detected"; ip_proto:>1; detection_filter:track by_src, count 10, seconds 20; sid:1000037;)
alert icmp any any -> any any (msg:"ICMP Timestamp Request Scan detected"; itype:13; sid:1000038;)
alert icmp any any -> any any (msg:"ICMP Address Mask Request Scan detected"; itype:17; sid:1000039;)
alert tcp any any -> any any (msg:"TCP Maimon Scan detected"; flags:FA; sid:1000040;)
alert tcp any any -> any [22,23,80,443,445] (msg:"Single Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000041;)
alert tcp any any -> any any (msg:"Multiple Port Scan detected"; flags:S; detection_filter:track by_src, count 20, seconds 60; sid:1000042;)
alert tcp any any -> any any (msg:"TCP FIN Scan detected"; flags:F; detection_filter:track by_src, count 10, seconds 5; sid:1000043;)
alert tcp any any -> any any (msg:"Version Scan (Banner Grabbing) detected"; content:"HTTP/"; detection_filter:track by_src, count 5, seconds 60; sid:1000044;)
alert icmp any any -> any any (msg:"ICMP Echo Scan detected"; itype:8; detection_filter:track by_src, count 10, seconds 3; sid:1000045;)
alert icmp any any -> any any (msg:"ICMP Echo Reply Scan detected"; itype:0; detection_filter:track by_src, count 10, seconds 3; sid:1000046;)
alert udp any any -> any 7 (msg:"UDP Ping detected"; detection_filter:track by_src, count 10, seconds 3; sid:1000047;)
alert tcp any any -> any any (msg:"TCP ACK-PSH Scan detected"; flags:AP; sid:1000048;)
alert tcp any any -> any any (msg:"TCP PSH Scan detected"; flags:P; sid:1000049;)
alert tcp any any -> any any (msg:"TCP XMAS Scan detected"; flags:UPF; sid:1000050;)
alert tcp any any -> any any (msg:"TCP SYN-ACK Scan detected"; flags:SA; sid:1000051;)
alert tcp any any -> any any (msg:"TCP NULL Scan detected"; flags:0; sid:1000052;)
alert ip any any -> any any (msg:"IP Fragment Scan detected"; fragbits:M; sid:1000053;)
alert tcp any any -> any any (msg:"FTP Bounce Scan detected"; content:"PORT "; sid:1000054;)
alert tcp any any -> any 21 (msg:"FTP Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000055;)
alert tcp any any -> any 25 (msg:"SMTP Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000056;)
alert tcp any any -> any 23 (msg:"Telnet Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000057;)
alert tcp any any -> any 22 (msg:"SSH Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000058;)
alert tcp any any -> any 53 (msg:"DNS Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000059;)
alert tcp any any -> any 80 (msg:"HTTP Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000060;)
alert tcp any any -> any 443 (msg:"HTTPS Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000061;)
alert tcp any any -> any 445 (msg:"SMB Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000062;)
alert tcp any any -> any 3389 (msg:"RDP Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000063;)
alert tcp any any -> any 110 (msg:"POP3 Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000064;)
alert tcp any any -> any 143 (msg:"IMAP Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000065;)
alert tcp any any -> any 3306 (msg:"MySQL Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000066;)
alert tcp any any -> any 1433 (msg:"MSSQL Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000067;)
alert tcp any any -> any 5432 (msg:"PostgreSQL Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000068;)
alert tcp any any -> any 5900 (msg:"VNC Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000069;)
alert tcp any any -> any 389 (msg:"LDAP Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000070;)
alert udp any any -> any 161 (msg:"SNMP Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000071;)
alert udp any any -> any 69 (msg:"TFTP Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000072;)
alert udp any any -> any 88 (msg:"Kerberos Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000073;)
alert udp any any -> any 123 (msg:"NTP Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000074;)
alert udp any any -> any 1812 (msg:"RADIUS Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000075;)
alert udp any any -> any 520 (msg:"RIP Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000076;)
alert udp any any -> any 5060 (msg:"SIP Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000077;)
alert tcp any any -> any 179 (msg:"BGP Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000078;)
alert tcp any any -> any 111 (msg:"RPC Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000079;)
alert tcp any any -> any 515 (msg:"LPD Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000080;)
alert udp any any -> any 514 (msg:"Syslog Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000081;)
alert tcp any any -> any 6667 (msg:"IRC Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000082;)
alert tcp any any -> any 636 (msg:"LDAP over SSL Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000083;)
alert tcp any any -> any 445 (msg:"Microsoft DS Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000084;)
alert tcp any any -> any 548 (msg:"AFP Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000085;)
alert udp any any -> any 1434 (msg:"Microsoft SQL Monitor Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000086;)
alert tcp any any -> any 3389 (msg:"Microsoft Terminal Services Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000087;)
alert tcp any any -> any 1521 (msg:"Oracle DB Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000088;)
alert tcp any any -> any 135 (msg:"Windows RPC Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000089;)
alert tcp any any -> any 593 (msg:"Windows RPC over HTTP Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000090;)
alert udp any any -> any 1434 (msg:"Microsoft SQL Server Resolution Protocol Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000091;)
alert tcp any any -> any 445 (msg:"Microsoft RPC over Named Pipes Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000092;)
alert tcp any any -> any 445 (msg:"Microsoft-DS over IPX Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000093;)
alert tcp any any -> any 524 (msg:"Novell NetWare Service Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000094;)
alert tcp any any -> any 139 (msg:"Microsoft SMB over NetBIOS Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000095;)
alert tcp any any -> any 135 (msg:"Microsoft Windows Messenger Port Scan detected"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000096;)
alert udp any any -> any 123 (msg:"Microsoft Windows Time Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000097;)
alert udp any any -> any 138 (msg:"NetBIOS Datagram Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000098;)
alert udp any any -> any 137 (msg:"NetBIOS Name Service Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000099;)
alert udp any any -> any 427 (msg:"Windows Service Location Port Scan detected"; detection_filter:track by_src, count 5, seconds 60; sid:1000100;)
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt Detected"; content:"UNION SELECT"; nocase; sid:1000101;)
alert tcp any any -> $HOME_NET 80 (msg:"Command Injection Attempt Detected"; content:"|26|"; content:"|7C|"; distance:1; sid:1000102;)
alert tcp any any -> $HOME_NET 80 (msg:"XSS Attempt Detected"; content:"<script>"; nocase; sid:1000103;)
alert tcp any any -> $HOME_NET any (msg:"Buffer Overflow Attempt Detected"; content:"|41 41 41 41 41 41 41 41|"; sid:1000104;)
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt Detected"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; sid:1000105;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Zeus Malware Command and Control Traffic Detected"; content:"|3c 70 6f 6c 69 63 79 3e|"; sid:1000106;)
alert tcp any any -> $HOME_NET any (msg:"C2 Traffic Detected"; content:"/gate.php"; http_uri; sid:1000107;)
alert tcp any any -> $HOME_NET 80 (msg:"Unauthorized Admin Access Attempt Detected"; content:"/admin"; http_uri; sid:1000108;)
alert tcp any any -> $HOME_NET 80 (msg:"Remote File Inclusion Attempt Detected"; content:"http://"; http_uri; sid:1000109;)
alert udp $EXTERNAL_NET 138 -> $HOME_NET any (msg:"Conficker Worm Detected"; content:"|81 00 00 00 8c|"; sid:1000110;)
alert tcp any any -> $HOME_NET 25 (msg:"Phishing Email Detected"; content:"From: "; content:"@phishing.com"; sid:1000111;)
alert tcp any any -> $HOME_NET 80 (msg:"Attempt to Access Sensitive File Detected"; content:"/etc/passwd"; http_uri; sid:1000112;)
alert tcp any any -> $HOME_NET 80 (msg:"Obfuscated JavaScript Detected"; content:"eval("; http_client_body; sid:1000113;)
alert tcp any any -> $HOME_NET any (msg:"Cryptolocker Command and Control Traffic Detected"; content:"|15 03 01 00 02 02 28|"; sid:1000114;)
alert tcp any any -> $HOME_NET any (msg:"Privilege Escalation Attempt Detected"; content:"/sudoers"; sid:1000115;)
alert tcp any any -> $HOME_NET any (msg:"Remote Code Execution Attempt Detected"; content:"/bin/sh"; sid:1000116;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Data Exfiltration Attempt Detected"; content:"filename="; sid:1000117;)
alert tcp any any -> $HOME_NET 80 (msg:"Directory Traversal Attempt Detected"; content:"../"; sid:1000118;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"WannaCry Ransomware Activity Detected"; content:"|57 41 4E 41|"; sid:1000119;)
alert tcp any any -> $HOME_NET 445 (msg:"Unauthorized Network Share Access Detected"; content:"\\\\"; sid:1000120;)
alert tcp any any -> $HOME_NET 80 (msg:"Phishing URL Detected"; content:"login.php"; http_uri; sid:1000121;)
alert tcp any any -> $HOME_NET 80 (msg:"CSRF Attempt Detected"; content:"<input type=\"hidden\""; http_client_body; sid:1000122;)
alert tcp any any -> $HOME_NET any (msg:"Emotet Malware Activity Detected"; content:"/wp-admin/admin-ajax.php"; http_uri; sid:1000123;)
alert tcp any any -> $HOME_NET any (msg:"TrickBot Malware Activity Detected"; content:"/client.dll"; http_uri; sid:1000125;)
alert tcp any any -> $HOME_NET any (msg:"Keylogging Activity Detected"; content:"password="; http_client_body; sid:1000126;)
alert tcp any any -> $HOME_NET 23 (msg:"Unauthorized Telnet Access Attempt Detected"; sid:1000127;)
alert tcp any any -> $HOME_NET any (msg:"Agent Tesla Malware Activity Detected"; content:"/get.php"; http_uri; sid:1000128;)
alert tcp any any -> $HOME_NET 445 (msg:"Unauthorized SMB Access Attempt Detected"; sid:1000129;)
alert tcp any any -> $HOME_NET 80 (msg:"XXE Attack Detected"; content:"<!DOCTYPE"; sid:1000130;)
alert tcp any any -> $HOME_NET any (msg:"Dridex Malware Activity Detected"; content:"/webinject.php"; http_uri; sid:1000131;)
alert tcp any any -> $HOME_NET 53 (msg:"DNS Cache Poisoning Attack Detected"; content:"CNAME"; sid:1000132;)
alert tcp any any -> $HOME_NET 80 (msg:"Session Hijacking Attempt Detected"; content:"Set-Cookie:"; http_header; sid:1000133;)
alert tcp any any -> $HOME_NET any (msg:"Ursnif Malware Activity Detected"; content:"/pan.php"; http_uri; sid:1000134;)
alert tcp any any -> $HOME_NET 80 (msg:"Clickjacking Attempt Detected"; content:"X-Frame-Options: DENY"; http_header; sid:1000135;)
alert tcp any any -> $HOME_NET 445 (msg:"EternalBlue Exploit Detected"; content:"|17 03 01 00|"; sid:1000136;)
alert tcp any any -> $HOME_NET any (msg:"Locky Ransomware Activity Detected"; content:"/bitcoin_address.txt"; http_uri; sid:1000137;)
alert tcp any any -> any any (msg:"Man-in-the-Middle Attack Detected"; content:"Proxy-Connection:"; sid:1000138;)
alert tcp any any -> $HOME_NET any (msg:"Cobalt Strike Malware Activity Detected"; content:"/beacon"; http_uri; sid:1000139;)
alert tcp any any -> $HOME_NET any (msg:"Shellshock Exploit Detected"; content:"|28 29 20 7B 20 3A 3B 20 7D|"; sid:1000140;)
alert udp any any -> $HOME_NET 53 (msg:"DNS Spoofing Attempt Detected"; content:"|C0 A8 00|"; sid:1000141;)
alert tcp any any -> $HOME_NET any (msg:"GandCrab Ransomware Activity Detected"; content:"/payment.php"; http_uri; sid:1000142;)
alert tcp any any -> $HOME_NET any (msg:"Timing Analysis Attack Detected"; content:"If-Modified-Since:"; http_header; sid:1000143;)
alert tcp any any -> $HOME_NET any (msg:"DarkComet RAT Activity Detected"; content:"/DC"; http_uri; sid:1000144;)
alert tcp any any -> $HOME_NET 445 (msg:"SMBGhost Exploit Detected"; content:"|FE 53 4D 42 40|"; sid:1000145;)
alert tcp any any -> $HOME_NET any (msg:"QakBot Malware Activity Detected"; content:"/status.php"; http_uri; sid:1000146;)
alert tcp any any -> $HOME_NET 3389 (msg:"BlueKeep Exploit Detected"; content:"|03 00 00|"; sid:1000147;)
alert tcp any any -> $HOME_NET 443 (msg:"Credential Stuffing Attempt Detected"; content:"username="; http_client_body; detection_filter:track by_src, count 5, seconds 60; sid:1000148;)
alert tcp any any -> $HOME_NET any (msg:"Agent Smith Malware Activity Detected"; content:"/agent_smith.php"; http_uri; sid:1000149;)
alert tcp any any -> $HOME_NET 80 (msg:"Typosquatting Domain Detected"; content:"googl.com"; http_header; sid:1000150;)
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt Detected"; content:"OR 1=1"; nocase; sid:1000151;)
alert tcp any any -> $HOME_NET 80 (msg:"Directory Listing Attempt Detected"; content:"Index of /"; http_uri; sid:1000152;)
alert tcp $EXTERNAL_NET 1433 -> $HOME_NET any (msg:"SQL Server Bruteforce Attempt Detected"; flow:to_server,established; detection_filter:track by_src, count 10, seconds 60; sid:1000153;)
alert udp any any -> $HOME_NET 67 (msg:"DHCP Starvation Attack Detected"; content:"|63 82 53 63|"; sid:1000154;)
alert tcp any any -> $HOME_NET 21 (msg:"FTP Brute Force Attempt Detected"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; sid:1000155;)
alert tcp any any -> $HOME_NET 80 (msg:"Shell Upload Attempt Detected"; content:"/upload.php"; http_uri; sid:1000156;)
alert tcp any any -> $HOME_NET any (msg:"RPC DCOM Exploit Attempt Detected"; content:"|5c 00 5c 00|"; sid:1000157;)
alert udp any any -> $HOME_NET 161 (msg:"SNMP Brute Force Attempt Detected"; content:"|30|"; sid:1000158;)
alert tcp any any -> $HOME_NET 80 (msg:"PHP Remote File Inclusion Attempt Detected"; content:"php://input"; http_uri; sid:1000159;)
alert tcp $EXTERNAL_NET 3389 -> $HOME_NET any (msg:"RDP Bruteforce Attempt Detected"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; sid:1000160;)
alert udp any any -> $HOME_NET 5060 (msg:"SIP Digest Leak Detected"; content:"Digest"; sid:1000161;)
alert tcp any any -> $HOME_NET 25 (msg:"SMTP Command Injection Detected"; content:"EHLO "; sid:1000162;)
alert udp any any -> $HOME_NET 53 (msg:"DNS Zone Transfer Attempt Detected"; content:"AXFR"; sid:1000163;)
alert tcp any any -> $HOME_NET 22 (msg:"SSH Tunneling Attempt Detected"; content:"-D "; sid:1000164;)
alert tcp any any -> $HOME_NET 80 (msg:"WordPress Brute Force Login Detected"; content:"/wp-login.php"; http_uri; detection_filter:track by_src, count 5, seconds 60; sid:1000165;)
alert tcp any any -> $HOME_NET 80 (msg:"Joomla Admin Login Attempt Detected"; content:"/administrator/index.php"; http_uri; sid:1000166;)
alert tcp any any -> $HOME_NET 8080 (msg:"Tomcat Manager Access Attempt Detected"; content:"/manager/html"; http_uri; sid:1000167;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"Samba Trans2open Overflow Attempt Detected"; content:"|00 02|"; sid:1000168;)
alert tcp any any -> $HOME_NET 445 (msg:"MS08-067 NetAPI Buffer Overflow Detected"; content:"|4d 53 46 54 43|"; sid:1000169;)
alert udp any any -> $HOME_NET 137 (msg:"NetBIOS Name Service Spoofing Detected"; content:"|20|"; sid:1000170;)
alert tcp any any -> $HOME_NET 80 (msg:"PHP Shell Injection Attempt Detected"; content:"shell_exec("; sid:1000171;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"HTTP Basic Auth Bruteforce Detected"; content:"Authorization: Basic"; detection_filter:track by_src, count 5, seconds 60; sid:1000172;)
alert tcp any any -> $HOME_NET 1433 (msg:"SQL Slammer Worm Activity Detected"; content:"|04 01 01 01|"; sid:1000173;)
alert tcp any any -> $HOME_NET 80 (msg:"WordPress Timthumb Exploit Attempt Detected"; content:"/timthumb.php"; http_uri; sid:1000174;)
alert tcp any any -> $HOME_NET 80 (msg:"WebDAV PUT Method Detected"; content:"PUT "; sid:1000175;)
alert tcp any any -> $HOME_NET 143 (msg:"IMAP Login Bruteforce Detected"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; sid:1000176;)
alert tcp any any -> $HOME_NET 110 (msg:"POP3 Login Bruteforce Detected"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; sid:1000177;)
alert udp any any -> $HOME_NET 69 (msg:"TFTP GET Request Detected"; content:"|00 01|"; sid:1000178;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"TOR Exit Node Traffic Detected"; content:"torproject.org"; sid:1000179;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Social Engineering Toolkit Activity Detected"; content:"SET User-Agent"; sid:1000180;)
alert tcp any any -> $HOME_NET 443 (msg:"SSLv2 Handshake Detected"; content:"|80 03 01 00 02|"; sid:1000181;)
alert tcp any any -> $HOME_NET 80 (msg:"HTML5 WebSocket Detected"; content:"Upgrade: websocket"; sid:1000182;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Meterpreter Reverse TCP Traffic Detected"; content:"|00 00 00|"; sid:1000183;)
alert tcp any any -> $HOME_NET 80 (msg:"Cross-Site Request Forgery (CSRF) Detected"; content:"<input type=\"hidden\" name=\"csrf_token\""; sid:1000184;)
alert tcp any any -> $HOME_NET 80 (msg:"Insecure Cookie Detected"; content:"Set-Cookie: "; content:"; HttpOnly"; http_header; sid:1000185;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Reverse Shell Attempt Detected"; content:"/bin/bash"; sid:1000186;)
alert tcp any any -> $HOME_NET 80 (msg:"Directory Traversal via Encoding Detected"; content:"%2e%2e%2f"; sid:1000187;)
alert udp any any -> $HOME_NET 500 (msg:"IKE Aggressive Mode Detected"; content:"|00 00 00 01|"; sid:1000188;)
alert tcp any any -> $HOME_NET 389 (msg:"LDAP Injection Attempt Detected"; content:"(&(objectClass="; sid:1000189;)
alert tcp any any -> $HOME_NET any (msg:"Buffer Overflow via Long URL Detected"; urilen:>255; sid:1000190;)
alert tcp any any -> $HOME_NET any (msg:"Potentially Malicious Executable Detected"; content:"MZ"; sid:1000191;)
EOT

echo "Custom rules added to $custom_rules_file."

# Ask if you want to log the rules to syslog
read -p "Do you want to configure Snort to log the rules to syslog? (y/n): " syslog_config
if [ "$syslog_config" == "y" ]; then
    if ! grep -q "output alert_syslog" "$snort_conf"; then
        echo "# syslog" >> "$snort_conf"
        echo "output alert_syslog: host=127.0.0.1:514, LOG_LOCAL1 LOG_ALERT" >> "$snort_conf"
        echo "Syslog configuration added to Snort configuration file."
    else
        echo "Syslog configuration already present in Snort configuration file."
    fi
    
    # Check if rsyslog is configured correctly
    if ! grep -q "local1.* /var/log/syslog" /etc/rsyslog.conf; then
        echo "local1.* /var/log/syslog" >> /etc/rsyslog.conf
        echo "Rsyslog configuration updated."
        
        # Restart rsyslog and snort
        systemctl restart rsyslog
        echo "Rsyslog restarted."
    else
        echo "Rsyslog configuration already present."
    fi
    
    systemctl restart snort
    echo "Snort restarted."
fi

echo "Script completed."