# Study Guide for Network Analyst Senior - Test 2
## Section 1.3.3: Initial Exploitation

### HTTP GET Request Brute Force Attack
An HTTP GET request brute force attack can be identified through various indicators such as increased traffic on specific URLs or endpoints, a high volume of GET requests from a single IP address, and access logs showing repeated attempts to access sensitive resources. These patterns suggest systematic attempts to guess or access unauthorized information.

**Log Source:** Web server access logs  
**Wireshark Filter Example:** 
```plaintext
http.request.method == "GET"
```  
**Suricata Rule:** 
```plaintext
alert http any any -> any any (msg:"HTTP GET brute force attack"; flow:to_server,established; threshold:type threshold, track by_src, count 100, seconds 60; classtype:web-application-attack; sid:1000001;)
```  
**Snort Rule:** 
```plaintext
alert tcp any any -> any 80 (msg:"HTTP GET brute force attack"; flow:to_server,established; content:"GET"; http_method; threshold:type threshold, track by_src, count 100, seconds 60; classtype:web-application-attack; sid:1000001;)
```

### HTTP POST Request Brute Force Attack
Detecting an HTTP POST request brute force attack involves looking for unusual patterns in form submissions, such as numerous submissions with different credential combinations. This indicates systematic attempts to breach security through brute force.

**Log Source:** Web server access logs  
**Wireshark Filter Example:** 
```plaintext
http.request.method == "POST"
```  
**Suricata Rule:** 
```plaintext
alert http any any -> any any (msg:"HTTP POST brute force attack"; flow:to_server,established; threshold:type threshold, track by_src, count 100, seconds 60; classtype:web-application-attack; sid:1000002;)
```  
**Snort Rule:** 
```plaintext
alert tcp any any -> any 80 (msg:"HTTP POST brute force attack"; flow:to_server,established; content:"POST"; http_method; threshold:type threshold, track by_src, count 100, seconds 60; classtype:web-application-attack; sid:1000002;)
```

### Cross-Site Scripting (XSS) Reflected Attack
Vulnerability to reflected XSS attacks can be identified by unsanitized user input echoed back in HTTP responses and detection of encoded or obfuscated JavaScript in responses. These signs indicate potential for malicious script execution.

**Log Source:** Web server access logs, application logs  
**Wireshark Filter Example:** 
```plaintext
http contains "<script>"
```  
**Suricata Rule:** 
```plaintext
alert http any any -> any any (msg:"XSS Reflected Attack"; flow:to_server,established; content:"<script>"; nocase; classtype:web-application-attack; sid:1000003;)
```  
**Snort Rule:** 
```plaintext
alert tcp any any -> any 80 (msg:"XSS Reflected Attack"; flow:to_server,established; content:"<script>"; nocase; classtype:web-application-attack; sid:1000003;)
```

### Cross-Site Scripting (XSS) Persistent Attack
Persistent XSS attacks involve ongoing malicious scripts appearing on web pages. These can be identified through user reports or automated scans detecting persistent malicious content.

**Log Source:** Web server access logs, application logs  
**Wireshark Filter Example:** 
```plaintext
http contains "<script>"
```  
**Suricata Rule:** 
```plaintext
alert http any any -> any any (msg:"XSS Persistent Attack"; flow:to_server,established; content:"<script>"; nocase; classtype:web-application-attack; sid:1000004;)
```  
**Snort Rule:** 
```plaintext
alert tcp any any -> any 80 (msg:"XSS Persistent Attack"; flow:to_server,established; content:"<script>"; nocase; classtype:web-application-attack; sid:1000004;)
```

## Section 1.4.1: Actions on Target

### Command and Control (C2)
C2 activity can be identified by monitoring for encrypted or obfuscated communication patterns, which are common in C2 traffic to evade detection.

**Log Source:** Network traffic logs, firewall logs  
**Wireshark Filter Example:** 
```plaintext
ssl
```  
**Suricata Rule:** 
```plaintext
alert tcp any any -> any any (msg:"Possible C2 Communication"; flow:to_server,established; content:"|16 03|"; depth:2; classtype:trojan-activity; sid:1000005;)
```  
**Snort Rule:** 
```plaintext
alert tcp any any -> any any (msg:"Possible C2 Communication"; flow:to_server,established; content:"|16 03|"; depth:2; classtype:trojan-activity; sid:1000005;)
```

### Lateral Movement
Lateral movement within a network can be identified by unusual authentication attempts and remote desktop protocol (RDP) connections from unexpected sources. These signs suggest an attacker is trying to move laterally within the network.

**Log Source:** Windows Event Logs, Sysmon logs  
**Wireshark Filter Example:** 
```plaintext
tcp.port == 3389
```  
**Suricata Rule:** 
```plaintext
alert tcp any any -> any 3389 (msg:"Possible Lateral Movement via RDP"; flow:to_server,established; content:"USER"; nocase; classtype:policy-violation; sid:1000006;)
```  
**Snort Rule:** 
```plaintext
alert tcp any any -> any 3389 (msg:"Possible Lateral Movement via RDP"; flow:to_server,established; content:"USER"; nocase; classtype:policy-violation; sid:1000006;)
```

### Data Exfiltration
Data exfiltration attempts can be detected by monitoring for large or unusual outbound data transfers. This indicates that sensitive data may be leaving the network.

**Log Source:** Network traffic logs, data transfer logs  
**Wireshark Filter Example:** 
```plaintext
ip.dst == <external_ip> and frame.len > 1500
```  
**Suricata Rule:** 
```plaintext
alert ip any any -> any any (msg:"Large Outbound Data Transfer"; flow:to_server,established; dsize:>1500; classtype:data-theft; sid:1000007;)
```  
**Snort Rule:** 
```plaintext
alert ip any any -> any any (msg:"Large Outbound Data Transfer"; flow:to_server,established; dsize:>1500; classtype:data-theft; sid:1000007;)
```

### Obfuscation
Common techniques for network traffic obfuscation include encoding or encrypting payloads and using steganography to hide data within innocuous files. These methods make it harder to detect malicious activity.

**Log Source:** Network traffic logs, IDS/IPS logs  
**Wireshark Filter Example:** 
```plaintext
ssl.handshake.type == 1
```  
**Suricata Rule:** 
```plaintext
alert ip any any -> any any (msg:"Obfuscated Traffic Detected"; flow:to_server,established; content:"|16 03|"; depth:2; classtype:obfuscation; sid:1000008;)
```  
**Snort Rule:** 
```plaintext
alert ip any any -> any any (msg:"Obfuscated Traffic Detected"; flow:to_server,established; content:"|16 03|"; depth:2; classtype:obfuscation; sid:1000008;)
```

### Multi-Stage Malware Deployment
Multi-stage malware deployment typically involves the initial delivery of a downloader or dropper component, followed by the subsequent retrieval of additional payload components from external servers. Immediate execution of the full malware payload is not characteristic of multi-stage deployment.

**Log Source:** Endpoint detection logs, antivirus logs  
**Wireshark Filter Example:** 
```plaintext
http.request.uri contains "/download"
```  
**Suricata Rule:** 
```plaintext
alert http any any -> any any (msg:"Multi-Stage Malware Download"; flow:to_server,established; content:"/download"; nocase; classtype:malware-download; sid:1000009;)
```  
**Snort Rule:** 
```plaintext
alert tcp any any -> any 80 (msg:"Multi-Stage Malware Download"; flow:to_server,established; content:"/download"; nocase; classtype:malware-download; sid:1000009;)
```

### Persistence
Persistence mechanisms on a compromised system can be identified by attempts to create or modify system services or scheduled tasks, communication with command and control infrastructure for periodic check-ins, and exploitation of vulnerabilities to maintain access.

**Log Source:** Windows Event Logs, Sysmon logs  
**Wireshark Filter Example:** 
```plaintext
dns.qry.name == "example.com"
```  
**Suricata Rule:** 
```plaintext
alert dns any any -> any any (msg:"C2 Domain Check-in"; dns_query; content:"example.com"; nocase; classtype:command-and-control; sid:1000010;)
```  
**Snort Rule:** 
```plaintext
alert udp any any -> any 53 (msg:"C2 Domain Check-in"; content:"example.com"; nocase; classtype:command-and-control; sid:1000010;)
```

## Section 1.4.7: Hiding C2 and Data Exfiltration in HTTP Requests

iding C2 and Data Exfiltration in HTTP Requests

Actors can hide command and control (C2) communication and data exfiltration within HTTP requests by embedding C2 commands or data within the URL path or query parameters. This method conceals malicious activity within legitimate HTTP requests.

**Log Source:** Web server access logs, firewall logs  
**Wireshark Filter Example:** 
```plaintext
http.request.uri contains "/cmd="
```  
**Suricata Rule:** 
```plaintext
alert http any any -> any any (msg:"Hidden C2 in HTTP Request"; flow:to_server,established; content:"/cmd="; nocase; classtype:command-and-control; sid:1000011;)
```  
**Snort Rule:** 
```plaintext
alert tcp any any -> any 80 (msg:"Hidden C2 in HTTP Request"; flow:to_server,established; content:"/cmd="; nocase; classtype:command-and-control; sid:1000011;)
```

## Section 1.4.8: Anomalous Web Connection Behaviors

Repeated access attempts to restricted resources within a web application usually suggest brute-force attacks or other unauthorized access efforts, rather than legitimate user activity or maintenance.

**Log Source:** Web server access logs, firewall logs  
**Wireshark Filter Example:** 
```plaintext
http.request.uri contains "/admin"
```  
**Suricata Rule:** 
```plaintext
alert http any any -> any any (msg:"Repeated Access to Restricted Resource"; flow:to_server,established; content:"/admin"; nocase; threshold:type threshold, track by_src, count 10, seconds 60; classtype:web-application-attack; sid:1000012;)
```  
**Snort Rule:** 
```plaintext
alert tcp any any -> any 80 (msg:"Repeated Access to Restricted Resource"; flow:to_server,established; content:"/admin"; nocase; threshold:type threshold, track by_src, count 10, seconds 60; classtype:web-application-attack; sid:1000012;)
```

## Section 1.4.9: DNS Spoofing

DNS spoofing exploits vulnerabilities in DNS records by manipulating DNS records to redirect legitimate traffic to malicious websites or servers, compromising network security.

**Log Source:** DNS server logs, firewall logs  
**Wireshark Filter Example:** 
```plaintext
dns.flags == 0x8180
```  
**Suricata Rule:** 
```plaintext
alert dns any any -> any any (msg:"DNS Spoofing Detected"; dns_query; content:"malicious.com"; nocase; classtype:dns-spoof; sid:1000013;)
```  
**Snort Rule:** 
```plaintext
alert udp any any -> any 53 (msg:"DNS Spoofing Detected"; content:"malicious.com"; nocase; classtype:dns-spoof; sid:1000013;)
```

## Section 2.1.6: Using Variables in an IDS

Variables in an IDS can be utilized to define IP address ranges for monitoring. This allows for flexible and reusable rule creation without hardcoding specific values.

**Example:** If you want to monitor traffic within a specific internal network, you can define a variable such as `$HOME_NET` to represent the internal IP address range (e.g., `10.0.0.0/24`). This variable can then be used in IDS rules to target only the internal network traffic.

**Query Example:** 
```plaintext
var HOME_NET [10.0.0.0/24]
alert tcp $HOME_NET any -> any any (msg:"Internal Network Traffic Detected"; sid:1000001;)
```

## Section 2.1.10: Configuring $HOME_NET_IPs

Configuring `$HOME_NET_IPs` helps in differentiating between internal and external network traffic, aiding in accurate analysis and security monitoring.

**Example:** By defining `$HOME_NET` as your internal network (e.g., `192.168.1.0/24`), IDS rules can be set to specifically watch for traffic originating from or destined to this network.

**Usage in Rules:** This differentiation helps in focusing the analysis on potentially suspicious traffic within the internal network, ignoring external, irrelevant traffic.

## Section 2.1.14: Detecting IRC Activity

A Snort rule can be used to alert if IRC ports (6667-7001) are being used. This rule targets traffic using IRC ports and specific IRC-related content, indicating potential unauthorized IRC activity.

**Example Rule:** 
```plaintext
alert tcp any any -> any $IRC_PORTS (msg:"IRC Activity Detected"; flow:to_server,established; content:"USER"; nocase; content:"PRIVMSG"; nocase; classtype:policy-violation; sid:1000013;)
```

**Explanation:** This rule will trigger an alert if it detects traffic on IRC ports containing IRC commands such as `USER` and `PRIVMSG`.

## Section 2.1.15: Monitoring Communications with Malicious Domains

A Snort rule designed to alert on communications to or from a known malicious domain (e.g., "badwebsite.com") helps detect and mitigate potential threats by targeting specified variables.

**Example Rule:** 
```plaintext
alert tcp any any -> $BAD_WEBSITE any (msg:"Communication with badwebsite.com"; flow:to_server,established; classtype:policy-violation; sid:1000014;)
```

**Explanation:** This rule will generate an alert if any communication is detected between your network and the specified malicious domain.

## Section 2.1.16: Suricata Log Files

Suricata logs are stored in the `/var/log/suricata/` directory, with `eve.json` being the primary log file for event data.

**Log File Example:**
```plaintext
/var/log/suricata/eve.json
```

**Explanation:** This file contains detailed logs of all events detected by Suricata, which can be analyzed to identify and investigate security incidents.

## Section 2.2.1: Writing Queries for Detection

### Brute Force Attacks over HTTP:
To detect brute force attacks over HTTP, a query can be used to identify IPs with a high number of GET requests, which is a common pattern in brute force attacks.
```sql
SELECT ip, COUNT(*) 
FROM http_logs 
WHERE method = 'GET' 
GROUP BY ip 
HAVING COUNT(*) > 100;
```
**Explanation:** This query identifies IP addresses with more than 100 GET requests, which is indicative of a potential brute force attack.

### Shortened URL Redirects:
To find shortened URLs redirecting the customer to another domain, a query can be used to look for URLs containing 'bit.ly', indicating a potential redirect.
```sql
SELECT * 
FROM http_logs 
WHERE url LIKE '%bit.ly%';
```
**Explanation:** This query filters the HTTP logs to find entries where the URL contains 'bit.ly', which is a common URL shortening service.

### More HTTP POST Requests than GET Requests:
To detect more HTTP POST requests than GET requests, a query can be used to compare the counts of each method and identify when POST requests exceed GET requests.
```sql
SELECT method, COUNT(*) 
FROM http_logs 
WHERE method IN ('POST', 'GET') 
GROUP BY method 
HAVING method = 'POST' AND COUNT(*) > 
  (SELECT COUNT(*) 
   FROM http_logs 
   WHERE method = 'GET');
```
**Explanation:** This query compares the number of POST and GET requests to identify when POST requests are more frequent, which could indicate a brute force attempt using POST.

### Spike in DNS "A" Records:
A query can be used to detect a spike in DNS "A" records by grouping and counting occurrences within a specific timeframe, indicating unusual activity.
```sql
SELECT COUNT(*), timestamp 
FROM dns_logs 
WHERE type = 'A' 
GROUP BY timestamp 
HAVING COUNT(*) > 100;
```
**Explanation:** This query looks for timeframes where the count of DNS "A" records exceeds 100, which can indicate a spike in activity.

### Monitoring DNS Entropy Levels:
Monitoring DNS entropy levels helps identify unusual or random patterns, which can indicate the use of a Domain Generation Algorithm (DGA) by malware.

**Example:** If a domain shows a high level of randomness in its structure (e.g., `abcd1234.xyz`), it may be generated by malware using a DGA to avoid detection.

### More Data Sent Than Received Over HTTP/SSL:
To detect more data sent to an IP or domain over HTTP/SSL than received, a query can sum the bytes sent and compare it to bytes received, identifying potential data exfiltration.
```sql
SELECT ip, SUM(bytes_sent) 
FROM http_ssl_logs 
GROUP BY ip 
HAVING SUM(bytes_sent) > SUM(bytes_received);
```
**Explanation:** This query calculates the total bytes sent and received for each IP and identifies IPs where more data is being sent out, indicating possible data exfiltration.

## Section 2.2.2: Identifying Brute Force Attacks with Windows Logs

### Event Log ID for Failed Login Attempts:
Windows Event Log ID 4625 indicates failed login attempts, which can be a sign of brute force attacks due to multiple failed login attempts. The corresponding Sysmon Event ID for failed logon attempts is Sysmon Event ID 4625.

**Example:** Monitoring for Event ID 4625 in security logs can help identify repeated failed logon attempts from the same source, indicating a potential brute force attack.

### Event Log ID for Logoff Events:
Windows Event Log ID 4634 indicates logoff events, which can be useful in tracking user activity and potential unauthorized access. The corresponding Sysmon Event ID for logoff events is Sys

mon Event ID 2.

**Example:** Analyzing Event ID 4634 logs can help understand user logoff patterns and detect any unusual logoff activities that may indicate security issues.

### Event Log ID for New User Account Creation:
Windows Event Log ID 4720 indicates the creation of a new user account, which can be a sign of unauthorized account creation. The corresponding Sysmon Event ID for new user account creation is Sysmon Event ID 4720.

**Example:** Monitoring Event ID 4720 helps in identifying when new user accounts are created, especially if done outside of normal administrative procedures.

## Section 2.2.3: Identifying Lateral Movement with Windows Logs

### Event Log ID for Lateral Movement:
Windows Event Log ID 4648 indicates a logon attempt with explicit credentials, often seen in lateral movement using RDP (Remote Desktop Protocol). The corresponding Sysmon Event ID for explicit credential logon attempts is Sysmon Event ID 4648.

**Example:** Reviewing logs for Event ID 4648 can help detect lateral movement within a network, as attackers often use explicit credentials to access different systems.

## Section 3.3.2: Creating Signatures for Future Detection

### Late Night Connections:
High-volume file transfers late at night can indicate possible unauthorized access or data exfiltration attempts. Monitoring for unusual activity during off-hours is crucial.

**Example:** Analyzing network logs for large data transfers during late hours can help identify suspicious activities that may not be normal for typical business operations.

**Log Source:** Network traffic logs, firewall logs  
**Wireshark Filter Example:** 
```plaintext
ip.dst == <external_ip> and frame.len > 1500
```  
**Suricata Rule:** 
```plaintext
alert ip any any -> any any (msg:"High-volume data transfer during late hours"; threshold:type both, track by_dst, count 500, seconds 3600; classtype:data-exfiltration; sid:2000001;)
```  
**Snort Rule:** 
```plaintext
alert ip any any -> any any (msg:"High-volume data transfer during late hours"; threshold:type both, track by_dst, count 500, seconds 3600; classtype:data-exfiltration; sid:2000001;)
```

### Beaconing:
Beaconing activity is indicated by regular, periodic outbound connections to the same IP address, suggesting communication with a command and control server.

**Example:** Detecting consistent intervals of outbound connections to the same IP can indicate beaconing, which is commonly used by malware to communicate with its control servers.

**Log Source:** Network traffic logs, firewall logs  
**Wireshark Filter Example:** 
```plaintext
ip.dst == <c2_server_ip> and frame.time_delta >= 300
```  
**Suricata Rule:** 
```plaintext
alert ip any any -> any any (msg:"Periodic outbound connections indicating beaconing"; threshold:type both, track by_src, count 1, seconds 300; classtype:trojan-activity; sid:2000002;)
```  
**Snort Rule:** 
```plaintext
alert ip any any -> any any (msg:"Periodic outbound connections indicating beaconing"; threshold:type both, track by_src, count 1, seconds 300; classtype:trojan-activity; sid:2000002;)
```

### Long Standing Connections:
Long-standing connections can indicate a persistent threat or ongoing data exfiltration, as legitimate user connections are typically not long-standing.

**Example:** Monitoring network connections that remain open for extended periods can help identify persistent threats or data exfiltration activities.

**Log Source:** Network traffic logs, firewall logs  
**Wireshark Filter Example:** 
```plaintext
tcp.flags == 0x12 and frame.time_delta > 3600
```  
**Suricata Rule:** 
```plaintext
alert ip any any -> any any (msg:"Long-standing connection detected"; threshold:type both, track by_src, count 1, seconds 3600; classtype:policy-violation; sid:2000003;)
```  
**Snort Rule:** 
```plaintext
alert ip any any -> any any (msg:"Long-standing connection detected"; threshold:type both, track by_src, count 1, seconds 3600; classtype:policy-violation; sid:2000003;)
```

### Frequent DNS Requests for Non-Existent Domains:
Frequent DNS requests for non-existent domains (NXDOMAIN responses) suggest potential DNS tunneling or exfiltration attempts.

**Example:** High volumes of NXDOMAIN responses can indicate malware attempting to use DNS tunneling to exfiltrate data or communicate with external servers.

**Log Source:** DNS server logs, firewall logs  
**Wireshark Filter Example:** 
```plaintext
dns.flags.rcode == 3
```  
**Suricata Rule:** 
```plaintext
alert dns any any -> any any (msg:"High volume of NXDOMAIN responses detected"; threshold:type both, track by_src, count 10, seconds 60; classtype:dns-tunnel; sid:2000004;)
```  
**Snort Rule:** 
```plaintext
alert udp any any -> any 53 (msg:"High volume of NXDOMAIN responses detected"; threshold:type both, track by_src, count 10, seconds 60; classtype:dns-tunnel; sid:2000004;)
```

### Unusual Traffic Patterns:
Monitoring for unusual traffic patterns is important in network security to detect potential anomalies or malicious activities that deviate from normal behavior.

**Example:** Unusual spikes in traffic volume, changes in typical communication patterns, or unexpected protocol usage can all be indicators of a security issue requiring further investigation.

**Log Source:** Network traffic logs, firewall logs  
**Wireshark Filter Example:** 
```plaintext
(ip.src == <internal_ip> and frame.len > 1500) or (ip.dst == <internal_ip> and frame.len > 1500)
```  
**Suricata Rule:** 
```plaintext
alert ip any any -> any any (msg:"Unusual traffic pattern detected"; threshold:type both, track by_src, count 1, seconds 60; classtype:anomaly-detection; sid:2000005;)
```  
**Snort Rule:** 
```plaintext
alert ip any any -> any any (msg:"Unusual traffic pattern detected"; threshold:type both, track by_src, count 1, seconds 60; classtype:anomaly-detection; sid:2000005;)
```
