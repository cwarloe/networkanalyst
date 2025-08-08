# Study Guide for Network Analyst Senior - Test 2
## Section 1.3.3: Initial Exploitation

### HTTP GET Request Brute Force Attack
An HTTP GET request brute force attack can be identified through various indicators such as increased traffic on specific URLs or endpoints, a high volume of GET requests from a single IP address, and access logs showing repeated attempts to access sensitive resources. These patterns suggest systematic attempts to guess or access unauthorized information.

**Log Source:** Web server access logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">http.request.method == "GET"
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert http any any -> any any (msg:"HTTP GET brute force attack"; flow:to_server,established; threshold:type threshold, track by_src, count 100, seconds 60; classtype:web-application-attack; sid:1000001;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any 80 (msg:"HTTP GET brute force attack"; flow:to_server,established; content:"GET"; http_method; threshold:type threshold, track by_src, count 100, seconds 60; classtype:web-application-attack; sid:1000001;)
</pre>

### HTTP POST Request Brute Force Attack
Detecting an HTTP POST request brute force attack involves looking for unusual patterns in form submissions, such as numerous submissions with different credential combinations. This indicates systematic attempts to breach security through brute force.

**Log Source:** Web server access logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">http.request.method == "POST"
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert http any any -> any any (msg:"HTTP POST brute force attack"; flow:to_server,established; threshold:type threshold, track by_src, count 100, seconds 60; classtype:web-application-attack; sid:1000002;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any 80 (msg:"HTTP POST brute force attack"; flow:to_server,established; content:"POST"; http_method; threshold:type threshold, track by_src, count 100, seconds 60; classtype:web-application-attack; sid:1000002;)
</pre>

### Cross-Site Scripting (XSS) Reflected Attack
Vulnerability to reflected XSS attacks can be identified by unsanitized user input echoed back in HTTP responses and detection of encoded or obfuscated JavaScript in responses. These signs indicate potential for malicious script execution.

**Log Source:** Web server access logs, application logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">http contains "<script>"
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert http any any -> any any (msg:"XSS Reflected Attack"; flow:to_server,established; content:"<script>"; nocase; classtype:web-application-attack; sid:1000003;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any 80 (msg:"XSS Reflected Attack"; flow:to_server,established; content:"<script>"; nocase; classtype:web-application-attack; sid:1000003;)
</pre>

### Cross-Site Scripting (XSS) Persistent Attack
Persistent XSS attacks involve ongoing malicious scripts appearing on web pages. These can be identified through user reports or automated scans detecting persistent malicious content.

**Log Source:** Web server access logs, application logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">http contains "<script>"
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert http any any -> any any (msg:"XSS Persistent Attack"; flow:to_server,established; content:"<script>"; nocase; classtype:web-application-attack; sid:1000004;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any 80 (msg:"XSS Persistent Attack"; flow:to_server,established; content:"<script>"; nocase; classtype:web-application-attack; sid:1000004;)
</pre>

## Section 1.4.1: Actions on Target

### Command and Control (C2)
C2 activity can be identified by monitoring for encrypted or obfuscated communication patterns, which are common in C2 traffic to evade detection.

**Log Source:** Network traffic logs, firewall logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">ssl
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any any (msg:"Possible C2 Communication"; flow:to_server,established; content:"|16 03|"; depth:2; classtype:trojan-activity; sid:1000005;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any any (msg:"Possible C2 Communication"; flow:to_server,established; content:"|16 03|"; depth:2; classtype:trojan-activity; sid:1000005;)
</pre>

### Lateral Movement
Lateral movement within a network can be identified by unusual authentication attempts and remote desktop protocol (RDP) connections from unexpected sources. These signs suggest an attacker is trying to move laterally within the network.

**Log Source:** Windows Event Logs, Sysmon logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">tcp.port == 3389
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any 3389 (msg:"Possible Lateral Movement via RDP"; flow:to_server,established; content:"USER"; nocase; classtype:policy-violation; sid:1000006;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any 3389 (msg:"Possible Lateral Movement via RDP"; flow:to_server,established; content:"USER"; nocase; classtype:policy-violation; sid:1000006;)
</pre>

### Data Exfiltration
Data exfiltration attempts can be detected by monitoring for large or unusual outbound data transfers. This indicates that sensitive data may be leaving the network.

**Log Source:** Network traffic logs, data transfer logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">ip.dst == <external_ip> and frame.len > 1500
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert ip any any -> any any (msg:"Large Outbound Data Transfer"; flow:to_server,established; dsize:>1500; classtype:data-theft; sid:1000007;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert ip any any -> any any (msg:"Large Outbound Data Transfer"; flow:to_server,established; dsize:>1500; classtype:data-theft; sid:1000007;)
</pre>

### Obfuscation
Common techniques for network traffic obfuscation include encoding or encrypting payloads and using steganography to hide data within innocuous files. These methods make it harder to detect malicious activity.

**Log Source:** Network traffic logs, IDS/IPS logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">ssl.handshake.type == 1
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert ip any any -> any any (msg:"Obfuscated Traffic Detected"; flow:to_server,established; content:"|16 03|"; depth:2; classtype:obfuscation; sid:1000008;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert ip any any -> any any (msg:"Obfuscated Traffic Detected"; flow:to_server,established; content:"|16 03|"; depth:2; classtype:obfuscation; sid:1000008;)
</pre>

### Multi-Stage Malware Deployment
Multi-stage malware deployment typically involves the initial delivery of a downloader or dropper component, followed by the subsequent retrieval of additional payload components from external servers. Immediate execution of the full malware payload is not characteristic of multi-stage deployment.

**Log Source:** Endpoint detection logs, antivirus logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">http.request.uri contains "/download"
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert http any any -> any any (msg:"Multi-Stage Malware Download"; flow:to_server,established; content:"/download"; nocase; classtype:malware-download; sid:1000009;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any 80 (msg:"Multi-Stage Malware Download"; flow:to_server,established; content:"/download"; nocase; classtype:malware-download; sid:1000009;)
</pre>

### Persistence
Persistence mechanisms on a compromised system can be identified by attempts to create or modify system services or scheduled tasks, communication with command and control infrastructure for periodic check-ins, and exploitation of vulnerabilities to maintain access.

**Log Source:** Windows Event Logs, Sysmon logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">dns.qry.name == "example.com"
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert dns any any -> any any (msg:"C2 Domain Check-in"; dns_query; content:"example.com"; nocase; classtype:command-and-control; sid:1000010;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert udp any any -> any 53 (msg:"C2 Domain Check-in"; content:"example.com"; nocase; classtype:command-and-control; sid:1000010;)
</pre>

## Section 1.4.7: Hiding C2 and Data Exfiltration in HTTP Requests

iding C2 and Data Exfiltration in HTTP Requests

Actors can hide command and control (C2) communication and data exfiltration within HTTP requests by embedding C2 commands or data within the URL path or query parameters. This method conceals malicious activity within legitimate HTTP requests.

**Log Source:** Web server access logs, firewall logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">http.request.uri contains "/cmd="
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert http any any -> any any (msg:"Hidden C2 in HTTP Request"; flow:to_server,established; content:"/cmd="; nocase; classtype:command-and-control; sid:1000011;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any 80 (msg:"Hidden C2 in HTTP Request"; flow:to_server,established; content:"/cmd="; nocase; classtype:command-and-control; sid:1000011;)
</pre>

## Section 1.4.8: Anomalous Web Connection Behaviors

Repeated access attempts to restricted resources within a web application usually suggest brute-force attacks or other unauthorized access efforts, rather than legitimate user activity or maintenance.

**Log Source:** Web server access logs, firewall logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">http.request.uri contains "/admin"
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert http any any -> any any (msg:"Repeated Access to Restricted Resource"; flow:to_server,established; content:"/admin"; nocase; threshold:type threshold, track by_src, count 10, seconds 60; classtype:web-application-attack; sid:1000012;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any 80 (msg:"Repeated Access to Restricted Resource"; flow:to_server,established; content:"/admin"; nocase; threshold:type threshold, track by_src, count 10, seconds 60; classtype:web-application-attack; sid:1000012;)
</pre>

## Section 1.4.9: DNS Spoofing

DNS spoofing exploits vulnerabilities in DNS records by manipulating DNS records to redirect legitimate traffic to malicious websites or servers, compromising network security.

**Log Source:** DNS server logs, firewall logs  
**Wireshark Filter Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">dns.flags == 0x8180
</pre>  
**Suricata Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert dns any any -> any any (msg:"DNS Spoofing Detected"; dns_query; content:"malicious.com"; nocase; classtype:dns-spoof; sid:1000013;)
</pre>  
**Snort Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert udp any any -> any 53 (msg:"DNS Spoofing Detected"; content:"malicious.com"; nocase; classtype:dns-spoof; sid:1000013;)
</pre>

## Section 2.1.6: Using Variables in an IDS

Variables in an IDS can be utilized to define IP address ranges for monitoring. This allows for flexible and reusable rule creation without hardcoding specific values.

**Example:** If you want to monitor traffic within a specific internal network, you can define a variable such as `$HOME_NET` to represent the internal IP address range (e.g., `10.0.0.0/24`). This variable can then be used in IDS rules to target only the internal network traffic.

**Query Example:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">var HOME_NET [10.0.0.0/24]
alert tcp $HOME_NET any -> any any (msg:"Internal Network Traffic Detected"; sid:1000001;)
</pre>

## Section 2.1.10: Configuring $HOME_NET_IPs

Configuring `$HOME_NET_IPs` helps in differentiating between internal and external network traffic, aiding in accurate analysis and security monitoring.

**Example:** By defining `$HOME_NET` as your internal network (e.g., `192.168.1.0/24`), IDS rules can be set to specifically watch for traffic originating from or destined to this network.

**Usage in Rules:** This differentiation helps in focusing the analysis on potentially suspicious traffic within the internal network, ignoring external, irrelevant traffic.

## Section 2.1.14: Detecting IRC Activity

A Snort rule can be used to alert if IRC ports (6667-7001) are being used. This rule targets traffic using IRC ports and specific IRC-related content, indicating potential unauthorized IRC activity.

**Example Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> any $IRC_PORTS (msg:"IRC Activity Detected"; flow:to_server,established; content:"USER"; nocase; content:"PRIVMSG"; nocase; classtype:policy-violation; sid:1000013;)
</pre>

**Explanation:** This rule will trigger an alert if it detects traffic on IRC ports containing IRC commands such as `USER` and `PRIVMSG`.

## Section 2.1.15: Monitoring Communications with Malicious Domains

A Snort rule designed to alert on communications to or from a known malicious domain (e.g., "badwebsite.com") helps detect and mitigate potential threats by targeting specified variables.

**Example Rule:** 
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">alert tcp any any -> $BAD_WEBSITE any (msg:"Communication with badwebsite.com"; flow:to_server,established; classtype:policy-violation; sid:1000014;)
</pre>

**Explanation:** This rule will generate an alert if any communication is detected between your network and the specified malicious domain.

## Section 2.1.16: Suricata Log Files

Suricata logs are stored in the `/var/log/suricata/` directory, with `eve.json` being the primary log file for event data.

**Log File Example:**
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">/var/log/suricata/eve.json
</pre>

**Explanation:** This file contains detailed logs of all events detected by Suricata, which can be analyzed to identify and investigate security incidents.

## Section 2.2.1: Writing Queries for Detection

### Brute Force Attacks over HTTP:
To detect brute force attacks over HTTP, a query can be used to identify IPs with a high number of GET requests, which is a common pattern in brute force attacks.
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">SELECT ip, COUNT(*) 
FROM http_logs 
WHERE method = 'GET' 
GROUP BY ip 
HAVING COUNT(*) > 100;
</pre>
**Explanation:** This query identifies IP addresses with more than 100 GET requests, which is indicative of a potential brute force attack.

### Shortened URL Redirects:
To find shortened URLs redirecting the customer to another domain, a query can be used to look for URLs containing 'bit.ly', indicating a potential redirect.
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">SELECT * 
FROM http_logs 
WHERE url LIKE '%bit.ly%';
</pre>
**Explanation:** This query filters the HTTP logs to find entries where the URL contains 'bit.ly', which is a common URL shortening service.

### More HTTP POST Requests than GET Requests:
To detect more HTTP POST requests than GET requests, a query can be used to compare the counts of each method and identify when POST requests exceed GET requests.
<pre style="white-space: pre-wrap; font-family: monospace; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">SELECT method, COUNT(*) 
FROM http_logs 
WHERE method IN ('POST', 'GET') 
GROUP BY method 
HAVING method = 'POST' AND COUNT(*) > 
  (SELECT COUNT(*) 
   FROM http_logs 
   WHERE method = 'G
