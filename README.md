# Network Traffic Analysis with Brim

This project demonstrates how I performed network traffic analysis using **Brim** to investigate various types of network activity, including DNS queries, NTP logs, Suricata alerts, and more. Throughout the project, I explored packet capture (PCAP) data and extracted crucial information for security investigations.

## Objective

To analyze network traffic from a provided PCAP file using **Brim**, identify specific patterns of malicious activity, and respond to a series of investigative queries related to DNS logs, NTP logs, Suricata alerts, and port usage.

## Skills Learned

- **Network Traffic Analysis**: Using Brim to analyze PCAP files.
- **Querying with Zeek**: Extracting meaningful data from large PCAP datasets.
- **Cybersecurity Threat Detection**: Identifying potential threats such as **CobaltStrike** and **IcedID**.
- **Using MITRE ATT&CK Framework**: Cross-referencing detected alerts with known MITRE tactics.

## Tools Used

- **Brim**: For packet capture analysis and detailed log inspection.
- **Zeek**: A powerful tool for network traffic analysis and security monitoring.

## Steps

### 1. Analyze DNS Logs
   - Processed the `sample.pcap` file and looked at DNS logs.
   - Found the first **DNS log** and identified the `qclass_name` as `C_INTERNET`.

   ![DNS Log Analysis](https://via.placeholder.com/400x200)

### 2. Investigate NTP Logs
   - Identified the **NTP log** and found that the duration of the log was `0.005 seconds`.

   ![NTP Log Duration](https://via.placeholder.com/400x200)

### 3. STATS Packet Analysis
   - Inspected the STATS log and determined the `reassem_tcp_size` to be **540**.

   ![STATS Log Analysis](https://via.placeholder.com/400x200)

### 4. GIF File Detection
   - Investigated the `gif` files and found the file `cat01_with_hidden_text.gif`.

   ![GIF Detection](https://via.placeholder.com/400x200)

### 5. City Name Detection from conn log
   - Used the following command to identify the number of city names:
     ```
     _path=="conn" | cut geo.resp.country_code, geo.resp.region, geo.resp.city
     ```
   - Discovered **2 cities**: `Eppelborn` and one other city.

   ![City Name Detection](https://via.placeholder.com/400x200)

### 6. Suricata Alerts
   - Queried **Suricata alerts** using the command:
     ```
     event_type=="alert" alert.severity:1
     ```
   - Identified the signature ID for "Potential Corporate Privacy Violation" as `2,012,887`.

   ![Suricata Alert Investigation](https://via.placeholder.com/400x200)

### 7. CobaltStrike Connections on Port 443
   - Executed the following query to determine the number of connections:
     ```
     _path == "conn" | where id.resp_h == 104.168.44.45 and id.resp_p == 443 | count() by id.resp_p
     ```
   - Found **328 connections** using port `443`.

   ![CobaltStrike Detection](https://via.placeholder.com/400x200)

### 8. Secondary C2 Channel Detection
   - Discovered the secondary C2 channel in the case, identified as **IcedID**.

   ![Secondary C2 Detection](https://via.placeholder.com/400x200)

### 9. Connections Using Port 19999
   - I used the following command to find the number of connections on port 19999:
     ```
     _path=="conn" | cut id.resp_p | where id.resp_p == 19999 | count()
     ```
   - Found **22 connections** on port `19999`.

   ![Port 19999 Connections](https://via.placeholder.com/400x200)

### 10. Service on Port 6666
   - I ran the following query to identify the service on port 6666:
     ```
     _path=="conn" | cut id.resp_p, service | where id.resp_p == 6666 | sort -r | uniq
     ```
   - The service was identified as **IRC**.

   ![IRC Service Detection](https://via.placeholder.com/400x200)

### 11. Transferred Bytes Analysis
   - To calculate the total bytes transferred, I used this command:
     ```
     _path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes | where id.resp_h == 101.201.172.235 and id.resp_p == 8888
     ```
   - Determined that a total of **3,729 bytes** were transferred to `101.201.172.235:8888`.

   ![Transferred Bytes Calculation](https://via.placeholder.com/400x200)

### 12. MITRE Tactic ID
   - Queried the data with the following command to identify the detected MITRE tactic ID:
     ```
     _path=="mitre" | cut alert.metadata.mitre_tactic_id
     ```
   - Identified the MITRE tactic ID as `TA0040`.

   ![MITRE Tactic ID](https://via.placeholder.com/400x200)

## Conclusion

This project showcased my ability to use **Brim** for network traffic analysis, investigate various log types, and detect potential threats based on the data. By querying and extracting key information from logs, I successfully identified suspicious network behavior and correlated the findings with known MITRE tactics.
