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

   ![image6](https://github.com/user-attachments/assets/9b75186c-7b9f-4730-b7ad-f78f8ef0f937)


### 2. Investigate NTP Logs
   - Identified the **NTP log** and found that the duration of the log was `0.005 seconds`.

 ![image10](https://github.com/user-attachments/assets/d99b46f1-ca9a-421a-a82a-f5296b1a1bed)


### 3. STATS Packet Analysis
   - Inspected the STATS log and determined the `reassem_tcp_size` to be **540**.

   ![image21](https://github.com/user-attachments/assets/ca8176d7-ca47-482f-a0ec-f159dbefdf26)


### 4. GIF File Detection
   - Investigated the `gif` files and found the file `cat01_with_hidden_text.gif`.

   ![image18](https://github.com/user-attachments/assets/69f0d53d-84c0-47dd-8d0f-587b628a5578)


### 5. City Name Detection from conn log
   - Used the following command to identify the number of city names:
     ```
     _path=="conn" | cut geo.resp.country_code, geo.resp.region, geo.resp.city
     ```
   - Discovered **2 cities**: `Eppelborn` and one other city.

   ![image13](https://github.com/user-attachments/assets/428cb88a-55d4-4b00-bcd3-3d049818c028)


### 6. Suricata Alerts
   - Queried **Suricata alerts** using the command:
     ```
     event_type=="alert" alert.severity:1
     ```
   - Identified the signature ID for "Potential Corporate Privacy Violation" as `2,012,887`.

   ![image15](https://github.com/user-attachments/assets/be5a164b-115d-4a76-96e3-c2e82326344a)

### 7. CobaltStrike Connections on Port 443
   - Executed the following query to determine the number of connections:
     ```
     _path == "conn" | where id.resp_h == 104.168.44.45 and id.resp_p == 443 | count() by id.resp_p
     ```
   - Found **328 connections** using port `443`.

   ![image22](https://github.com/user-attachments/assets/26b3c1cd-d848-49bc-94b4-cc6abf64cf46)


### 8. Secondary C2 Channel Detection
   - Discovered the secondary C2 channel in the case, identified as **IcedID**.

   ![image24](https://github.com/user-attachments/assets/32bb1527-396c-458e-94f9-2cdb5f532c92)


### 9. Connections Using Port 19999
   - I used the following command to find the number of connections on port 19999:
     ```
     _path=="conn" | cut id.resp_p | where id.resp_p == 19999 | count()
     ```
   - Found **22 connections** on port `19999`.

   ![image11](https://github.com/user-attachments/assets/6c3dbbb1-9a1e-4ac8-9d5e-f86a6040eee3)


### 10. Service on Port 6666
   - I ran the following query to identify the service on port 6666:
     ```
     _path=="conn" | cut id.resp_p, service | where id.resp_p == 6666 | sort -r | uniq
     ```
   - The service was identified as **IRC**.

![image9](https://github.com/user-attachments/assets/cf56c158-a97e-4f46-8368-5bd8844e1429)

### 11. Transferred Bytes Analysis
   - To calculate the total bytes transferred, I used this command:
     ```
     _path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes | where id.resp_h == 101.201.172.235 and id.resp_p == 8888
     ```
   - Determined that a total of **3,729 bytes** were transferred to `101.201.172.235:8888`.

![image20](https://github.com/user-attachments/assets/1fefd78f-0599-4ebc-913a-2f6d521e284b)

### 12. MITRE Tactic ID
   - Queried the data with the following command to identify the detected MITRE tactic ID:
     ```
     _path=="mitre" | cut alert.metadata.mitre_tactic_id
     ```
   - Identified the MITRE tactic ID as `TA0040`.

![image16](https://github.com/user-attachments/assets/ebb15cf1-619c-4cb2-bc82-f994b3ab545f)

## Conclusion

This project showcased my ability to use **Brim** for network traffic analysis, investigate various log types, and detect potential threats based on the data. By querying and extracting key information from logs, I successfully identified suspicious network behavior and correlated the findings with known MITRE tactics.
