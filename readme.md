# **WhatsApp IP Tracker Tool**

This project is an **educational tool** designed to help cybersecurity enthusiasts understand how **peer-to-peer (P2P) communication** works during WhatsApp voice or video calls. It demonstrates how public IP addresses can be exposed when P2P connections are used.  

When making WhatsApp voice or video calls, the app typically prioritizes direct **peer-to-peer (P2P)** communication to minimize latency and improve call quality. By avoiding relay servers, both devices exchange their **public IP addresses** directly. However, this mechanism could lead to **IP address exposure**, which, in malicious hands, could be used for reconnaissance or other attacks.

This project aims to capture network traffic on a local network, filter out packets related to WhatsApp calls, and extract the public IP addresses of the devices participating in the call.

---

## **🌟 Motivation**

- **Understanding WhatsApp P2P Calling**: WhatsApp's calling feature avoids using a relay server to reduce latency, relying on P2P communication. This means the two participating devices must share their **public IP addresses**.
- **IP Exposure Risks**: While P2P improves performance, exposing public IPs can lead to potential security risks:
  - **Reconnaissance**: Malicious actors can use the IP to locate users geographically or identify their ISPs.
  - **Denial-of-Service (DoS) Attacks**: IP addresses can be targeted in DoS or DDoS attacks.
- **Education and Awareness**: This tool is designed to make users aware of how public IPs can be exposed during P2P communication and how attackers might leverage such information.

---

## **⚙️ Features**

- **Real-time Packet Sniffing**: Captures live network traffic to analyze packets exchanged during WhatsApp calls.
- **WhatsApp Traffic Filtering**: Filters packets related to WhatsApp based on known IP ranges and ports.
- **Network Interface Detection**: Allows users to view and select the network interface for sniffing.
- **Geolocation of IPs**: Retrieves geographical location data (country, city, latitude, and longitude) for captured IPs.
- **Report Generation**:
  - Captured IPs are saved to JSON and CSV reports for further analysis.
  - Full packet logs are stored in `.pcap` format for inspection using tools like Wireshark.

---

## **🚀 How It Works**

1. **Network Interface Selection**:  
   The tool first lists all available network interfaces. For example:
   ```plaintext
   Available network interfaces:
     [0] Ethernet
     [1] Wi-Fi
     [2] Loopback Pseudo-Interface 1
   ```
   The user selects the desired interface (e.g., `Wi-Fi`).

2. **Packet Sniffing**:  
   The tool begins sniffing network packets on the selected interface and filters traffic related to WhatsApp. WhatsApp packets are identified based on:
   - **IP Ranges**: Known WhatsApp IP ranges (e.g., `31.13.64.0/18`, `157.240.0.0/16`).
   - **Ports**: WhatsApp typically uses UDP with dynamic ports in the range `49152-65535`.

3. **IP Address Extraction**:  
   The tool extracts the source and destination IPs from the captured packets.

4. **Geolocation Analysis**:  
   Public IPs are analyzed using a geolocation database (e.g., MaxMind GeoLite2) to identify the country, city, latitude, and longitude of each IP.

5. **Report Generation**:  
   Captured data is saved as:
   - **JSON Report**: For programmatic analysis.
   - **CSV Report**: For easy visualization and sharing.
   - **PCAP File**: Full packet logs for detailed analysis using Wireshark.

---

## **📋 Setup and Installation**

Follow these steps to set up and run the project on your system:

### **1. Clone the Repository**
```bash
git clone https://github.com/arshadakl/Whatsapp-P2P-Traceroute.git
cd Whatsapp-P2P-Traceroute
```

### **2. Install Dependencies**
This project requires Python 3.7 or higher. Install the required Python libraries using:
```bash
pip install -r requirements.txt
```

### **3. Install Npcap**
- On Windows, you must install **Npcap** for Scapy to capture network packets.  
- Download and install it from [Npcap's official site](https://nmap.org/npcap/).  
  During installation:
  - Check the option **"Install Npcap in WinPcap API-compatible mode"**.
  - Allow non-administrator users to capture packets (if necessary).

---

## **💻 How to Run**

1. Open a terminal or command prompt in the project directory.

2. Run the script:
   ```bash
   python main.py
   ```

3. The script will display a list of available network interfaces:
   ```plaintext
   Available network interfaces:
     [0] Ethernet
     [1] Wi-Fi
     [2] Loopback Pseudo-Interface 1
   ```

4. Enter the number corresponding to the interface you want to use. For example:
   ```plaintext
   Enter the number of the interface you want to use: 1
   ```

5. The tool will start sniffing packets on the selected interface. Captured WhatsApp packets will be displayed in real-time, along with extracted IP addresses and geolocation data.

---


### **Sample Output**


```plaintext
Available network interfaces:
  [0] Ethernet
  [1] Wi-Fi
  [2] Loopback Pseudo-Interface 1

Enter the number of the interface you want to use: 1
[+] You selected: Wi-Fi

[*] Starting packet sniffing...
[+] Captured WhatsApp Packet: 192.168.1.101 -> 157.240.12.34
[+] Captured WhatsApp Packet: 192.168.1.102 -> 31.13.64.12
[+] IP: 157.240.12.34 - Menlo Park, United States (37.453, -122.181)
[+] IP: 31.13.64.12 - Dublin, Ireland (53.333, -6.248)
```

### **JSON Report**
```json
[
    {
        "ip": "157.240.12.34",
        "country": "United States",
        "city": "Menlo Park",
        "latitude": 37.453,
        "longitude": -122.181
    },
    {
        "ip": "31.13.64.12",
        "country": "Ireland",
        "city": "Dublin",
        "latitude": 53.333,
        "longitude": -6.248
    }
]
```

### **CSV Report**
```csv
ip,country,city,latitude,longitude
157.240.12.34,United States,Menlo Park,37.453,-122.181
31.13.64.12,Ireland,Dublin,53.333,-6.248
```

---

### **⚠️ Legal Disclaimer**

This tool is intended for **educational purposes only**. Unauthorized network sniffing or monitoring may violate privacy laws or terms of service agreements. Always ensure you have proper authorization before using this tool in any real-world environment. The authors are not responsible for misuse of this tool.

---
