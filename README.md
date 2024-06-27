### **Packet Sniffer Using Scapy**

This project is a packet sniffer written in Python3, utilizing the Scapy library. The packet sniffer is designed to capture and analyze network packets on Linux systems.

### **Features**

Capture packets on a specified network interface
Display detailed information about captured packets
Filter packets based on criteria (e.g., IP addresses, protocols, ports)
Save captured packets to a file
Read and analyze packets from a saved file
Requirements
Python 3.6+
Linux operating system
Scapy library

### **Installation**

**Clone the repository:**

git clone https://github.com/zhamilton85/packet_sniffer.git

cd packet_sniffer


**Install the required libraries:**

pip install -r requirements.txt


**Ensure you have Scapy installed:**

pip install scapy


**Run the packet sniffer:**

sudo python3 packet_sniffer.py

_Note: Running the packet sniffer requires root privileges._


### **Usage**

**Start capturing packets on a specific interface:**

sudo python3 packet_sniffer.py -i <interface>

_Replace <interface> with the name of the network interface you want to capture packets from (e.g., eth0, wlan0)._


**Filter packets based on criteria:**


**Capture only TCP packets:**

sudo python3 packet_sniffer.py -i <interface> -f "tcp"


**Save captured packets to a file:**

sudo python3 packet_sniffer.py -i <interface> -o packets.pcap


**Read packets from a saved file:**

sudo python3 packet_sniffer.py -r packets.pcap


### **Contributing**
Contributions are welcome! Please fork the repository and submit a pull request with your changes. For major changes, open an issue to discuss what you would like to change.

### **License**
This project is licensed under the MIT License - see the LICENSE file for details.

### **Acknowledgments**
[Scapy](https://scapy.net/) - The powerful Python library used for packet manipulation and analysis.

### **Disclaimer**
This tool is intended for educational and ethical use only. Ensure you have proper authorization before using it to capture network traffic on any network.
