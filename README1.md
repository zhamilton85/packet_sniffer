## Packet Sniffer

A Python3-based packet sniffer for Linux, utilizing the Scapy library to capture and analyze network packets.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. **Clone the Repository:**

    ```
    git clone https://github.com/zhamilton85/packet_sniffer.git

    cd packet_sniffer
    ```

2. **Install Dependencies:**

    Ensure you have Python 3 and pip installed. Install the required Python packages using:

    ```
    pip install -r requirements.txt

    pip install scapy
    ```

## Usage

1. **Running the Packet Sniffer:**

    To run the packet sniffer, use the following command. Replace `<interface>` with the name of your network interface (e.g., `eth0`, `wlan0`).

    ```
    sudo python3 packet_sniffer.py -i <interface>
    ```

    Example:

    ```
    sudo python3 packet_sniffer.py -i eth0
    ```

2. **Script Explanation:**

    The `packet_sniffer.py` script captures network packets on the specified interface and prints basic information about each packet, such as source and destination IP addresses and ports.

    ```
    #!/usr/bin/env python3
    from scapy.all import *

    def packet_callback(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print(f"Source IP: {src_ip} --> Destination IP: {dst_ip}")

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                print(f"Source Port: {src_port} --> Destination Port: {dst_port}")
                print(f"TCP Packet:\n{packet.summary()}\n")
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"Source Port: {src_port} --> Destination Port: {dst_port}")
                print(f"UDP Packet:\n{packet.summary()}\n")
            else:
                print(f"Other IP Packet:\n{packet.summary()}\n")

    # Replace 'eth0' with your network interface
    network_interface = 'eth0'

    print(f"Sniffing packets on interface {network_interface}...\n")
    sniff(iface=network_interface, prn=packet_callback, store=0)
    ```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

1. Fork the Repository
2. Create a Feature Branch (`git checkout -b feature-branch`)
3. Commit Your Changes (`git commit -m 'Add new feature'`)
4. Push to the Branch (`git push origin feature-branch`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.