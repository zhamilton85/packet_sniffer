from scapy.all import *
import argparse

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

def main():
    parser = argparse.ArgumentParser(description="A simple packet sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on (e.g., eth0, wlan0)")
    args = parser.parse_args()
    
    print(f"Sniffing packets on interface {args.interface}...\n")
    sniff(iface=args.interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
