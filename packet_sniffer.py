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
