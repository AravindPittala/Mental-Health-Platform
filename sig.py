import scapy.all as scapy
import re

# 🔹 List all network interfaces
def list_interfaces():
    interfaces = scapy.get_if_list()
    print("\n🔍 Available Network Interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx}: {iface}")
    return interfaces

# Select an interface (Modify index as needed)
interfaces = list_interfaces()
interface = interfaces[2]  # Change index as per system

# 🔹 Known Malicious Signatures (Modify/Add more)
malicious_ips = {"192.168.5.100", "172.16.20.5", "10.0.0.50"}
malicious_ports = {4444, 5555, 6667}  # Common malware backdoor ports
attack_signatures = [
    r"malicious shellcode",
    r"SQL Injection attempt",
    r"<script>alert('XSS')</script>",
    r"Remote Code Execution detected"
]

reserved_ips = {"192.168.1.4", "192.168.1.1", "192.168.1.7", "172.16.0.3"}

# Function to detect IP Spoofing
def check_ip_spoofing(source_ip, mac_address, known_mac):
    if mac_address != known_mac and source_ip not in reserved_ips:
        if re.match(r"^(10\.|192\.168\.|169\.254\.)", source_ip):
            print("🚨 Possible IP Spoofing using Private Networks detected!")
        elif source_ip.startswith("172.") and 16 <= int(source_ip.split(".")[1]) <= 31:
            print("🚨 Possible IP Spoofing using Private Networks detected!")

# Function to detect SYN-FIN attack
def check_syn_fin_attack(packet):
    if packet.haslayer(scapy.TCP):
        tcp_layer = packet[scapy.TCP]
        if tcp_layer.flags == 0b00000011:  # SYN and FIN both set
            print("🚨 SYN-FIN Attack Detected!")
            print(f"MAC Address of Attacker: {packet.src}")

# Function to detect NULL packet attack
def check_null_attack(packet):
    if packet.haslayer(scapy.TCP):
        tcp_layer = packet[scapy.TCP]
        if tcp_layer.flags == 0b00000000:  # No flags set
            print("🚨 NULL Packet Attack Detected!")
            print(f"MAC Address of Attacker: {packet.src}")

# Function to detect reserved bit attack
def check_reserved_bits(packet):
    if packet.haslayer(scapy.TCP):
        tcp_layer = packet[scapy.TCP]
        if tcp_layer.reserved > 0:
            print("🚨 Reserved Bit Attack Detected!")
            print(f"MAC Address of Attacker: {packet.src}")

# Function to detect invalid port numbers
def check_invalid_ports(packet):
    if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
        if packet.haslayer(scapy.TCP):
            src_port, dst_port = packet[scapy.TCP].sport, packet[scapy.TCP].dport
        else:
            src_port, dst_port = packet[scapy.UDP].sport, packet[scapy.UDP].dport

        if src_port == 0 or dst_port == 0:
            print("🚨 Port Zero Detected! This is suspicious.")
            print(f"MAC Address of Attacker: {packet.src}")

# Function to detect signature-based attacks
def check_signatures(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst

        # Check for Malicious IPs
        if ip_src in malicious_ips or ip_dst in malicious_ips:
            print(f"🚨 ALERT: Known Malicious IP detected: {ip_src} → {ip_dst}")
            return

    if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
        sport, dport = (packet[scapy.TCP].sport, packet[scapy.TCP].dport) if packet.haslayer(scapy.TCP) else (packet[scapy.UDP].sport, packet[scapy.UDP].dport)

        # Check for Malicious Ports
        if sport in malicious_ports or dport in malicious_ports:
            print(f"🚨 ALERT: Traffic on a known malicious port detected: {sport} → {dport}")
            return

    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load.decode(errors="ignore")

        # Check for Malicious Payloads
        for signature in attack_signatures:
            if re.search(signature, payload, re.IGNORECASE):
                print(f"🚨 ALERT: Malicious Signature Found! Pattern: {signature}")
                print(f"Payload: {payload}")
                return

# Function to process packets
def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        mac_src = packet.src

        print(f"\n📡 Packet captured from {ip_src} → {ip_dst} via {mac_src}")

        # Run security checks
        check_ip_spoofing(ip_src, mac_src, "00:1A:2B:3C:4D:5E")  # Replace with actual known MAC
        check_syn_fin_attack(packet)
        check_null_attack(packet)
        check_reserved_bits(packet)
        check_invalid_ports(packet)
        check_signatures(packet)  # Signature-based detection

# Start Sniffing on Selected Interface
print(f"\n📡 Sniffing on interface: {interface}...\n")
scapy.sniff(iface=interface, prn=process_packet, store=False)
