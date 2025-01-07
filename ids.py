import os
from scapy.all import sniff  # For sniffing packets
from scapy.layers.inet import IP  # Ensure IP is imported
from detection import categorize_threat  # Threat detection logic
from logger import log_alert,initialize_database ,send_email_alert  # For logging detected threats
from utils import block_ip, is_ip_blocked, check_ip_with_virustotal  # For IP blocking and VirusTotal

def process_packet(packet):
    """
    Processes each packet captured by the sniffer.
    Detects threats, logs alerts, and blocks malicious IPs.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src

        # Skip processing if the IP is already blocked
        if is_ip_blocked(src_ip):
           return

        # Categorize the threat
        threat = categorize_threat(packet)
        if threat:
            # Check IP reputation using VirusTotal
            reputation = check_ip_with_virustotal(src_ip)
            if "Malicious" in reputation:
                threat += f" | Reputation: {reputation}"

            # Log the alert, send mail and block the IP
            log_alert(src_ip, threat)
            block_ip(src_ip)
            send_email_alert(src_ip, threat)

def start_sniffer():
    """
    Starts the packet sniffer to monitor network traffic.
    """
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    sniff(iface="eth0", filter="ip", prn=process_packet) # Captues each IP packet on eth0 interface and pass it to process_packet function


if __name__ == "__main__":
    initialize_database()
    os.system("sudo ip link set eth0 promisc on")
    try:
        start_sniffer()
    except KeyboardInterrupt:
        print("\nPacket sniffer stopped.")

