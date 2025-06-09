import os
from scapy.all import sniff  # For sniffing packets
from scapy.layers.inet import IP  # Ensure IP is imported
from ids import categorize_threat # Threat detection logic
from logger import log_alert,initialize_database ,send_email_alert  # For logging detected threats
from ips import block_ip, is_ip_blocked, check_ip_with_virustotal  # For IP blocking and VirusTotal
from colorama import Fore, Back, Style

# Define the IP address of your Host Machine
HOST_IP = "192.168.1.39"

# Define trusted local IPs or networks to ignore
LOCAL_IPS = [HOST_IP] 
TRUSTED_EXTERNAL_IPS = [] 

# Function to check if the IP is in the trusted list
def is_trusted_ip(ip):
    if ip in LOCAL_IPS or ip in TRUSTED_EXTERNAL_IPS:
        return True
    return False

def process_packet(packet):
    """
    Processes each packet captured by the sniffer.
    Detects threats, logs alerts, and blocks malicious IPs.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_dst = packet[IP].dst

        # Skip processing if the IP is already blocked
        if is_ip_blocked(src_ip):
           return
        
         # Ignore packets that are not destined for Kali Linux (i.e., they are meant for the Windows host)
        if ip_dst != HOST_IP:
            return 
        
        if is_trusted_ip(src_ip):
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
    print(Fore.GREEN + Back.BLACK +"""
                                                                
``````````````````````````````````````````````````_|      _|                _|_|_|                                      _|``````````````````````````````````````````````````````
``````````````````````````````````````````````````_|_|    _|              _|        _|    _|    _|_|_|  _|  _|_|    _|_|_|``````````````````````````````````````````````````````
``````````````````````````````````````````````````_|  _|  _|  _|_|_|_|_|  _|  _|_|  _|    _|  _|    _|  _|_|      _|    _|``````````````````````````````````````````````````````
``````````````````````````````````````````````````_|    _|_|              _|    _|  _|    _|  _|    _|  _|        _|    _|``````````````````````````````````````````````````````
``````````````````````````````````````````````````_|      _|                _|_|_|    _|_|_|    _|_|_|  _|          _|_|_|``````````````````````````````````````````````````````
``````````````````````````````````````````````````                                                                        ``````````````````````````````````````````````````````""" + Style.RESET_ALL)
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    sniff(iface="eth0", filter="ip", prn=process_packet)


if __name__ == "__main__":
    initialize_database()
    os.system("sudo ifconfig eth0 promisc")
    try:
        start_sniffer()
    except KeyboardInterrupt:
        print("\nPacket sniffer stopped.")

