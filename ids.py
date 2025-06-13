from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict
import time

# Trackers for different types of suspicious activities
port_scan_tracker = defaultdict(list)
icmp_tracker = defaultdict(list)
dns_tracker = defaultdict(list)
http_tracker = defaultdict(list)
login_attempt_tracker = defaultdict(list)
syn_tracker = defaultdict(list)
ack_tracker = defaultdict(list)
xmas_scan_tracker = defaultdict(list)
reverse_shell_tracker = defaultdict(list)
ftp_tracker=defaultdict(list)
telnet_tracker=defaultdict(list)
smb_tracker=defaultdict(list)

# =====================
# SYN Flood Detection
# =====================
def detect_syn_flood(packet):
    """
    Detects SYN flood attacks (DDoS) by monitoring SYN packet rates.
    Threshold: More than 100 SYN packets from a single IP in 2 seconds.
    """
    if packet.haslayer(TCP) and packet[TCP].flags == "S":  # SYN flag
        src_ip = packet[IP].src
        current_time = time.time()
        syn_tracker[src_ip].append(current_time)
        syn_tracker[src_ip] = [t for t in syn_tracker[src_ip] if current_time - t < 2]

        if len(syn_tracker[src_ip]) > 50:
            return "DDoS Attack: SYN Flood Detected"
    return None

# =====================
# ACK Flood Detection
# =====================
def detect_ack_flood(packet):
    """
    Detects ACK flood attacks (DDoS) by monitoring excessive ACK packets.
    Threshold: More than 100 ACK packets in 2 seconds from a single IP.
    """
    if packet.haslayer(TCP) and packet[TCP].flags == "A":  # ACK flag
        src_ip = packet[IP].src
        current_time = time.time()
        ack_tracker[src_ip].append(current_time)
        ack_tracker[src_ip] = [t for t in ack_tracker[src_ip] if current_time - t < 2]

        if len(ack_tracker[src_ip]) > 50: 
            return "DDoS Attack: ACK Flood Detected"
    return None

# =====================
# Port Scan Detection
# =====================
def detect_port_scan(packet):
    """
    Detects port scanning attempts by identifying rapid access to multiple ports.
    Threshold: More than 15 unique ports accessed in 10 seconds.
    """
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()
        port_scan_tracker[src_ip].append((dst_port, current_time))
        port_scan_tracker[src_ip] = [(p, t) for p, t in port_scan_tracker[src_ip] if current_time - t < 10] 

        if len(set(p for p, t in port_scan_tracker[src_ip])) > 15:
            return "Port Scanning Attempt Detected"
    return None

# =====================
# ICMP Flood Detection
# =====================
def detect_icmp_flood(packet):
    """
    Detects ICMP (ping) flood attacks (DDoS).
    Threshold: More than 200 ICMP packets in 5 seconds.
    """
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # Echo Request (ping)
        src_ip = packet[IP].src
        current_time = time.time()
        icmp_tracker[src_ip].append(current_time)
        icmp_tracker[src_ip] = [t for t in icmp_tracker[src_ip] if current_time - t < 5]

        if len(icmp_tracker[src_ip]) > 50:
            return "DDoS Attack: ICMP Flood Detected"
    return None

# =====================
# XMAS Scan Detection
# =====================
def detect_xmas_scan(packet):
    """
    Detects XMAS scans (TCP packets with all flags set).
    """
    if packet.haslayer(TCP) and packet[TCP].flags == 41:  # XMAS scan
        return "Reconnaissance: XMAS Scan Detected"
    return None

# =====================
# TCP Null Scan Detection (Added)
# =====================
def detect_tcp_null_scan(packet):
    """
    Detects TCP Null scans (TCP packets with no flags set).
    """
    if packet.haslayer(TCP) and packet[TCP].flags == 0:  # No flags set
        return "Reconnaissance: TCP Null Scan Detected"
    return None

# =====================
# DNS Amplification Detection
# =====================
def detect_dns_amplification(packet):
    """
    Detects DNS amplification attacks.
    Threshold: More than 50 DNS requests in 5 seconds from the same IP.
    """
    if packet.haslayer(UDP) and packet[UDP].dport == 53:
        src_ip = packet[IP].src
        current_time = time.time()
        dns_tracker[src_ip].append(current_time)
        dns_tracker[src_ip] = [t for t in dns_tracker[src_ip] if current_time - t < 5]

        if len(dns_tracker[src_ip]) > 50: 
            return "DNS Amplification Attack Detected"
    return None

# =====================
# HTTP Flood Detection
# =====================
def detect_http_flood(packet):
    """
    Detects HTTP/HTTPS flood attacks (DDoS).
    Threshold: More than 50 HTTP requests in 2 seconds.
    """
    if packet.haslayer(TCP) and packet[TCP].dport in [80, 443]:  # HTTP/HTTPS
        src_ip = packet[IP].src
        current_time = time.time()
        http_tracker[src_ip].append(current_time)
        http_tracker[src_ip] = [t for t in http_tracker[src_ip] if current_time - t < 2]

        if len(http_tracker[src_ip]) > 50:
            return "DDoS Attack: HTTP Flood Detected"
    return None

# =====================
# Brute Force Login Detection
# =====================
def detect_ssh_brute_force_login(packet):
    """
    Detects brute-force login attempts (e.g., SSH).
    Threshold: More than 5 login attempts in 10 seconds.
    """
    if packet.haslayer(TCP) and packet[TCP].dport == 22:  # SSH port
        src_ip = packet[IP].src
        current_time = time.time()
        login_attempt_tracker[src_ip].append(current_time)
        login_attempt_tracker[src_ip] = [t for t in login_attempt_tracker[src_ip] if current_time - t < 10]

        if len(login_attempt_tracker[src_ip]) > 5:
            return "SSH Brute Force Login Attempt Detected"
    return None

# =====================
# FTP Brute Force Detection
# =====================
def detect_ftp_brute_force(packet):
    """
    Detects FTP brute force login attempts.
    Threshold: More than 5 login attempts in 10 seconds.
    """
    if packet.haslayer(TCP) and packet[TCP].dport == 21:  # FTP port
        src_ip = packet[IP].src
        current_time = time.time()
        
        ftp_tracker[src_ip].append(current_time)
        ftp_tracker[src_ip] = [t for t in ftp_tracker[src_ip] if current_time - t < 10]

        if len(ftp_tracker[src_ip]) > 5: 
            return "FTP Brute Force Login Attempt Detected"
    return None

# =====================
# Telnet Brute Force Detection
# =====================
def detect_telnet_brute_force(packet):
    """
    Detects Telnet brute force login attempts.
    Threshold: More than 5 login attempts in 10 seconds.
    """
    if packet.haslayer(TCP) and packet[TCP].dport == 23:  # Telnet port
        src_ip = packet[IP].src
        current_time = time.time()
    
        telnet_tracker[src_ip].append(current_time)
        telnet_tracker[src_ip] = [t for t in telnet_tracker[src_ip] if current_time - t < 10]

        if len(telnet_tracker[src_ip]) > 5:
            return "Telnet Brute Force Login Attempt Detected"
    return None

# =====================
# SMB Brute Force Detection
# =====================
def detect_smb_brute_force(packet):
    """
    Detects SMB brute force login attempts.
    Threshold: More than 5 login attempts in 10 seconds.
    """
    if packet.haslayer(TCP) and packet[TCP].dport == 445:  # SMB port
        src_ip = packet[IP].src
        current_time = time.time()
        
        smb_tracker[src_ip].append(current_time)
        smb_tracker[src_ip] = [t for t in smb_tracker[src_ip] if current_time - t < 10]

        if len(smb_tracker[src_ip]) > 5:
            return "SMB Brute Force Login Attempt Detected"
    return None



# =====================
# Reverse Shell Detection
# =====================
def detect_reverse_shell(packet):
    """
    Detects reverse shell connections by monitoring outbound connections to high ports.
    Threshold: More than 2 connections to high ports in 10 seconds.
    """
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        current_time = time.time()
        
        # List of common reverse shell ports (this list can be expanded as needed)
        reverse_shell_ports = [
            4000, 4444, 5555, 6666, 12345, 31337, 44445, 8000, 8080, 2000, 
            3389, 2222, 1080, 7777, 123, 49152, 65535
        ]
        
        # Check if the destination port is one of the reverse shell ports
        if packet[TCP].dport in reverse_shell_ports:
            # Track the timestamps of outbound packets to these ports
            reverse_shell_tracker[src_ip].append(current_time)
            
            # Filter out timestamps older than 10 seconds (increased time window)
            reverse_shell_tracker[src_ip] = [t for t in reverse_shell_tracker[src_ip] if current_time - t < 10] 

            # If more than 2 connections occur within 10 seconds, flag as a reverse shell
            if len(reverse_shell_tracker[src_ip]) > 2:
                return "Reverse Shell Detected"
    
    return None


# =====================
# Malformed Packet Detection
# =====================
def detect_malformed_packet(packet):
    """
    Detects malformed packets (e.g., IP packets with missing length).
    """
    try:
        if packet.haslayer(IP) and not packet[IP].len:
            return "Malformed Packet Detected"
    except Exception:
        return "Malformed Packet Detected"
    return None

# =====================
# Main Categorization Function
# =====================
def categorize_threat(packet):
    """
    Combines all detection functions to identify potential threats.
    """
    return (
        detect_syn_flood(packet)
        or detect_ack_flood(packet)
        or detect_port_scan(packet)
        or detect_icmp_flood(packet)
        or detect_xmas_scan(packet)
        or detect_tcp_null_scan(packet)  
        or detect_dns_amplification(packet)
        or detect_http_flood(packet)
        or detect_ssh_brute_force_login(packet)
        or detect_ftp_brute_force(packet)
        or detect_telnet_brute_force(packet)  
        or detect_smb_brute_force(packet) 
        or detect_reverse_shell(packet)
        or detect_malformed_packet(packet)
    )
