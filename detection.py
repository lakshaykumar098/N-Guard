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

        if len(syn_tracker[src_ip]) > 50: # update it to 100
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

        if len(ack_tracker[src_ip]) > 50: # update it to 100
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
        port_scan_tracker[src_ip] = [(p, t) for p, t in port_scan_tracker[src_ip] if current_time - t < 5]

        if len(set(p for p, t in port_scan_tracker[src_ip])) > 5: # update it to 10
            return "Port Scanning Attempt Detected"
    return None

# =====================
# ICMP Flood Detection
# =====================
def detect_icmp_flood(packet):
    """
    Detects ICMP (ping) flood attacks (DDoS).
    Threshold: More than 200 ICMP packets in 2 seconds.
    """
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # Echo Request (ping)
        src_ip = packet[IP].src
        current_time = time.time()
        icmp_tracker[src_ip].append(current_time)
        icmp_tracker[src_ip] = [t for t in icmp_tracker[src_ip] if current_time - t < 2]

        if len(icmp_tracker[src_ip]) > 50: #Update it to 200
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
    Threshold: More than 50 DNS requests in 2 seconds from the same IP.
    """
    if packet.haslayer(UDP) and packet[UDP].dport == 53:
        src_ip = packet[IP].src
        current_time = time.time()
        dns_tracker[src_ip].append(current_time)
        dns_tracker[src_ip] = [t for t in dns_tracker[src_ip] if current_time - t < 2]

        if len(dns_tracker[src_ip]) > 20: # update it to 50
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

        if len(http_tracker[src_ip]) > 20: # update it to 50
            return "DDoS Attack: HTTP Flood Detected"
    return None

# =====================
# Brute Force Login Detection
# =====================
def detect_brute_force_login(packet):
    """
    Detects brute-force login attempts (e.g., SSH).
    Threshold: More than 5 login attempts in 10 seconds.
    """
    if packet.haslayer(TCP) and packet[TCP].dport == 22:  # SSH port
        src_ip = packet[IP].src
        current_time = time.time()
        login_attempt_tracker[src_ip].append(current_time)
        login_attempt_tracker[src_ip] = [t for t in login_attempt_tracker[src_ip] if current_time - t < 10]

        if len(login_attempt_tracker[src_ip]) > 3: # update it to 5
            return "Brute Force Login Attempt Detected"
    return None


# =====================
# Reverse Shell Detection
# =====================
def detect_reverse_shell(packet):
    """
    Detects reverse shell connections by monitoring outbound connections to high ports.
    Threshold: More than 2 connections to high ports in 10 seconds.
    """
    if packet.haslayer(TCP) and 40000 <= packet[TCP].dport <= 65535:
        src_ip = packet[IP].src
        current_time = time.time()
        reverse_shell_tracker[src_ip].append(current_time)
        reverse_shell_tracker[src_ip] = [t for t in reverse_shell_tracker[src_ip] if current_time - t < 5] # update it to 10

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
        or detect_brute_force_login(packet)
        or detect_reverse_shell(packet)
        or detect_malformed_packet(packet)
    )
