import os
import requests
import subprocess

def is_ip_blocked(ip):
    """
    Checks if an IP is already blocked in iptables.
    """
    try:
        # List iptables rules and search for the IP
        result = subprocess.check_output(["sudo", "iptables", "-L", "-v", "-n"], text=True)
        return ip in result
    except Exception as e:
        print(f"Error checking iptables for IP {ip}: {e}")
        return False

def block_ip(ip):
    """
    Blocks a malicious IP address using iptables if not already blocked,
    and saves the updated rules.
    """

    try:
        # Add the rule to block the IP
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        print(f"Blocked IP: {ip}")

        # Save the updated rules to rules.v4
        os.system("sudo iptables-save > /etc/iptables/rules.v4")

    except Exception as e:
        print(f"Error blocking IP {ip}: {e}")


VIRUSTOTAL_API_KEY = "Your_Api_Key" # Add your VirusTotal Api Key Here

def check_ip_with_virustotal(ip):
    """
    Checks the reputation of an IP address using the VirusTotal API.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
        if malicious_count > 0:
            return f"Malicious (Count: {malicious_count})"
    return "Clean"
