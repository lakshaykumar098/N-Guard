# N-Guard (Intrusion Detection and Prevention System)

Welcome to **N-Guard** – a robust Python-based Intrusion Detection and Prevention System (IDS/IPS) designed to monitor, detect, and respond to malicious activities within your network.

## **Features**

- **Packet Sniffing:** Captures and analyzes live network traffic using `scapy`.
- **Threat Detection:** Identifies various network attacks including SYN floods, ICMP floods, port scanning, reverse shells, and more.
- **Intrusion Prevention:** Blocks malicious IP addresses in real-time using `iptables`.
- **Email Notifications:** Sends real-time email alerts when threats are detected.
- **Logging:** Logs all detected threats to a SQLite database for easy review.

---

## **Project Structure**

```
N-Guard/
|
├── ids.py               # Core detection functions for network attacks
├── main.py              # Main script to run the N-Guard and sniff packets
├── logger.py            # Handles alert logging and email notifications
├── ips.py               # Core prevention function, responsible for blocking malicious IPs
├── delete_logs.py       # Script to clear or delete logs from the database
├── read_logs.py         # Script to read and display logs from the database
├── requirements.txt     # Dependencies required for the project
├── ids_logs.db          # SQLite database to store threat logs (optional)
└── README.md            # Project documentation
```

---

## **Pre-requisites**

Make sure your system meets the following requirements:

- Python 3.x
- Linux-based OS (with `iptables` support)
- Required libraries (install using `requirements.txt`)
- Admin/root access

---

## **Installation**

1. **Clone the repository:**

   ```bash
   git clone <repository-url>
   cd N-Guard
   ```

2. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Set up `iptables` for IP blocking:**

   ```bash
   sudo apt update
   sudo apt install iptables iptables-persistent
   ```

4. **Enable automatic rule persistence:**

   ```bash
   sudo systemctl enable netfilter-persistent
   sudo systemctl start netfilter-persistent
   ```

---

## **Usage**

### **Running the IDS**

1. Ensure you have root access.
2. Start the N-Guard by running:
   ```bash
   sudo python3 main.py
   ```
3. Press `Ctrl+C` to stop the packet sniffer.

### **Reading Logs**

View stored alerts:

```bash
python3 read_logs.py
```

### **Clearing Logs**

To delete all logs:

```bash
python3 delete_logs.py
```

---

## **Threats Detected**

The N-Guard can detect the following types of network attacks:

| **Attack Type**         | **Description**                                     |
| ----------------------- | --------------------------------------------------- |
| SYN Flood               | Detects excessive SYN packets (DDoS attempt).       |
| ACK Flood               | Detects excessive ACK packets.                      |
| ICMP Flood              | Detects ping flood attempts.                        |
| Port Scanning           | Identifies attempts to scan open ports.             |
| DNS Amplification       | Detects DNS request floods.                         |
| HTTP Flood              | Detects HTTP/HTTPS request floods.                  |
| XMAS Scan               | Detects scans using packets with all flags set.     |
| TCP Null Scan           | Detects scans using TCP packets with no flags.      |
| Reverse Shell Detection | Detects outbound reverse shell connections.         |
| SSH Brute Force Login   | Detects repeated failed SSH login attempts.         |
| Telnet Brute Force Login| Detects repeated failed Telnet login attempts.      |
| FTP Brute Force Login   | Detects repeated failed FTP login attempts.         |
| SMB Brute Force Login   | Detects repeated failed SMB login attempts.         |
| Malformed Packets       | Detects packets with unusual structures.            |

---

## **Configuration Options**

You can customize the IDS by modifying `detection.py`:

- **Threshold Values:** Adjust packet count thresholds (e.g., SYN flood threshold).
- **Email Configuration:** Update sender/recipient details in `logger.py`.

---

## **Security Considerations**

- **Sensitive Information:** Avoid storing sensitive credentials directly in the script (e.g., use `.env` files).
- **Email Security:** Use app-specific passwords for email alerts instead of your main password.
- **Firewall Rules:** Ensure `iptables` rules are appropriately managed to avoid accidental lockout.

---

## **Potential Improvements**

- Add a **web dashboard** for real-time monitoring using `Flask` or `Dash`.
- Implement **dynamic thresholds** based on real-time traffic patterns.
- Add **Slack/Telegram integration** for real-time alerts.

---

## **Contributing**

Feel free to open issues or submit pull requests to improve this project. Contributions are welcome!

---

## **License**

This project is licensed under the MIT License.

---

## **Contact**

If you have any questions or feedback, feel free to reach out!

- **Email:** [crushtheskull404@gmail.com](mailto:crushtheskull404@gmail.com)

