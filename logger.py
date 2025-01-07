import sqlite3
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

def initialize_database():
    """
    Initializes the SQLite database with an 'alerts' table.
    Creates the database if it does not already exist.
    """
    try:
        conn = sqlite3.connect('ids_logs.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                alert TEXT
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")
    finally:
        conn.close()

def log_alert(src_ip, alert):
    """
    Logs an alert to the SQLite database.
    Each alert includes a timestamp, source IP, and alert type.
    """
    try:
        conn = sqlite3.connect('ids_logs.db')
        cursor = conn.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            "INSERT INTO alerts(timestamp, src_ip, alert) VALUES (?, ?, ?)", 
            (current_time,src_ip, alert)
        )
        conn.commit()
        print(f"Alert logged: [Source IP: {src_ip}, Timestamp: {current_time} ,Alert: {alert}]")
    except sqlite3.Error as e:
        print(f"Error logging alert: {e}")
    finally:
        conn.close()


def send_email_alert(src_ip, alert):
    """
    Sends an email alert for a detected threat.
    """
    sender = "example@gmail.com"  # Replace with your email
    receiver = "recipient@gmail.com"  # Replace with the recipient email
    password = "Your_App_Password"  # Replace with your App Password (not your email password)

    # Email content
    message = MIMEText(
    f"🚨 Security Threat Alert 🚨\n\n"
    f"A potential threat has been detected by the system.\n\n"
    f"Details:\n"
    f"-----------------------------------\n"
    f"🔹 Source IP Address: {src_ip}\n"
    f"🔹 Alert Description: {alert}\n"
    f"-----------------------------------\n\n"
    f"Please investigate this issue promptly to ensure system security."
)
    message['Subject'] = "IDS Alert"
    message['From'] = sender
    message['To'] = receiver

    try:
        # Connect to the Gmail SMTP server
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Start TLS encryption
            server.login(sender, password)  # Log in to the email account
            server.sendmail(sender, receiver, message.as_string())  # Send the email
            print("Email alert sent successfully!")
    except Exception as e:
        print(f"Failed to send email alert: {e}")


