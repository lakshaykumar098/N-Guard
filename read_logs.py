import sqlite3

def read_logs():
    """
    Reads and displays logs from the SQLite database with filtering options.
    """
    try:
        conn = sqlite3.connect("ids_logs.db")
        cursor = conn.cursor()

        print("Choose a filter option:")
        print("1. Read logs of a specific Source IP")
        print("2. Read logs between specific dates")
        print("3. Read all logs")
        user_input = input("Enter your choice: ").strip()

        if user_input == "1":
            # Filter by specific Source IP
            source_ip = input("Enter the Source IP to filter logs: ").strip()
            cursor.execute("SELECT * FROM alerts WHERE src_ip = ?", (source_ip,))
            logs = cursor.fetchall()

        elif user_input == "2":
            # Filter by date range
            start_date = input("Enter the start date (YYYY-MM-DD): ").strip()
            end_date = input("Enter the end date (YYYY-MM-DD): ").strip()
            cursor.execute(
                "SELECT * FROM alerts WHERE timestamp BETWEEN ? AND ?", 
                (start_date, end_date)
            )
            logs = cursor.fetchall()

        elif user_input == "3":
            # Retrieve all logs
            cursor.execute("SELECT * FROM alerts")
            logs = cursor.fetchall()

        else:
            print("Invalid choice. Exiting.")
            return

        # Display logs
        if logs:
            print(f"{'ID':<5}{'Timestamp':<25}{'Source IP':<20}{'Alert':<50}")
            print("="*100)
            for log in logs:
                print(f"{log[0]:<5}{log[1]:<25}{log[2]:<20}{log[3]:<50}")
        else:
            print("No logs found for the given filter.")
    
    except sqlite3.Error as e:
        print(f"Error reading logs: {e}")
    
    finally:
        if conn:
            conn.close()
# Main entry Point
if __name__ == "__main__":
    read_logs()
