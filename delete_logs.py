import sqlite3

def delete_logs():
    """
    Delete record for a particular src_ip or Clears the entire table if '*' is provided.
    """
    try:
        conn = sqlite3.connect("ids_logs.db")
        cursor = conn.cursor()

        # Get user input for deletion criteria
        user_input = input("Enter the Source IP to delete logs for, or '*' to clear all logs: ").strip()

        if user_input == "*":
            # Clear the entire table
            confirmation = input("Are you sure you want to delete all logs? Type 'yes' to confirm: ").strip().lower()
            if confirmation == 'yes':
                cursor.execute("DELETE FROM alerts")
                conn.commit()
                # Reset the AUTOINCREMENT ID
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")
                conn.commit()
                print("All logs have been cleared.")
            else:
                print("Operation canceled.")
        else:
            # Delete logs for the specified Source IP
            cursor.execute("DELETE FROM alerts WHERE src_ip = ?", (user_input,))
            if cursor.rowcount > 0:
                conn.commit()
                print(f"Logs for Source IP '{user_input}' have been deleted.")
            else:
                print(f"No logs found for Source IP '{user_input}'.")
    
    except sqlite3.Error as e:
        print(f"Error deleting logs: {e}")
    
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    delete_logs()
