import json
from datetime import datetime
import os

class AuditLogger:
    """Logs all command interceptions and security events"""

    # def __init__(self, log_file='audit.log'):
    #     # Always use the absolute path so it's consistent everywhere in your project
    #     base_dir = os.path.dirname(os.path.abspath(__file__))
    #     self.log_file = os.path.join(base_dir, log_file)

    def __init__(self, log_file='audit.log'):
        if not os.path.isabs(log_file):
            log_file = os.path.join(
                'C:\\Users\\Prachi Verma\\OneDrive\\Desktop\\minor',
                log_file
            )
        self.log_file = log_file

    def log_event(self, command, secrets_detected, action, user_choice=None):
        """
        Log a command execution event

        Args:
            command: The command that was intercepted
            secrets_detected: List of detected secrets ({type: ...} items expected)
            action: 'ALLOWED', 'BLOCKED', or 'WARNED'
            user_choice: User's decision if prompted (y/n)
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'command': command,
            'action': action,
            'secrets_found': len(secrets_detected),
            'secret_types': [s['type'] for s in secrets_detected],
            'user_choice': user_choice
        }
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
                f.flush()
                os.fsync(f.fileno())
            print(f"[AUDIT_LOGGED] {log_entry}")  # Diagnostic print
        except Exception as e:
            print(f"[AUDIT_LOGGER ERROR] Failed to write log: {e}")

        return log_entry

    def get_recent_logs(self, count=10):
        """Retrieve recent log entries"""
        if not os.path.exists(self.log_file):
            return []

        entries = []
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines[-count:]:
                    try:
                        entries.append(json.loads(line.strip()))
                    except Exception:
                        continue
        except Exception as e:
            print(f"[AUDIT_LOGGER ERROR] Failed to read log: {e}")

        return entries
