import json
from datetime import datetime
import os

class AuditLogger:
    """Logs all command interceptions and security events"""
    
    def __init__(self, log_file='audit.log'):
        self.log_file = log_file
        
    def log_event(self, command, secrets_detected, action, user_choice=None):
        """
        Log a command execution event
        
        Args:
            command: The command that was intercepted
            secrets_detected: List of detected secrets
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
        
        # Write to log file
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        return log_entry
    
    def get_recent_logs(self, count=10):
        """Retrieve recent log entries"""
        if not os.path.exists(self.log_file):
            return []
        
        with open(self.log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        recent = lines[-count:] if len(lines) > count else lines
        return [json.loads(line) for line in recent]
