import json
from datetime import datetime
import os
from mongo_handler import MongoDBHandler

class AuditLogger:
    """Logs all command interceptions and security events to MongoDB"""

    def __init__(self, use_mongodb=True):
        self.use_mongodb = use_mongodb
        
        if self.use_mongodb:
            try:
                self.mongo_handler = MongoDBHandler()
                print("[AUDIT_LOGGER] Using MongoDB for logging")
            except Exception as e:
                print(f"[AUDIT_LOGGER] MongoDB unavailable, falling back to file: {e}")
                self.use_mongodb = False
        
        # Keep file logging as backup
        if not self.use_mongodb:
            log_file = 'audit.log'
            if not os.path.isabs(log_file):
                log_file = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    log_file
                )
            self.log_file = log_file

    def log_event(self, command, secrets_detected, action, user_choice=None):
        """Log a command execution event"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'command': command,
            'action': action,
            'secrets_found': len(secrets_detected),
            'secret_types': [s['type'] for s in secrets_detected],
            'user_choice': user_choice
        }
        
        if self.use_mongodb:
            try:
                self.mongo_handler.insert_log(log_entry)
                print(f"[AUDIT_LOGGED - MongoDB] {log_entry}")
            except Exception as e:
                print(f"[AUDIT_LOGGER ERROR] MongoDB write failed: {e}")
        else:
            # Fallback to file
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(log_entry) + '\n')
                    f.flush()
                print(f"[AUDIT_LOGGED - File] {log_entry}")
            except Exception as e:
                print(f"[AUDIT_LOGGER ERROR] File write failed: {e}")

        return log_entry

    def get_recent_logs(self, count=10):
        """Retrieve recent log entries"""
        if self.use_mongodb:
            return self.mongo_handler.get_recent_logs(count)
        else:
            # Fallback file reading (your existing code)
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