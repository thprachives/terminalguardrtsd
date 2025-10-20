from pymongo import MongoClient
from datetime import datetime
import os

class MongoDBHandler:
    """MongoDB handler for audit logs"""
    
    def __init__(self):
        # Get MongoDB URI from environment variable
        mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
        self.client = MongoClient(mongo_uri)
        self.db = self.client['terminalguard']
        self.logs_collection = self.db['audit_logs']
        print("[MONGODB] Connected successfully")
    
    def insert_log(self, log_entry):
        """Insert a single log entry"""
        try:
            result = self.logs_collection.insert_one(log_entry)
            return result.inserted_id
        except Exception as e:
            print(f"[MONGODB ERROR] Failed to insert: {e}")
            return None
    
    def get_recent_logs(self, count=10):
        """Retrieve recent log entries"""
        try:
            logs = list(
                self.logs_collection
                .find({}, {'_id': 0})  # Exclude MongoDB _id field
                .sort('timestamp', -1)
                .limit(count)
            )
            return logs
        except Exception as e:
            print(f"[MONGODB ERROR] Failed to read: {e}")
            return []
    
    def get_all_logs(self, limit=1000):
        """Get all logs with limit"""
        try:
            logs = list(
                self.logs_collection
                .find({}, {'_id': 0})
                .sort('timestamp', -1)
                .limit(limit)
            )
            return logs
        except Exception as e:
            print(f"[MONGODB ERROR] Failed to read: {e}")
            return []