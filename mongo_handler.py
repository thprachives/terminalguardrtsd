from pymongo import MongoClient
from datetime import datetime
import os

class MongoDBHandler:
    """MongoDB handler for audit logs"""
    
    def __init__(self):
        # Get MongoDB URI from environment variable

        print("[DEBUG] Attempting to read MONGODB_URI environment variable...")
        mongo_uri = os.getenv('MONGODB_URI')
        if not mongo_uri:
            print("[ERROR] MONGODB_URI environment variable is missing")
            raise ValueError("MONGODB_URI environment variable is not set")
        else:
            print(f"[DEBUG] MONGODB_URI found: {mongo_uri[:30]}...")  # mask part for safety

        try:
            self.client = MongoClient(mongo_uri, tls=True, tlsAllowInvalidCertificates=False)
            # Test connection
            self.client.admin.command('ping')
            print("[MONGODB] Connected successfully")
        except Exception as e:
            print(f"[MONGODB ERROR] Connection failed: {e}")
            raise

    
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
            raise
    
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