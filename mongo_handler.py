from pymongo import MongoClient
from datetime import datetime
import os
import certifi

class MongoDBHandler:
    """MongoDB handler for audit logs"""
    
    def __init__(self):
        print("[DEBUG] Attempting MongoDBHandler initialization")
        mongo_uri = os.getenv('MONGODB_URI')
        print(f"[DEBUG] MONGODB_URI: {mongo_uri[:30]}")

        if not mongo_uri:
            print("[ERROR] MONGODB_URI environment variable is missing!!")
            raise ValueError("MONGODB_URI environment variable is not set")
        
        try:
            self.client = MongoClient(
                mongo_uri,
                tls=True,
                tlsAllowInvalidCertificates=True,  # Use certifi's certificate bundle
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000
            )
            self.client.admin.command('ping')
            print("[MONGODB] Connected successfully")
        except Exception as e:
            print(f"[MONGODB ERROR] Connection failed: {e}")
            raise

        self.db = self.client['terminalguard']
        self.logs_collection = self.db['audit_logs']
    
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