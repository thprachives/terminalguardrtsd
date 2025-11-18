# from pymongo import MongoClient
# from datetime import datetime
# import os
# import certifi
# from bson.objectid import ObjectId
# import sys

# class MongoDBHandler:
#     """MongoDB handler for audit logs"""
    
#     def __init__(self):
#         import sys
#         print("[DEBUG] Attempting MongoDBHandler initialization", file=sys.stderr)
#         mongo_uri = os.getenv('MONGODB_URI')
#         print(f"[DEBUG] MONGODB_URI: {mongo_uri[:30] if mongo_uri else 'NOT SET'}", file=sys.stderr)

#         if not mongo_uri:
#             print("[ERROR] MONGODB_URI environment variable is missing!!", file=sys.stderr)
#             raise ValueError("MONGODB_URI environment variable is not set")

#         try:
#             self.client = MongoClient(
#                 mongo_uri,
#                 tls=True,
#                 tlsCAFile=certifi.where(),
#                 serverSelectionTimeoutMS=10000,
#                 connectTimeoutMS=10000
#             )
#             self.client.admin.command('ping')
#             print("[MONGODB] Connected successfully", file=sys.stderr)
#         except Exception as e:
#             print(f"[MONGODB ERROR] Connection failed: {e}", file=sys.stderr)
#             raise

#         self.db = self.client['terminalguard']
#         self.logs_collection = self.db['audit_logs']
    
#     def insert_log(self, log_entry):
#         """Insert a single log entry"""
#         import sys
#         try:
#             result = self.logs_collection.insert_one(log_entry)
#             print(f"[MONGODB] Successfully inserted log with id: {result.inserted_id}", file=sys.stderr)
#             return result.inserted_id
#         except Exception as e:
#             print(f"[MONGODB ERROR] Failed to insert: {e}", file=sys.stderr)
#             raise

#     def get_recent_logs(self, count=10):
#         """Retrieve recent log entries"""
#         import sys
#         try:
#             logs = list(
#                 self.logs_collection
#                 .find({}, {'_id': 0})  # Exclude MongoDB _id field
#                 .sort('timestamp', -1)
#                 .limit(count)
#             )
#             return logs
#         except Exception as e:
#             print(f"[MONGODB ERROR] Failed to read: {e}", file=sys.stderr)
#             raise
    
#     def get_all_logs(self, limit=1000):
#         """Get all logs with limit"""
#         import sys
#         try:
#             logs = list(
#                 self.logs_collection
#                 .find({}, {'_id': 0})
#                 .sort('timestamp', -1)
#                 .limit(limit)
#             )
#             return logs
#         except Exception as e:
#             print(f"[MONGODB ERROR] Failed to read: {e}", file=sys.stderr)
#             return []
        
    

#     def update_log_marking(self, log_id, user_choice):
#         try:
#             result = self.logs_collection.update_one(
#                 {"_id": ObjectId(log_id)},
#                 {"$set": {"user_choice": user_choice}}
#             )
#             return result.modified_count > 0
#         except Exception as e:
#             print("[MONGODB] ERROR: Failed to update marking", e, file=sys.stderr)
#             return False


from pymongo import MongoClient
from bson.objectid import ObjectId
import os
import certifi
import sys


class MongoDBHandler:
    """MongoDB handler for audit logs"""

    def __init__(self):
        print("[DEBUG] Attempting MongoDBHandler initialization", file=sys.stderr)
        mongo_uri = os.getenv('MONGODB_URI')
        print(f"[DEBUG] MONGODB_URI: {mongo_uri[:30] if mongo_uri else 'NOT SET'}", file=sys.stderr)

        if not mongo_uri:
            print("[ERROR] MONGODB_URI environment variable is missing!!", file=sys.stderr)
            raise ValueError("MONGODB_URI environment variable is not set")

        try:
            self.client = MongoClient(
                mongo_uri,
                tls=True,
                tlsCAFile=certifi.where(),
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000
            )
            self.client.admin.command('ping')
            print("[MONGODB] Connected successfully", file=sys.stderr)
        except Exception as e:
            print(f"[MONGODB ERROR] Connection failed: {e}", file=sys.stderr)
            raise

        self.db = self.client['terminalguard']
        self.logs_collection = self.db['audit_logs']

    def insert_log(self, log_entry):
        """Insert a single log entry"""
        try:
            result = self.logs_collection.insert_one(log_entry)
            print(f"[MONGODB] Successfully inserted log with id: {result.inserted_id}", file=sys.stderr)
            return result.inserted_id
        except Exception as e:
            print(f"[MONGODB ERROR] Failed to insert: {e}", file=sys.stderr)
            raise

    def get_recent_logs(self, count=10):
        """Retrieve recent log entries"""
        try:
            logs = list(
                self.logs_collection
                .find()
                .sort('timestamp', -1)
                .limit(count)
            )
            return logs
        except Exception as e:
            print(f"[MONGODB ERROR] Failed to read: {e}", file=sys.stderr)
            return []

    def get_all_logs(self, limit=1000):
        """Get all logs with limit"""
        try:
            logs = list(
                self.logs_collection
                .find()
                .sort('timestamp', -1)
                .limit(limit)
            )
            return logs
        except Exception as e:
            print(f"[MONGODB ERROR] Failed to read: {e}", file=sys.stderr)
            return []
        
    def update_mark_detection(self, log_id, mark):
        """Update manual frontend mark detection field"""
        try:
            result = self.logs_collection.update_one(
                {"_id": ObjectId(log_id)},
                {"$set": {"mark_detection": mark}}
            )
            return result.modified_count > 0
        except Exception as e:
            print(f"[MONGODB] ERROR updating mark_detection: {e}", file=sys.stderr)
            return False
