# from fastapi import FastAPI, Query
# from fastapi.middleware.cors import CORSMiddleware
# from audit_logger import AuditLogger
# from fastapi.responses import JSONResponse
# import pymongo, certifi, sys, os

# print("[DEBUG] Starting application...")
# app = FastAPI(title="TerminalGuard Dashboard API")

# # Enable CORS for local frontend
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],  # In production, specify your GitHub Pages domain
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# logger = AuditLogger(use_mongodb=True)

# @app.get("/")
# def root():
#     return {"message": "Welcome to the TerminalGuard Dashboard API!"}

# @app.get("/health")
# def health_check():
#     try:
#         # Check if mongo_handler exists
#         if hasattr(logger, "mongo_handler") and logger.mongo_handler:
#             # Do a MongoDB ping test
#             logger.mongo_handler.client.admin.command("ping")
#             return {"status": "healthy", "mongodb": "connected"}
#         else:
#             return {"status": "degraded", "message": "MongoDB logging not in use"}
#     except Exception as e:
#         return {"status": "unhealthy", "error": str(e)}

# @app.get("/logs")
# def get_logs(
#     count: int = Query(20, ge=1, le=100),
#     action_filter: str = Query(None, description="Filter by action: BLOCKED or ALLOWED"),
# ):
#     """Get recent audit logs with optional filtering"""
#     all_logs = logger.get_recent_logs(1000)
#     if action_filter:
#         filtered = [log for log in all_logs if log['action'] == action_filter.upper()]
#     else:
#         filtered = all_logs
#     return {
#         "total_logs": len(filtered),
#         "logs": filtered[:count],
#     }


# @app.get("/statistics")
# def get_statistics():
#     logs = logger.get_recent_logs(1000)
#     total = len(logs)
#     blocked = sum(1 for log in logs if log["action"] == "BLOCKED")
#     allowed = total - blocked
#     secrets_count = sum(log["secrets_found"] for log in logs)
    
#     secret_types = {}
#     for log in logs:
#         for stype in log["secret_types"]:
#             secret_types[stype] = secret_types.get(stype, 0) + 1
            
#     block_rate = (blocked / total * 100) if total > 0 else 0.0
    
#     return {
#         "total_commands": total,
#         "blocked_commands": blocked,
#         "allowed_commands": allowed,
#         "total_secrets_detected": secrets_count,
#         "secret_types_breakdown": secret_types,
#         "block_rate_percent": round(block_rate, 2),
#     }

# @app.post("/reload_config")
# def reload_config():
#     """Trigger reload of the secret detection configuration"""
#     from config_manager import ConfigManager
#     cm = ConfigManager()
#     cm.reload_config()
#     return {"status": "success", "message": "Configuration reloaded"}

# if __name__ == "__main__":
#     import uvicorn
#     import os
    
#     # Use PORT from environment (Render sets this), fallback to 8001 for local
#     port = int(os.environ.get("PORT", 8001))
    
#     # MUST bind to 0.0.0.0 for Render to detect the port
#     uvicorn.run(
#         "dashboard_api:app", 
#         host="0.0.0.0", 
#         port=port, 
#         reload=False  # Disable reload in production
#     )


# @app.get("/debug-info")
# def debug_info():
#     info = {
#         "python_version": sys.version,
#         "pymongo_version": pymongo.__version__,
#         "certifi_version": certifi.__version__,
#         "certifi_ca_path": certifi.where(),
#         "mongo_connection_status": "unknown",
#         "mongo_error": None,
#         "sample_log": None
#     }

#     try:
#         # Check if the logger is using MongoDB
#         if hasattr(logger, "mongo_handler") and logger.mongo_handler:
#             mongo_handler = logger.mongo_handler

#             # Use the same client to test connection
#             mongo_handler.client.admin.command("ping")
#             info["mongo_connection_status"] = "connected"

#             # Try fetching a sample log
#             db = mongo_handler.client.get_database("audit_logs")  # update DB name if different
#             logs = list(db.logs.find().limit(1))
#             info["sample_log"] = logs[0] if logs else "No logs yet"
#         else:
#             info["mongo_connection_status"] = "not_configured"
#     except Exception as e:
#         info["mongo_connection_status"] = "failed"
#         info["mongo_error"] = str(e)

#     return JSONResponse(content=info)

from fastapi import FastAPI, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from audit_logger import AuditLogger
from fastapi.responses import JSONResponse
import sys, os, pymongo, certifi

app = FastAPI(title="TerminalGuard Dashboard API")

# Update CORS to allow your frontend domains later
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = AuditLogger(use_mongodb=True)

@app.get("/")
def root():
    return {"message": "Welcome to the TerminalGuard Dashboard API!"}

@app.get("/health")
def health_check():
    try:
        if hasattr(logger, "mongo_handler") and logger.mongo_handler:
            logger.mongo_handler.client.admin.command("ping")
            return {"status": "healthy", "mongodb": "connected"}
        else:
            return {"status": "degraded", "message": "MongoDB logging not in use"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

@app.get("/logs")
def get_logs(
    count: int = Query(20, ge=1, le=100),
    action_filter: str = Query(None),
):
    all_logs = logger.get_recent_logs(1000)
    if action_filter:
        filtered = [log for log in all_logs if log["action"] == action_filter.upper()]
    else:
        filtered = all_logs

    # Return fields including mark_detection, default null if missing
    result_logs = []
    for log in filtered[:count]:
        result_logs.append({
            "id": str(log.get("_id", log.get("id"))),
            "_id": str(log.get("_id", log.get("id"))),
            "timestamp": log.get("timestamp"),
            "command": log.get("command", ""),
            "action": log.get("action"),
            "secrets_found": log.get("secrets_found"),
            "mark_detection": log.get("mark_detection", None),  # Our manual mark field
        })
    return {"total_logs": len(result_logs), "logs": result_logs}

@app.post("/logs/mark_detection")
def mark_detection(
    log_id: str = Body(...),
    mark: str = Body(...)  # "true" or "false"
):
    result = logger.update_mark_detection(log_id, mark)
    if result:
        return {"status": "success"}
    return {"status": "failed", "error": "Could not update marking"}

@app.get("/statistics")
def get_statistics():
    logs = logger.get_recent_logs(1000)
    total = len(logs)
    blocked = sum(1 for log in logs if log.get("action") == "BLOCKED")
    allowed = total - blocked
    secrets_count = sum(log.get("secrets_found", 0) for log in logs)
    
    secret_types = {}
    for log in logs:
        for stype in log.get("secret_types", []):
            secret_types[stype] = secret_types.get(stype, 0) + 1

    block_rate = (blocked / total * 100) if total > 0 else 0.0

    return {
        "total_commands": total,
        "blocked_commands": blocked,
        "allowed_commands": allowed,
        "total_secrets_detected": secrets_count,
        "secret_types_breakdown": secret_types,
        "block_rate_percent": round(block_rate, 2),
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run("dashboard_api:app", host="0.0.0.0", port=port, reload=False)
