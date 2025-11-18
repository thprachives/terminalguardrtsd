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
import pymongo, certifi, sys, os

print("[DEBUG] Starting application...")
app = FastAPI(title="TerminalGuard Dashboard API")

# Enable CORS for frontend (update this for production security)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to your frontend domain for production
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
    action_filter: str = Query(None, description="Filter by action: BLOCKED or ALLOWED"),
):
    """Get recent audit logs with optional filtering and user marking"""
    all_logs = logger.get_recent_logs(1000)
    if action_filter:
        filtered = [log for log in all_logs if log['action'] == action_filter.upper()]
    else:
        filtered = all_logs

    # Only include relevant fields for dashboard
    result_logs = []
    for log in filtered[:count]:
        # Ensure user_choice and secret_found fields
        log_obj = {
            "id": str(log.get("_id", log.get("id"))),
            "_id": str(log.get("_id", log.get("id"))),
            "action": log.get("action"),
            "secret_found": bool(log.get("secrets_found", log.get("secret_found", 0))),
            "command": log.get("command", ""),
            "timestamp": log.get("timestamp", ""),
            "user_choice": log.get("user_choice", None)
        }
        result_logs.append(log_obj)

    return {
        "total_logs": len(result_logs),
        "logs": result_logs,
    }

@app.post("/logs/mark")
def mark_log(
    log_id: str = Body(...),
    user_choice: str = Body(...)
):
    """
    Mark detection verdict (true/false) for a log entry in MongoDB.
    """
    result = logger.update_log_marking(log_id, user_choice)
    if result:
        return {"status": "success"}
    else:
        return {"status": "failed", "error": "Could not mark log"}

@app.get("/statistics")
def get_statistics():
    logs = logger.get_recent_logs(1000)
    total = len(logs)
    blocked = sum(1 for log in logs if log.get("action") == "BLOCKED")
    allowed = total - blocked
    secrets_count = sum(log.get("secrets_found", log.get("secret_found", 0)) for log in logs)
    
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

@app.post("/reload_config")
def reload_config():
    """Trigger reload of the secret detection configuration"""
    from config_manager import ConfigManager
    cm = ConfigManager()
    cm.reload_config()
    return {"status": "success", "message": "Configuration reloaded"}

@app.get("/debug-info")
def debug_info():
    info = {
        "python_version": sys.version,
        "pymongo_version": pymongo.__version__,
        "certifi_version": certifi.__version__,
        "certifi_ca_path": certifi.where(),
        "mongo_connection_status": "unknown",
        "mongo_error": None,
        "sample_log": None
    }
    try:
        if hasattr(logger, "mongo_handler") and logger.mongo_handler:
            mongo_handler = logger.mongo_handler
            mongo_handler.client.admin.command("ping")
            info["mongo_connection_status"] = "connected"
            db = mongo_handler.client.get_database("terminalguard")  # update DB name if different
            logs = list(db.logs.find().limit(1))
            info["sample_log"] = logs[0] if logs else "No logs yet"
        else:
            info["mongo_connection_status"] = "not_configured"
    except Exception as e:
        info["mongo_connection_status"] = "failed"
        info["mongo_error"] = str(e)
    return JSONResponse(content=info)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run(
        "dashboard_api:app",
        host="0.0.0.0",
        port=port,
        reload=False
    )
