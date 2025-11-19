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
