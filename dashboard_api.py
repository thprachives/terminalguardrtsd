from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from audit_logger import AuditLogger

app = FastAPI(title="TerminalGuard Dashboard API")

# Enable CORS for local frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your GitHub Pages domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


logger = AuditLogger(use_mongodb=True)

@app.get("/")
def root():
    return {"message": "Welcome to the TerminalGuard Dashboard API!"}

@app.get("/logs")
def get_logs(
    count: int = Query(20, ge=1, le=100),
    action_filter: str = Query(None, description="Filter by action: BLOCKED or ALLOWED"),
):
    """Get recent audit logs with optional filtering"""
    all_logs = logger.get_recent_logs(1000)
    if action_filter:
        filtered = [log for log in all_logs if log['action'] == action_filter.upper()]
    else:
        filtered = all_logs
    return {
        "total_logs": len(filtered),
        "logs": filtered[:count],
    }


@app.get("/statistics")
def get_statistics():
    logs = logger.get_recent_logs(1000)
    total = len(logs)
    blocked = sum(1 for log in logs if log["action"] == "BLOCKED")
    allowed = total - blocked
    secrets_count = sum(log["secrets_found"] for log in logs)
    
    secret_types = {}
    for log in logs:
        for stype in log["secret_types"]:
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

if __name__ == "__main__":
    import uvicorn
    import os
    
    # Use PORT from environment (Render sets this), fallback to 8001 for local
    port = int(os.environ.get("PORT", 8001))
    
    # MUST bind to 0.0.0.0 for Render to detect the port
    uvicorn.run(
        "dashboard_api:app", 
        host="0.0.0.0", 
        port=port, 
        reload=False  # Disable reload in production
    )
