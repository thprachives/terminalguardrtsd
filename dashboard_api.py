from fastapi import FastAPI, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from audit_logger import AuditLogger
from fastapi.responses import JSONResponse
from collections import defaultdict
from datetime import datetime
import sys, os, pymongo, certifi, psutil

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

    # Calculate TP, FP, TN, FN for manual marking (mark_detection)
    TP = FP = TN = FN = 0
    for log in logs:
        mark = log.get("mark_detection")
        secret_found = log.get("secrets_found", 0) > 0
        if mark == "true":
            if secret_found:
                TP += 1
            else:
                FN += 1
        elif mark == "false":
            if secret_found:
                FP += 1
            else:
                TN += 1

    fp_rate = FP / (FP + TP) if (FP + TP) > 0 else 0.0
    fn_rate = FN / (FN + TN) if (FN + TN) > 0 else 0.0
    accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0.0

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
        "false_positive_rate": round(fp_rate * 100, 2),
        "false_negative_rate": round(fn_rate * 100, 2),
        "accuracy_percent": round(accuracy * 100, 2)
    }

@app.get("/performance")
def get_performance():
    """Get latency and performance metrics"""
    logs = logger.get_recent_logs(1000)

    latencies = [log.get("latency_ms", 0) for log in logs if log.get("latency_ms")]

    if not latencies:
        return {
            "note": "No latency data yet - new logs will include latency",
            "avg_latency_ms": 0,
            "min_latency_ms": 0,
            "max_latency_ms": 0,
            "total_detections": len(logs)
        }

    latencies_sorted = sorted(latencies)
    return {
        "avg_latency_ms": round(sum(latencies) / len(latencies), 4),
        "min_latency_ms": round(min(latencies), 4),
        "max_latency_ms": round(max(latencies), 4),
        "p95_latency_ms": round(latencies_sorted[int(len(latencies_sorted) * 0.95)], 4) if len(latencies) >= 20 else None,
        "total_detections": len(logs),
        "detections_with_latency": len(latencies)
    }

@app.get("/severity")
def get_severity_breakdown():
    """Get detection breakdown by severity level"""
    logs = logger.get_recent_logs(1000)

    severity_counts = defaultdict(int)
    for log in logs:
        for sev in log.get("secret_severities", []):
            severity_counts[sev] += 1

    # If no severity data, note it
    if not severity_counts:
        return {
            "note": "No severity data yet - new logs will include severity",
            "by_severity": {},
            "total_secrets": 0
        }

    return {
        "by_severity": dict(severity_counts),
        "total_secrets": sum(severity_counts.values())
    }

@app.get("/trends")
def get_trends():
    """Get time-based detection trends"""
    logs = logger.get_recent_logs(1000)

    hourly = defaultdict(int)
    daily = defaultdict(int)

    for log in logs:
        try:
            ts_str = log.get("timestamp", "")
            if "T" in ts_str:
                ts = datetime.fromisoformat(ts_str)
            else:
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")

            hourly[ts.hour] += 1
            daily[ts.strftime("%Y-%m-%d")] += 1
        except Exception:
            continue

    return {
        "by_hour": dict(sorted(hourly.items())),
        "by_day": dict(sorted(daily.items())[-30:])  # Last 30 days
    }

@app.get("/resources")
def get_resources():
    """Get system resource usage (CPU, Memory)"""
    try:
        process = psutil.Process()
        return {
            "cpu_percent": round(process.cpu_percent(), 2),
            "memory_mb": round(process.memory_info().rss / 1024 / 1024, 2),
            "threads": process.num_threads(),
            "uptime_seconds": round((datetime.now() - datetime.fromtimestamp(process.create_time())).total_seconds(), 0)
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/full-report")
def get_full_report():
    """Get comprehensive analytics report (consolidated from analytics.py)"""
    logs = logger.get_recent_logs(1000)

    # Basic stats
    total = len(logs)
    blocked = sum(1 for log in logs if log.get("action") == "BLOCKED")
    allowed = total - blocked

    # Confusion matrix from manual marking
    TP = FP = TN = FN = 0
    for log in logs:
        mark = log.get("mark_detection")
        secret_found = log.get("secrets_found", 0) > 0
        if mark == "true":
            TP += 1 if secret_found else 0
            FN += 1 if not secret_found else 0
        elif mark == "false":
            FP += 1 if secret_found else 0
            TN += 1 if not secret_found else 0

    # Accuracy metrics
    precision = TP / (TP + FP) if (TP + FP) > 0 else None
    recall = TP / (TP + FN) if (TP + FN) > 0 else None
    f1 = 2 * (precision * recall) / (precision + recall) if precision and recall and (precision + recall) > 0 else None
    fpr = FP / (FP + TN) if (FP + TN) > 0 else None
    fnr = FN / (TP + FN) if (TP + FN) > 0 else None
    accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else None

    # Latency stats
    latencies = [log.get("latency_ms") for log in logs if log.get("latency_ms")]
    latency_stats = {}
    if latencies:
        latencies_sorted = sorted(latencies)
        latency_stats = {
            "avg_ms": round(sum(latencies) / len(latencies), 4),
            "min_ms": round(min(latencies), 4),
            "max_ms": round(max(latencies), 4),
            "p95_ms": round(latencies_sorted[int(len(latencies_sorted) * 0.95)], 4) if len(latencies) >= 20 else None,
            "count": len(latencies)
        }

    # Severity breakdown
    severity_counts = defaultdict(int)
    for log in logs:
        for sev in log.get("secret_severities", []):
            severity_counts[sev] += 1

    # Secret types breakdown
    type_counts = defaultdict(int)
    for log in logs:
        for stype in log.get("secret_types", []):
            type_counts[stype] += 1

    # Time distribution
    hourly = defaultdict(int)
    daily = defaultdict(int)
    for log in logs:
        try:
            ts_str = log.get("timestamp", "")
            ts = datetime.fromisoformat(ts_str) if "T" in ts_str else datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            hourly[ts.hour] += 1
            daily[ts.strftime("%Y-%m-%d")] += 1
        except:
            pass

    # Resource usage
    try:
        process = psutil.Process()
        resources = {
            "cpu_percent": round(process.cpu_percent(), 2),
            "memory_mb": round(process.memory_info().rss / 1024 / 1024, 2)
        }
    except:
        resources = {}

    return {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_operations": total,
            "blocked": blocked,
            "allowed": allowed,
            "block_rate_percent": round(blocked / total * 100, 2) if total > 0 else 0
        },
        "confusion_matrix": {
            "true_positives": TP,
            "false_positives": FP,
            "true_negatives": TN,
            "false_negatives": FN,
            "total_marked": TP + FP + TN + FN
        },
        "accuracy_metrics": {
            "precision": round(precision * 100, 2) if precision else None,
            "recall": round(recall * 100, 2) if recall else None,
            "f1_score": round(f1 * 100, 2) if f1 else None,
            "accuracy": round(accuracy * 100, 2) if accuracy else None,
            "false_positive_rate": round(fpr * 100, 2) if fpr else None,
            "false_negative_rate": round(fnr * 100, 2) if fnr else None
        },
        "latency": latency_stats,
        "severity_breakdown": dict(severity_counts),
        "secret_types": dict(sorted(type_counts.items(), key=lambda x: -x[1])[:20]),
        "trends": {
            "by_hour": dict(sorted(hourly.items())),
            "by_day": dict(sorted(daily.items())[-30:])
        },
        "resources": resources
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run("dashboard_api:app", host="0.0.0.0", port=port, reload=False)
