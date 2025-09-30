import nmap
import json
import os
import asyncio
import ipaddress
import signal
import socket
import re
import time
import shutil
from datetime import datetime
from collections import defaultdict
from quart import Quart, request, jsonify, websocket
from cryptography.fernet import Fernet
import logging
from logging.handlers import RotatingFileHandler
from telegram import Bot
from telegram.error import TelegramError
from dotenv import load_dotenv

load_dotenv()

"""
Quick scan:
curl -X POST http://localhost:5000/scan \
    -H "Content-Type: application/json" \
    -d '{"target": "127.0.0.1", "scan_type": "Ping"}'

Schedule scan:
curl -X POST http://localhost:5000/schedule \
    -H "Content-Type: application/json" \
    -d '{"target": "192.168.1.1", "scan_type": "TCP", "interval": 10}'

Task management:
# List tasks
curl http://localhost:5000/tasks

# Cancel task
curl -X DELETE http://localhost:5000/tasks/192.168.1.1-TCP

# Health check
curl http://localhost:5000/health
"""

# Global variables
start_time = datetime.now()
VERSION = "alpha_1.1.1"

# Configure logging with rotation
logging.basicConfig(
    handlers=[
        RotatingFileHandler(
            "/app/logs/scan_log.txt", maxBytes=10 * 1024 * 1024, backupCount=5
        )
    ],
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Confidential data from environment variables
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
bot = Bot(token=TELEGRAM_TOKEN) if TELEGRAM_TOKEN and CHAT_ID else None

# Nmap timeouts/settings from environment
HOST_TIMEOUT_SEC = int(os.getenv("NMAP_HOST_TIMEOUT_SEC", "300"))
NMAP_MAX_RETRIES = os.getenv("NMAP_MAX_RETRIES", "2")  # default 2

# Generate/load encryption key
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    raise RuntimeError(
        "FERNET_KEY not set! Specify it in .env or environment variables. "
        "Without it, old files cannot be decrypted!"
    )
FERNET_KEY = FERNET_KEY.strip()  # Remove invisible characters
cipher = Fernet(FERNET_KEY.encode())

print("=== DEBUG FERNET KEY ===")
print(f"Raw value: [{FERNET_KEY}]")
print(f"Length: {len(FERNET_KEY)}")
print(f"Last 5 chars: [{FERNET_KEY[-5:]}]")
print(f"repr: {repr(FERNET_KEY)}")
print("=========================")

app = Quart(__name__)
scan_tasks = {}  # For storing active tasks

SUPPORTED_SCAN_TYPES = {
    "SYN": "-sS",
    "TCP": "-sT",
    "UDP": "-sU",
    "Aggressive": "-A",
    "OS": "-O",
    "Ping": "-sn",
}

# Rate limiting
rate_limits = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # 60 seconds
MAX_REQUESTS_PER_WINDOW = 10


def get_scan_type_choices() -> str:
    return ", ".join(f"'{k}'" for k in SUPPORTED_SCAN_TYPES.keys())


def log_event(event: str):
    logging.info(event)
    print(event)


async def send_telegram_message(message: str):
    if not bot:
        log_event("Telegram not configured. Message not sent.")
        return
    try:
        await bot.send_message(chat_id=CHAT_ID, text=message)
    except TelegramError as e:
        log_event(f"Error sending message to Telegram: {e}")
    except Exception as e:
        log_event(f"Unexpected error sending Telegram message: {e}")


def validate_ip_or_host(target: str) -> bool:
    """Enhanced secure validation of IPs, subnets, and domains"""
    if not target or len(target) > 255:
        return False

    # Block potential injections
    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", "\\", " "]
    if any(char in target for char in dangerous_chars):
        log_event(f"Potential injection detected in target address: {target}")
        return False

    try:
        # Check as IP network
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        try:
            # Check domain (without command injection)
            if re.match(
                r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9])*$",
                target,
            ):
                socket.gethostbyname(target)
                return True
            return False
        except (socket.error, UnicodeError):
            log_event(f"Invalid address or domain: {target}")
            return False


def build_scan_args(scan_type: str) -> str:
    """Safe construction of scan arguments"""
    if scan_type not in SUPPORTED_SCAN_TYPES:
        raise ValueError(f"Invalid scan_type: {scan_type}")

    # Sanitize timeouts
    try:
        timeout = int(HOST_TIMEOUT_SEC)
        if timeout <= 0 or timeout > 3600:  # Maximum 1 hour
            timeout = 300
    except (ValueError, TypeError):
        timeout = 300

    base = SUPPORTED_SCAN_TYPES[scan_type]
    extra = [f"--host-timeout {timeout}s"]

    if NMAP_MAX_RETRIES:
        try:
            retries = int(NMAP_MAX_RETRIES)
            if 0 <= retries <= 10:  # Limit maximum amount
                extra.append(f"--max-retries {retries}")
        except (ValueError, TypeError):
            pass

    return f"{base} {' '.join(extra)}"


def scan_network(target: str, scan_type: str):
    """
    SYNC function, runs in ThreadPool.
    Exceptions are NOT swallowed - let them fly to async layer.
    """
    scanner = nmap.PortScanner()
    scan_args = build_scan_args(scan_type)
    log_event(f"Starting scan {target} with type {scan_type} and args: {scan_args}")

    # IMPORTANT: Don't pass timeout= to scan(), this is not cross-version compatible.
    scanner.scan(target, arguments=scan_args)

    return process_scan_results(scanner)


def process_scan_results(scanner: nmap.PortScanner) -> dict:
    results = {
        "scan_time": datetime.now().isoformat(),
        "scan_count": len(scanner.all_hosts()),
        "hosts": [],
    }
    for host in scanner.all_hosts():
        host_data = {
            "host": host,
            "hostname": scanner[host].hostname() or "N/A",
            "state": scanner[host].state(),
            "protocols": {},
        }
        for proto in scanner[host].all_protocols():
            ports = []
            # deterministic order
            for port in sorted(scanner[host][proto].keys()):
                pi = scanner[host][proto][port]
                ports.append(
                    {
                        "port": port,
                        "state": pi.get("state", "unknown"),
                        "name": pi.get("name", "unknown"),
                        "product": pi.get("product", "unknown"),
                        "version": pi.get("version", "unknown"),
                    }
                )
            host_data["protocols"][proto] = ports
        results["hosts"].append(host_data)
    return results


async def save_scan_results_async(results: dict, target: str, scan_type: str):
    if not results:
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(
        c if c.isalnum() or c in [".", "_", "-"] else "_" for c in target
    )[:120]
    filename = f"{safe_target}_{scan_type}_{timestamp}.json"
    os.makedirs("encrypted_results", exist_ok=True)
    path = os.path.join("encrypted_results", filename)
    try:
        encrypted_data = cipher.encrypt(json.dumps(results, indent=2).encode())
        with open(path, "wb") as enc_file:
            enc_file.write(encrypted_data)
        log_event(f"Results saved to {path}")
        await send_telegram_message(f"Scan {target} completed. Results: {filename}")
    except Exception as e:
        err = f"Error saving results: {e}"
        log_event(err)
        await send_telegram_message(f"Error saving results for {target}: {e}")


async def async_scan(target: str, scan_type: str):
    """Enhanced version with better error handling"""
    loop = asyncio.get_running_loop()
    try:
        # Additional validation of targets
        if target.count("/") > 1:  # Suspicious format
            raise ValueError("Invalid target address format")

        results = await loop.run_in_executor(None, scan_network, target, scan_type)

        # Log successful scan
        log_event(f"Scan {target} ({scan_type}) completed successfully")
        return results

    except nmap.PortScannerError as e:
        err = f"Nmap error scanning {target}: {e}"
        log_event(err)
        await send_telegram_message(f"Nmap error: {err}")
        raise
    except Exception as e:
        err = f"Error scanning {target} ({scan_type}): {e}"
        log_event(err)
        await send_telegram_message(f"Scan error: {err}")
        raise


def check_rate_limit():
    """Check rate limit"""
    client_ip = request.remote_addr
    now = time.time()

    # Remove old requests
    rate_limits[client_ip] = [
        req_time
        for req_time in rate_limits[client_ip]
        if now - req_time < RATE_LIMIT_WINDOW
    ]

    if len(rate_limits[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        return False

    rate_limits[client_ip].append(now)
    return True


@app.route("/scan", methods=["POST"])
async def start_scan():
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    try:
        data = await request.json
        if not data:
            return jsonify({"error": "No data"}), 400

        target = data.get("target")
        scan_type = data.get("scan_type", "SYN")

        if not target:
            return jsonify({"error": "Target not specified"}), 400

        if scan_type not in SUPPORTED_SCAN_TYPES:
            return jsonify(
                {"error": f"Invalid scan_type. Available: {get_scan_type_choices()}"}
            ), 400

        if not validate_ip_or_host(target):
            return jsonify({"error": "Invalid IP or domain"}), 400

        log_event(f"Received scan request: {target}, type: {scan_type}")
        results = await async_scan(target, scan_type)
        return jsonify(results or {"message": "Scan completed without results"}), 200
    except Exception as e:
        err = f"API error in /scan: {e}"
        log_event(err)
        await send_telegram_message(f"API error: {e}")
        return jsonify({"error": str(e)}), 500


async def periodic_scan(target: str, scan_type: str, interval_minutes: float):
    """Async periodic scanning"""
    log_event(f"Started periodic scan {target} every {interval_minutes} minutes")
    await send_telegram_message(
        f"Started periodic scan {target} every {interval_minutes} minutes"
    )
    while True:
        try:
            log_event(f"Performing periodic scan: {target}")
            await async_scan(target, scan_type)
        except asyncio.CancelledError:
            log_event(f"Periodic scan {target} cancelled")
            break
        except Exception as e:
            err = f"Error in periodic scan {target}: {e}"
            log_event(err)
            await send_telegram_message(f"Periodic scan error: {err}")
        try:
            await asyncio.sleep(interval_minutes * 60)
        except asyncio.CancelledError:
            break


@app.route("/schedule", methods=["POST"])
async def add_scheduled_scan():
    if not check_rate_limit():
        return jsonify({"error": "Rate limit exceeded"}), 429

    try:
        data = await request.json
        if not data:
            return jsonify({"error": "No data"}), 400

        target = data.get("target")
        scan_type = data.get("scan_type", "SYN")
        interval = data.get("interval", 30)

        if not target:
            return jsonify({"error": "Target not specified"}), 400

        if scan_type not in SUPPORTED_SCAN_TYPES:
            return jsonify(
                {"error": f"Invalid scan_type. Available: {get_scan_type_choices()}"}
            ), 400

        if not validate_ip_or_host(target):
            return jsonify({"error": "Invalid IP or domain"}), 400

        if not isinstance(interval, (int, float)) or interval <= 0:
            return jsonify({"error": "Interval must be a positive number"}), 400

        task_id = f"{target}-{scan_type}"
        if task_id in scan_tasks:
            return jsonify({"error": "Scan already scheduled"}), 400

        task = asyncio.create_task(periodic_scan(target, scan_type, interval))
        scan_tasks[task_id] = task
        log_event(f"Scan {target} scheduled every {interval} minutes")
        return jsonify(
            {
                "message": f"Scan {target} scheduled every {interval} minutes",
                "task_id": task_id,
            }
        ), 200
    except Exception as e:
        err = f"Error in /schedule: {e}"
        log_event(err)
        return jsonify({"error": str(e)}), 500


@app.route("/tasks", methods=["GET"])
async def list_tasks():
    tasks_info = []
    for task_id, task in scan_tasks.items():
        tasks_info.append(
            {"id": task_id, "running": not task.done(), "cancelled": task.cancelled()}
        )
    return jsonify(tasks_info), 200


@app.route("/tasks/<task_id>", methods=["DELETE"])
async def cancel_task(task_id):
    if task_id in scan_tasks:
        scan_tasks[task_id].cancel()
        del scan_tasks[task_id]
        log_event(f"Task {task_id} cancelled")
        await send_telegram_message(f"Task {task_id} cancelled")
        return jsonify({"message": f"Task {task_id} cancelled"}), 200
    return jsonify({"error": "Task not found"}), 404


def get_disk_space():
    """Check free space"""
    try:
        total, used, free = shutil.disk_usage("/")
        return {
            "total_gb": round(total / (1024**3), 2),
            "free_gb": round(free / (1024**3), 2),
            "used_percent": round((used / total) * 100, 2),
        }
    except:
        return {"error": "Cannot get disk info"}


@app.route("/health", methods=["GET"])
async def health_check():
    # Check Nmap availability
    try:
        import subprocess

        result = subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
        nmap_available = result.returncode == 0
    except:
        nmap_available = False

    return jsonify(
        {
            "status": "healthy" if nmap_available else "unhealthy",
            "version": VERSION,
            "tasks_count": len(scan_tasks),
            "telegram_configured": bot is not None,
            "uptime": str(datetime.now() - start_time),
            "fernet_key_configured": FERNET_KEY is not None,
            "nmap_available": nmap_available,
            "disk_space": get_disk_space(),
            "max_requests_per_window": MAX_REQUESTS_PER_WINDOW,
            "rate_limit_window": RATE_LIMIT_WINDOW,
        }
    ), 200


@app.route("/api/docs", methods=["GET"])
async def api_docs():
    return jsonify(
        {
            "name": "Nmap Automation Framework API",
            "version": VERSION,
            "rate_limit": f"{MAX_REQUESTS_PER_WINDOW} requests per {RATE_LIMIT_WINDOW} seconds",
            "endpoints": {
                "POST /scan": {
                    "description": "Immediate network scan",
                    "request": {
                        "target": "IP address, range, or domain",
                        "scan_type": "SYN|TCP|UDP|Aggressive|OS|Ping",
                    },
                    "example": {"target": "192.168.1.1", "scan_type": "TCP"},
                },
                "POST /schedule": {
                    "description": "Schedule periodic scanning",
                    "request": {
                        "target": "IP address, range, or domain",
                        "scan_type": "Scan type",
                        "interval": "Interval in minutes",
                    },
                    "example": {
                        "target": "192.168.1.0/24",
                        "scan_type": "SYN",
                        "interval": 30,
                    },
                },
                "GET /tasks": {"description": "List active tasks"},
                "DELETE /tasks/<task_id>": {"description": "Cancel task by ID"},
                "GET /health": {"description": "Service status check"},
            },
        }
    ), 200


@app.websocket("/ws/scan-results")
async def ws_scan_results():
    """WebSocket for real-time scan updates"""
    client_id = request.remote_addr
    log_event(f"WebSocket connected: {client_id}")

    try:
        while True:
            # Send result updates
            if scan_tasks:
                active_tasks = {k: not v.done() for k, v in scan_tasks.items()}
                await websocket.send(
                    json.dumps(
                        {
                            "type": "task_update",
                            "active_tasks": active_tasks,
                            "total_tasks": len(scan_tasks),
                        }
                    )
                )
            await asyncio.sleep(5)  # Update every 5 seconds
    except:
        log_event(f"WebSocket disconnected: {client_id}")
        pass


async def load_initial_tasks():
    """Load initial tasks from environment variable"""
    initial_tasks_raw = os.getenv("INITIAL_TASKS", "[]")
    if not initial_tasks_raw.strip():
        return  # Empty string

    try:
        initial_tasks = json.loads(initial_tasks_raw)
        if not isinstance(initial_tasks, list):
            log_event("INITIAL_TASKS must be an array")
            return

        for task_config in initial_tasks:
            target = task_config["target"]
            scan_type = task_config.get("scan_type", "SYN")
            interval = task_config.get("interval", 30)

            if scan_type not in SUPPORTED_SCAN_TYPES:
                log_event(f"Skipping task (invalid scan_type): {scan_type}")
                continue

            task_id = f"{target}-{scan_type}"
            if task_id not in scan_tasks:  # Avoid duplicates
                task = asyncio.create_task(periodic_scan(target, scan_type, interval))
                scan_tasks[task_id] = task
                log_event(
                    f"Loaded initial task: {target} ({scan_type}) every {interval} minutes"
                )
    except json.JSONDecodeError as e:
        log_event(f"Error parsing INITIAL_TASKS (JSON): {e}")
    except (KeyError, TypeError) as e:
        log_event(f"Error in INITIAL_TASKS structure: {e}")
    except Exception as e:
        log_event(f"Error loading INITIAL_TASKS: {e}")


async def main():
    log_event(f"Service started (version {VERSION})")
    await send_telegram_message(f"Nmap Automation Framework v{VERSION} started")

    # Load initial tasks
    await load_initial_tasks()

    # Start server
    server_task = asyncio.create_task(app.run_task(host="0.0.0.0", port=5000))

    # Handle shutdown (cross-platform)
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    for signame in {"SIGINT", "SIGTERM"}:
        try:
            sig = getattr(signal, signame)
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, AttributeError, ValueError):
            # Windows or other platform
            pass

    await stop_event.wait()
    log_event("Shutdown signal received")
    await send_telegram_message("Nmap Automation Framework shutting down")

    # Cancel all tasks
    for task in scan_tasks.values():
        task.cancel()
    server_task.cancel()

    # Wait for task completion with timeout
    try:
        await asyncio.wait_for(
            asyncio.gather(*scan_tasks.values(), server_task, return_exceptions=True),
            timeout=30.0,  # 30 seconds to complete
        )
    except asyncio.TimeoutError:
        log_event("Force stopping tasks due to timeout")

    log_event("Service stopped")
    await send_telegram_message("Nmap Automation Framework stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_event("Received KeyboardInterrupt")
    except Exception as e:
        log_event(f"Critical error: {e}")
