import requests
import socket
import time
import threading
import argparse
import yaml
from datetime import datetime, timezone

def load_config(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def fetch_tasks(server):
    url = f"{server['url']}/api/v1/tasks?tags={','.join(server['tags'])}"
    headers = {}
    if "token" in server:
        headers["X-API-Key"] = server["token"]

    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        return response.json().get("tasks", [])
    except Exception as e:
        print(f"[{server['name']}] [ERROR] Failed to fetch tasks: {e}")
        return []

def perform_tcp_check(task):
    start = time.time()
    try:
        sock = socket.create_connection((task["target_ip"], task["port"]), timeout=task["timeout_sec"])
        sock.close()
        latency = (time.time() - start) * 1000
        return {"status": "ok", "latency_ms": latency, "reason": None}
    except socket.timeout:
        return {"status": "fail", "latency_ms": None, "reason": "timeout"}
    except ConnectionRefusedError:
        return {"status": "fail", "latency_ms": None, "reason": "connection refused"}
    except Exception as e:
        return {"status": "fail", "latency_ms": None, "reason": str(e)}

def report_result(server, agent_id, task, result):
    payload = {
        "agent_id": agent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "check_name": task["check_name"],
        "domain": task["domain"],
        "type": task["type"],
        "target_ip": task["target_ip"],
        "port": task.get("port"),
        "status": result["status"],
        "latency_ms": result.get("latency_ms"),
        "reason": result.get("reason"),
    }

    headers = {}
    if "token" in server:
        headers["X-API-Key"] = server["token"]

    try:
        res = requests.post(f"{server['url']}/api/v1/report", json=payload, headers=headers, timeout=5)
        print(f"[{server['name']}] Reported: {task['check_name']} → {result['status']}")
    except Exception as e:
        print(f"[{server['name']}] [ERROR] Failed to report result: {e}")

def run_task(agent_id, server, task):
    while True:
        result = perform_tcp_check(task)
        report_result(server, agent_id, task, result)
        time.sleep(task["interval_sec"])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="agent_config.yaml", help="Путь до конфигурационного YAML-файла")
    args = parser.parse_args()

    config = load_config(args.config)
    agent_id = config["agent_id"]
    servers = config["servers"]

    for server in servers:
        tasks = fetch_tasks(server)
        if not tasks:
            print(f"[{server['name']}] [WARN] No tasks received.")
            continue

        for task in tasks:
            thread = threading.Thread(target=run_task, args=(agent_id, server, task), daemon=True)
            thread.start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("Агент остановлен.")

if __name__ == "__main__":
    main()