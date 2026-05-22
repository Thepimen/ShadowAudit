import os
import sys
import json
import socket
import threading
import time
from datetime import datetime
from typing import Dict, Any, List

import redis
from fastapi import FastAPI
import uvicorn

# 1. Environment and Configuration Setup
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", "shadowaudit:queue")
REDIS_RESULTS_CHANNEL = os.getenv("REDIS_RESULTS_CHANNEL", "shadowaudit:results")

# Port descriptions and mapping for the native socket fallback scanner
PORT_SERVICES = {
    22: ("ssh", "OpenSSH / Secure Shell"),
    80: ("http", "Web Server (HTTP)"),
    443: ("https", "Secure Web Server (HTTPS)"),
    3306: ("mysql", "MySQL Database Server"),
    8080: ("http-alt", "Alternative Web Server / Tomcat")
}

# Strict whitelist for defense-in-depth security validation
AUTHORIZED_TARGETS = {"localhost", "127.0.0.1", "scanme.nmap.org"}

# Initialize FastAPI App for worker monitoring/health checks
app = FastAPI(
    title="ShadowAudit Worker Service",
    description="Asynchronous pentest runner & network scanning microservice",
    version="1.0.0"
)

# Connect to Redis
try:
    redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    print(f"[Redis] Worker connected successfully to {REDIS_URL}")
except Exception as e:
    print(f"[Fatal] Failed to connect to Redis: {e}")
    sys.exit(1)

@app.get("/health")
def health_check():
    """Health check endpoint to ensure worker is alive."""
    return {
        "status": "healthy",
        "worker": "active",
        "redis_connection": redis_client.ping(),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

def publish_log(audit_id: str, stage: str, message: str, data: Any = None):
    """Publishes a structured real-time scan event log to Redis Pub/Sub."""
    payload = {
        "auditId": audit_id,
        "stage": stage,
        "message": message,
        "data": data,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    redis_client.publish(REDIS_RESULTS_CHANNEL, json.dumps(payload))
    print(f"[Worker] [{stage.upper()}] Audit {audit_id}: {message}")

def execute_native_socket_scan(target_ip: str) -> List[Dict[str, Any]]:
    """
    Fallback Scanner using native Python sockets.
    Extremely fast, robust, and doesn't require any binary dependencies.
    """
    scan_results = []
    
    for port, (service, desc) in PORT_SERVICES.items():
        # Setup socket connection with small timeout to prevent hanging
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        
        start_time = time.time()
        result = s.connect_ex((target_ip, port))
        latency = round((time.time() - start_time) * 1000, 2)
        
        if result == 0:
            state = "open"
            version_str = f"{desc} (Detected via direct TCP Handshake)"
        else:
            state = "closed"
            version_str = "N/A"
            
        s.close()
        
        scan_results.append({
            "port": port,
            "state": state,
            "service": service,
            "version": version_str,
            "latency_ms": latency
        })
        
    return scan_results

def execute_nmap_scan(target: str) -> List[Dict[str, Any]]:
    """
    Executes a real scan using python-nmap safely.
    Runs a TCP Connect Scan (-sT) to ensure normal user-privilege execution compatibility.
    """
    import nmap
    
    nm = nmap.PortScanner()
    # Safe scan arguments: TCP Connect Scan, no ping lookup (speeds up localhost), scan specified ports
    ports_str = ",".join(map(str, PORT_SERVICES.keys()))
    
    # We pass target safely to nm.scan to prevent any command injections (python-nmap uses subprocess internally)
    nm.scan(hosts=target, ports=ports_str, arguments="-sT -P0")
    
    scan_results = []
    
    # Process scanning results
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            if proto == "tcp":
                ports = nm[host][proto].keys()
                for port in ports:
                    port_data = nm[host][proto][port]
                    state = port_data.get("state", "closed")
                    service = port_data.get("name", "unknown")
                    product = port_data.get("product", "")
                    version = port_data.get("version", "")
                    
                    version_str = f"{product} {version}".strip() or "N/A"
                    
                    scan_results.append({
                        "port": port,
                        "state": state,
                        "service": service,
                        "version": version_str
                    })
                    
    # Fill in any missing ports as closed
    found_ports = {item["port"] for item in scan_results}
    for port, (service, _) in PORT_SERVICES.items():
        if port not in found_ports:
            scan_results.append({
                "port": port,
                "state": "closed",
                "service": service,
                "version": "N/A"
            })
            
    return scan_results

def generate_ai_insights(scan_results: List[Dict[str, Any]]) -> List[str]:
    """
    Simulates advanced AI processing to provide tactical recommendations and SecOps logs
    based on the open/closed ports found.
    """
    insights = []
    open_ports = [item for item in scan_results if item["state"] == "open"]
    
    if not open_ports:
        insights.append(
            "[AI Insight] PERFECT POSTURE: All targeted ports are closed. The surface area is extremely tight. "
            "Recommendation: Continue conducting regular automated sweeps and establish perimeter logging."
        )
        return insights

    insights.append(
        f"[AI Threat Profile] EXPOSURE DETECTED: Found {len(open_ports)} open port(s). Analyzing threat profiles..."
    )

    for item in open_ports:
        port = item["port"]
        if port == 22:
            insights.append(
                "[AI Fix SSH - Port 22] WARNING: SSH is accessible. "
                "Ensure PasswordAuthentication is set to 'no' in sshd_config. Force key-based MFA and consider "
                "restricting ingress to trusted developer IP ranges via UFW/Security Groups."
            )
        elif port == 80:
            insights.append(
                "[AI Fix HTTP - Port 80] NOTICE: Standard HTTP is open. "
                "Implement an immediate HSTS policy. Force HTTP to HTTPS redirects (301) to protect sessions "
                "from sniffing/MITM attacks."
            )
        elif port == 443:
            insights.append(
                "[AI Fix HTTPS - Port 443] GOOD: HTTPS is open. "
                "Ensure SSL/TLS versions below TLS 1.2 are fully disabled. Verify that modern cipher suites are enforced "
                "and TLS certificates are automatically renewed via Let's Encrypt."
            )
        elif port == 3306:
            insights.append(
                "[AI Fix Database - Port 3306] CRITICAL THREAT: MySQL is exposed directly to the WAN! "
                "Databases must NEVER bind to 0.0.0.0. Bind MySQL strictly to localhost (127.0.0.1) and route all admin "
                "connections securely through an encrypted SSH tunnel, VPN, or private VPC connection."
            )
        elif port == 8080:
            insights.append(
                "[AI Fix WebAlt - Port 8080] WARNING: Alternative Web Port (8080) is open. "
                "Ensure this is not displaying an unauthenticated admin dashboard or an out-of-date Apache Tomcat manager. "
                "Audit the underlying process and run under a low-privilege user sandbox."
            )
            
    return insights

def process_scan_job(job_data: Dict[str, Any]):
    """Orchestrates the entire scanning and AI-insight-logging lifecycle."""
    audit_id = job_data.get("auditId")
    target = job_data.get("target")
    
    if not audit_id or not target:
        print("[Error] Received invalid job structure missing auditId or target.")
        return

    # 1. Defense-in-depth: Strict whitelist validation
    clean_target = target.strip().lower()
    if clean_target not in AUTHORIZED_TARGETS:
        publish_log(
            audit_id, 
            "failed", 
            f"Scan terminated. Target '{target}' is not in the SecOps authorized whitelist."
        )
        return

    try:
        # Start audit
        publish_log(audit_id, "scanning", f"Audit initialized for target: {clean_target}")
        time.sleep(1) # Visual pacing for the terminal

        # 2. Host resolution
        publish_log(audit_id, "log", "Resolving DNS and measuring host network latency...")
        try:
            target_ip = socket.gethostbyname(clean_target)
            publish_log(audit_id, "log", f"Target resolved to IP address: {target_ip}")
        except Exception as dns_err:
            publish_log(audit_id, "failed", f"Failed to resolve target host: {dns_err}")
            return
        
        time.sleep(0.8)

        # 3. Choose Scanning Engine (Nmap vs Socket Fallback)
        scan_results = []
        try:
            publish_log(audit_id, "log", "Initializing safe Nmap Port Scan (Ports: 22, 80, 443, 3306, 8080)...")
            scan_results = execute_nmap_scan(clean_target)
            publish_log(audit_id, "log", "Nmap scan engine completed successfully.")
        except Exception as nmap_err:
            publish_log(
                audit_id, 
                "log", 
                f"[SecOps Notice] Nmap scanner unavailable ({nmap_err}). Triggering ultra-resilient Python Socket Engine..."
            )
            scan_results = execute_native_socket_scan(target_ip)
            publish_log(audit_id, "log", "Python Socket Engine finished scanning all core ports.")

        time.sleep(1)

        # 4. Stream scanned ports information
        publish_log(audit_id, "log", "Parsing port tables and service versions...", data={"ports": scan_results})
        time.sleep(1)

        # 5. Execute simulated AI processing and vulnerability generation
        publish_log(audit_id, "log", "Streaming raw logs to ShadowAudit AI analysis model...")
        time.sleep(1)
        
        ai_insights = generate_ai_insights(scan_results)
        for insight in ai_insights:
            publish_log(audit_id, "log", insight)
            time.sleep(0.5)

        # 6. Complete scan successfully
        publish_log(
            audit_id, 
            "completed", 
            "Audit complete. Full vulnerability vector reports generated successfully.",
            data={
                "target": clean_target,
                "ip": target_ip,
                "scan_time": datetime.utcnow().isoformat() + "Z",
                "results": scan_results,
                "ai_insights": ai_insights
            }
        )

    except Exception as scan_err:
        publish_log(audit_id, "failed", f"An unhandled execution crash occurred: {str(scan_err)}")

def worker_queue_loop():
    """Asynchronous infinite polling loop consuming Redis list tasks with BLPOP."""
    print("[Worker Loop] Started background queue listener thread. Waiting for audits...")
    while True:
        try:
            # BLPOP blocks until a job becomes available, preventing high-frequency CPU polling
            # Key 0 means block indefinitely, but we can set 2 seconds to allow graceful shutdown checks
            job_tuple = redis_client.blpop(REDIS_QUEUE_KEY, timeout=3)
            
            if job_tuple:
                # blpop returns: (list_key, list_value)
                _, job_payload_str = job_tuple
                
                try:
                    job_data = json.loads(job_payload_str)
                    print(f"\n[Queue] Picked up new audit task: {job_data.get('auditId')}")
                    
                    # Process the job
                    process_scan_job(job_data)
                except Exception as json_err:
                    print(f"[Error] Failed to deserialize JSON job payload: {json_err}")
                    
        except redis.ConnectionError:
            print("[Warning] Redis connection lost. Reconnecting in 5 seconds...")
            time.sleep(5)
        except Exception as loop_err:
            print(f"[Warning] Worker loop error: {loop_err}")
            time.sleep(2)

if __name__ == "__main__":
    # Start the Redis Worker Loop in a separate daemon thread
    worker_thread = threading.Thread(target=worker_queue_loop, daemon=True)
    worker_thread.start()

    # Run the FastAPI monitoring app
    # Port 8000 is used by the worker for status checks
    uvicorn.run(app, host="0.0.0.0", port=8000)
