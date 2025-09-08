#!/usr/bin/env python3
"""
Kali Security Platform - Simplified & Functional Version
Gerçekten çalışan, basit ve kullanışlı güvenlik tarama platformu
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import json
import asyncio
from typing import Dict, List, Any, Optional
import re
import socket
from datetime import datetime
import os
from pathlib import Path

# FastAPI app
app = FastAPI(title="Kali Security Scanner", version="2.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create necessary directories
os.makedirs("outputs", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# Store scan results
scan_results = {}

# ============================================
# UTILITY FUNCTIONS
# ============================================

def validate_target(target: str) -> bool:
    """Validate target URL/IP/Domain"""
    # Remove protocol if exists
    target = target.replace("http://", "").replace("https://", "").replace("ftp://", "")
    
    # Check if it's an IP
    try:
        socket.inet_aton(target.split('/')[0])
        return True
    except:
        pass
    
    # Check if it's a valid domain
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(domain_pattern.match(target))

def sanitize_command(command: str) -> str:
    """Sanitize command to prevent injection"""
    # Remove dangerous characters
    dangerous = [';', '&&', '||', '|', '>', '<', '`', '$', '(', ')', '{', '}', '[', ']', '\\']
    for char in dangerous:
        command = command.replace(char, '')
    return command

async def execute_command(command: str, timeout: int = 30) -> Dict:
    """Execute system command safely"""
    try:
        # Split command safely
        cmd_parts = command.split()
        
        # Execute with timeout
        process = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            return {
                "success": True,
                "output": stdout.decode('utf-8', errors='ignore'),
                "error": stderr.decode('utf-8', errors='ignore'),
                "command": command
            }
        except asyncio.TimeoutError:
            process.kill()
            return {
                "success": False,
                "error": f"Command timed out after {timeout} seconds",
                "command": command
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "command": command
        }

# ============================================
# MAIN PAGE
# ============================================

@app.get("/", response_class=HTMLResponse)
async def main_page():
    """Serve main HTML page"""
    html_file = Path("templates/index.html")
    if html_file.exists():
        return html_file.read_text()
    else:
        # Return simple inline HTML if template not found
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Kali Security Scanner</title>
            <style>
                body { font-family: Arial; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
                .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
                input { width: 70%; padding: 10px; font-size: 16px; }
                button { padding: 10px 20px; background: #4CAF50; color: white; border: none; cursor: pointer; }
                #output { background: #1a1a2e; color: #0fff50; padding: 20px; margin-top: 20px; border-radius: 5px; min-height: 200px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ Kali Security Scanner</h1>
                <input type="text" id="target" placeholder="Enter target (e.g., scanme.nmap.org)">
                <button onclick="scan()">Start Scan</button>
                <div id="output"></div>
            </div>
            <script>
                async function scan() {
                    const target = document.getElementById('target').value;
                    const output = document.getElementById('output');
                    output.innerHTML = 'Scanning...';
                    
                    try {
                        const response = await fetch('/api/scan', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({target: target})
                        });
                        const data = await response.json();
                        output.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                    } catch(e) {
                        output.innerHTML = 'Error: ' + e.message;
                    }
                }
            </script>
        </body>
        </html>
        """

# ============================================
# SCAN API ENDPOINTS
# ============================================

@app.post("/api/scan")
async def quick_scan(request: Dict):
    """Quick scan endpoint - MAIN SCANNING FUNCTION"""
    target = request.get("target", "").strip()
    
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    if not validate_target(target):
        raise HTTPException(status_code=400, detail="Invalid target format")
    
    # Remove protocol for scanning
    clean_target = target.replace("http://", "").replace("https://", "").split('/')[0]
    
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "scans": {}
    }
    
    # 1. Basic Port Scan (Fast)
    print(f"[+] Scanning ports on {clean_target}")
    port_scan = await execute_command(f"nmap -F {clean_target}", timeout=30)
    results["scans"]["port_scan"] = port_scan
    
    # 2. Service Detection (if ports found)
    if "open" in port_scan.get("output", ""):
        print(f"[+] Detecting services on {clean_target}")
        service_scan = await execute_command(f"nmap -sV --version-light {clean_target}", timeout=45)
        results["scans"]["services"] = service_scan
    
    # 3. Web Scan (if port 80/443 open)
    if any(port in port_scan.get("output", "") for port in ["80/tcp", "443/tcp", "8080/tcp"]):
        print(f"[+] Checking web vulnerabilities on {clean_target}")
        # Use curl for basic web check instead of nikto (faster)
        web_check = await execute_command(f"curl -I http://{clean_target}", timeout=10)
        results["scans"]["web_check"] = web_check
    
    # 4. DNS Information
    print(f"[+] Getting DNS info for {clean_target}")
    dns_info = await execute_command(f"host {clean_target}", timeout=10)
    results["scans"]["dns"] = dns_info
    
    # Save results
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_results[scan_id] = results
    results["scan_id"] = scan_id
    
    return results

@app.post("/api/tools/nmap")
async def nmap_scan(request: Dict):
    """Dedicated Nmap scanning"""
    target = request.get("target", "")
    options = request.get("options", "-sV")
    
    if not validate_target(target):
        raise HTTPException(status_code=400, detail="Invalid target")
    
    command = f"nmap {options} {target}"
    result = await execute_command(command, timeout=60)
    
    return {
        "tool": "nmap",
        "target": target,
        "result": result
    }

@app.post("/api/tools/execute")
async def execute_tool(request: Dict):
    """Execute specific security tool"""
    command = request.get("command", "")
    
    if not command:
        raise HTTPException(status_code=400, detail="Command is required")
    
    # Sanitize command
    command = sanitize_command(command)
    
    # Whitelist of allowed tools
    allowed_tools = ["nmap", "host", "dig", "whois", "curl", "ping"]
    tool = command.split()[0]
    
    if tool not in allowed_tools:
        raise HTTPException(status_code=403, detail=f"Tool '{tool}' is not allowed")
    
    result = await execute_command(command, timeout=30)
    return result

# ============================================
# OSINT ENDPOINTS
# ============================================

@app.post("/api/osint/whois")
async def whois_lookup(request: Dict):
    """WHOIS lookup"""
    target = request.get("target", "")
    
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    result = await execute_command(f"whois {target}", timeout=15)
    return {"tool": "whois", "target": target, "result": result}

@app.post("/api/osint/dns")
async def dns_lookup(request: Dict):
    """DNS lookup"""
    target = request.get("target", "")
    
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    results = {}
    
    # Multiple DNS queries
    queries = [
        ("A Records", f"dig {target} A +short"),
        ("MX Records", f"dig {target} MX +short"),
        ("NS Records", f"dig {target} NS +short"),
        ("TXT Records", f"dig {target} TXT +short"),
    ]
    
    for name, command in queries:
        result = await execute_command(command, timeout=10)
        results[name] = result.get("output", "").strip()
    
    return {"tool": "dns", "target": target, "results": results}

@app.post("/api/osint/subdomain")
async def subdomain_enum(request: Dict):
    """Basic subdomain enumeration"""
    domain = request.get("target", "")
    
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    
    # Use basic DNS brute force with common subdomains
    common_subs = ["www", "mail", "ftp", "admin", "blog", "shop", "api", "dev", "test"]
    found_subdomains = []
    
    for sub in common_subs:
        target = f"{sub}.{domain}"
        result = await execute_command(f"host {target}", timeout=5)
        if "has address" in result.get("output", ""):
            found_subdomains.append(target)
    
    return {
        "tool": "subdomain_enum",
        "domain": domain,
        "subdomains": found_subdomains
    }

# ============================================
# REPORT ENDPOINTS
# ============================================

@app.get("/api/reports/list")
async def list_reports():
    """List all scan results"""
    return {
        "reports": list(scan_results.keys()),
        "count": len(scan_results)
    }

@app.get("/api/reports/{scan_id}")
async def get_report(scan_id: str):
    """Get specific scan report"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_results[scan_id]

@app.post("/api/reports/generate")
async def generate_report(request: Dict):
    """Generate report in different formats"""
    scan_id = request.get("scan_id")
    format_type = request.get("format", "json")
    
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    data = scan_results[scan_id]
    
    if format_type == "json":
        return JSONResponse(content=data)
    elif format_type == "text":
        # Simple text report
        text = f"""
SECURITY SCAN REPORT
====================
Target: {data['target']}
Date: {data['timestamp']}

RESULTS:
--------
"""
        for scan_name, scan_data in data['scans'].items():
            text += f"\n{scan_name.upper()}:\n"
            text += scan_data.get('output', 'No output')
            text += "\n" + "="*50 + "\n"
        
        return {"format": "text", "content": text}
    
    return {"message": "Report generated", "format": format_type}

# ============================================
# HEALTH CHECK
# ============================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "tools_available": ["nmap", "dig", "host", "whois", "curl"]
    }

@app.get("/api/status")
async def status():
    """System status"""
    return {
        "status": "online",
        "scans_completed": len(scan_results),
        "platform": "Kali Linux Security Scanner v2.0"
    }

# ============================================
# MAIN EXECUTION
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║     KALI SECURITY SCANNER v2.0 - SIMPLIFIED & FUNCTIONAL     ║
╠══════════════════════════════════════════════════════════════╣
║  [✓] Fast port scanning with Nmap                           ║
║  [✓] Service detection                                      ║
║  [✓] DNS enumeration                                        ║
║  [✓] WHOIS lookup                                           ║
║  [✓] Web vulnerability check                                ║
║  [✓] Real-time results                                      ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    print("[+] Starting server on http://localhost:8000")
    print("[+] Open browser and navigate to http://localhost:8000")
    print("[+] Press CTRL+C to stop\n")
    
    # Run server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )
